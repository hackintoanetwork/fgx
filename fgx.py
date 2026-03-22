#!/usr/bin/env python3

"""
fgx - FortiGate Firmware Extraction Toolkit
Supports FortiOS 7.6.x (aarch64 / x86_64)

End-to-end decryption pipeline:
  Stage 1: Outer layer decryption (FortiCrack-compatible XOR block cipher)
  Stage 2: Filesystem extraction (ext3 from decrypted image)
  Stage 3: Kernel crypto material extraction (seed + RSA key from flatkc)
  Stage 4: rootfs.gz decryption (modified RC4 stream cipher)
"""

import io
import os
import re
import sys
import gzip
import shutil
import struct
import hashlib
import tempfile
import argparse
import functools
import subprocess
import multiprocessing

BANNER = r"""
   __
  / _| __ _ __  __
 | |_ / _` |\ \/ /
 |  _| (_| | >  <
 |_|  \__, |/_/\_\
      |___/

 fgx - FortiGate Firmware Extraction Toolkit
"""

BLOCK_SIZE = 512


# Stage 1: Outer Layer Decryption (FortiCrack algorithm)

def load_image_data(image_file):
    """Decompress .out firmware file (gzip) into raw bytes."""
    result = subprocess.run(
        ["gunzip", "--to-stdout", "--force", image_file],
        check=False, capture_output=True,
    )
    if result.stdout:
        return result.stdout
    raise ValueError(f"Failed to decompress {image_file}")


def derive_key_byte(key_offset, ciphertext_byte, prev_byte, known_plaintext):
    key_byte = prev_byte ^ (known_plaintext + key_offset) ^ ciphertext_byte
    return (key_byte + 256) & 0xFF


def validate_key(key):
    if len(key) != 32:
        return False
    try:
        s = key.decode("ascii")
    except UnicodeDecodeError:
        return False
    return all(c.isalnum() for c in s)


def decrypt_block(ciphertext, key, num_bytes=None):
    if num_bytes is None or num_bytes > len(ciphertext):
        num_bytes = len(ciphertext)
    if num_bytes > BLOCK_SIZE:
        num_bytes = BLOCK_SIZE

    cleartext = bytearray()
    prev = 0xFF
    ko = 0
    for i in range(num_bytes):
        if ko >= len(key):
            return bytes(cleartext)
        xor = (prev ^ ciphertext[i] ^ key[ko]) - ko
        xor = (xor + 256) & 0xFF
        cleartext.append(xor)
        prev = ciphertext[i]
        ko = (ko + 1) & 0x1F
    return bytes(cleartext)


def validate_decryption(cleartext):
    if len(cleartext) >= 80 and cleartext[12:16] == b"\xff\x00\xaa\x55":
        try:
            name = cleartext[16:46].decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return False
        if "build" in name.lower():
            return True
    return False


def derive_block_key(ciphertext):
    key = bytearray()
    for i in range(32):
        ko = (i + 16) % 32
        offset = i + 48
        key.append(derive_key_byte(ko, ciphertext[offset], ciphertext[offset - 1], 0x00))
    key = key[16:] + key[:16]
    if validate_key(key):
        cleartext = decrypt_block(ciphertext, key)
        if validate_decryption(cleartext):
            return bytes(key)
    return None


def derive_key(ciphertext):
    num_blocks = (len(ciphertext) + BLOCK_SIZE - 1) // BLOCK_SIZE
    with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
        results = [
            pool.apply_async(
                derive_block_key,
                (ciphertext[bn * BLOCK_SIZE : bn * BLOCK_SIZE + 80],),
            )
            for bn in range(num_blocks)
        ]
        for result in results:
            key = result.get()
            if key:
                pool.terminate()
                pool.join()
                return key
    return None


def decrypt_image(ciphertext, key):
    num_blocks = (len(ciphertext) + BLOCK_SIZE - 1) // BLOCK_SIZE
    with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
        worker = functools.partial(decrypt_block, key=key)
        chunks = [
            ciphertext[bn * BLOCK_SIZE : bn * BLOCK_SIZE + BLOCK_SIZE]
            for bn in range(num_blocks)
        ]
        results = pool.map(worker, chunks)
    return b"".join(results)


def stage1_outer_decrypt(firmware_path, verbose=False):
    """Decrypt outer .out firmware image. Returns decrypted bytes."""
    print("[*] Stage 1: Outer layer decryption")
    ciphertext = load_image_data(firmware_path)
    size_mb = len(ciphertext) / (1024 * 1024)
    print(f"    Loaded image ({size_mb:.1f} MB)")

    # Check if already cleartext
    for off in range(0, len(ciphertext), BLOCK_SIZE):
        if validate_decryption(ciphertext[off : off + 80]):
            print("[!] Image is already cleartext")
            return ciphertext

    key = derive_key(ciphertext)
    if not key:
        raise RuntimeError("Failed to derive XOR key")

    key_str = key.decode("utf-8")
    name = decrypt_block(ciphertext[:BLOCK_SIZE], key)[16:46].decode("utf-8")
    print(f"[+] Key: {key_str}")
    print(f"[+] Image: {name}")

    decrypted = decrypt_image(ciphertext, key)
    print(f"[+] Outer layer decrypted ({len(decrypted) / (1024*1024):.1f} MB)")
    return decrypted


# Stage 2: Filesystem Extraction

def stage2_extract_fs(image_data, output_dir, verbose=False):
    """Extract rootfs.gz, flatkc, datafs.tar.gz from ext3 image."""
    print("[*] Stage 2: Filesystem extraction")

    # Use 7z to extract from the ext3 filesystem at offset 512
    ext_image = image_data[512:]

    # Write ext image to temp file for 7z
    ext_path = os.path.join(output_dir, "rootfs.ext")
    with open(ext_path, "wb") as f:
        f.write(ext_image)

    target_files = ["rootfs.gz", "flatkc", "datafs.tar.gz", "split_rootfs.tar.xz",
                    "devicetree.dtb", "filechecksum", ".db"]

    result = subprocess.run(
        ["7z", "x", ext_path, "-o" + output_dir] + target_files,
        capture_output=True, text=True,
    )

    extracted = {}
    for name in target_files:
        path = os.path.join(output_dir, name)
        if os.path.exists(path):
            size = os.path.getsize(path)
            extracted[name] = path
            print(f"[+] Extracted {name} ({size / (1024*1024):.1f} MB)")

    if "rootfs.gz" not in extracted:
        raise RuntimeError("rootfs.gz not found in filesystem")
    if "flatkc" not in extracted:
        raise RuntimeError("flatkc not found in filesystem")

    # Clean up ext image (unless keep_intermediate)
    if not os.environ.get("FGX_KEEP_EXT"):
        os.remove(ext_path)

    return extracted


# Stage 3: Kernel Crypto Material Extraction

def convert_flatkc_to_elf(flatkc_path, elf_path):
    """Convert flatkc to ELF using vmlinux-to-elf."""
    result = subprocess.run(
        ["vmlinux-to-elf", flatkc_path, elf_path],
        capture_output=True, text=True,
    )
    if not os.path.exists(elf_path):
        raise RuntimeError(f"vmlinux-to-elf failed: {result.stdout}\n{result.stderr}")

    # Detect arch from ELF header (e_machine at offset 18)
    with open(elf_path, "rb") as f:
        f.seek(18)
        e_machine = struct.unpack("<H", f.read(2))[0]
    if e_machine == 183:  # EM_AARCH64
        arch = "aarch64"
    elif e_machine == 62:  # EM_X86_64
        arch = "x86_64"
    else:
        arch = "unknown"
    return arch



def _try_xor_rsa(seed, enc):
    """Check if 270-byte enc XOR'd with 32-byte seed yields valid RSA DER."""
    d0 = enc[0] ^ seed[0]
    d1 = enc[1] ^ seed[1]
    if d0 != 0x30 or d1 != 0x82:
        return None
    d2 = enc[2] ^ seed[2]
    d3 = enc[3] ^ seed[3]
    if (d2 << 8 | d3) != 0x010A:
        return None
    if (enc[4] ^ seed[4]) != 0x02:
        return None
    if (enc[5] ^ seed[5]) != 0x82:
        return None
    if ((enc[6] ^ seed[6]) << 8 | (enc[7] ^ seed[7])) != 0x0101:
        return None
    dec = bytearray(270)
    for i in range(270):
        dec[i] = enc[i] ^ seed[i & 0x1F]
    if dec[265:270] == b"\x02\x03\x01\x00\x01":
        return bytes(dec)
    return None


def find_seed_and_rsa_universal(elf_data, verbose=False):
    """Architecture-independent seed + RSA key search.

    Scans the entire ELF binary for a 32-byte seed and a 270-byte
    XOR-encrypted RSA public key.  Supports both contiguous layout
    (aarch64: seed immediately followed by RSA key) and non-contiguous
    layout (x86_64: seed and RSA key separated by a small gap).
    """
    elf_len = len(elf_data)

    # Pass 1: contiguous seed(32) + RSA(270)
    for offset in range(0, elf_len - 302):
        seed = elf_data[offset : offset + 32]
        if seed == b"\x00" * 32 or len(set(seed)) < 8:
            continue
        enc = elf_data[offset + 32 : offset + 32 + 270]
        if len(enc) < 270:
            break
        dec = _try_xor_rsa(seed, enc)
        if dec:
            if verbose:
                print(f"    Seed at ELF offset 0x{offset:x} (contiguous)")
            return seed, dec

    # Pass 2: non-contiguous — RSA key before seed with small gap
    # In x86_64 FortiOS, RSA key(270) + gap(≤64) + seed(32)
    if verbose:
        print("    Pass 1 (contiguous) failed, trying non-contiguous...")

    # Build index: for each possible seed, compute expected first 2 bytes of encrypted RSA
    # If enc[0]^seed[0]==0x30 and enc[1]^seed[1]==0x82, then enc[0]=seed[0]^0x30
    # We index by (enc[0], enc[1]) = (seed[0]^0x30, seed[1]^0x82)
    enc_prefix_index = {}
    for offset in range(0, elf_len - 270):
        key2 = (elf_data[offset], elf_data[offset + 1])
        if key2 not in enc_prefix_index:
            enc_prefix_index[key2] = []
        enc_prefix_index[key2].append(offset)

    for offset in range(0, elf_len - 32):
        seed = elf_data[offset : offset + 32]
        if seed == b"\x00" * 32 or len(set(seed)) < 12:
            continue
        # Compute expected first 2 bytes of encrypted RSA key
        expected = (seed[0] ^ 0x30, seed[1] ^ 0x82)
        if expected not in enc_prefix_index:
            continue
        for rsa_offset in enc_prefix_index[expected]:
            # Skip if contiguous (already checked in pass 1)
            if rsa_offset == offset + 32:
                continue
            # Only check nearby (within 512 bytes before or after seed)
            dist = abs(rsa_offset - offset)
            if dist > 512 or dist < 32:
                continue
            enc = elf_data[rsa_offset : rsa_offset + 270]
            if len(enc) < 270:
                continue
            dec = _try_xor_rsa(seed, enc)
            if dec:
                if verbose:
                    print(f"    Seed at 0x{offset:x}, RSA at 0x{rsa_offset:x} (gap={dist-32 if rsa_offset<offset else dist-270})")
                return seed, dec

    return None, None


def find_seed_and_rsa_chacha20(elf_path, verbose=False):
    """Find seed and RSA key using miasm + ChaCha20 (x86_64 fallback).

    Uses the RandoriSec/nurfed1 approach:
    1. Find fgt_verify_initrd function via objdump/miasm
    2. Extract ChaCha20 key/IV from SHA256 call parameters
    3. Decrypt RSA public key with ChaCha20
    """
    try:
        from miasm.core.locationdb import LocationDB
        from miasm.analysis.binary import Container
        from miasm.analysis.machine import Machine
        from hashlib import sha256
        from Crypto.Cipher import ChaCha20
    except ImportError:
        return None, None, None

    loc_db = LocationDB()
    container = Container.from_stream(open(elf_path, "rb"), loc_db)

    # Try to find fgt_verifier_pub_key symbol (FortiOS 7.4.2-7.4.3)
    fgt_addr = None
    for sym_name in ["fgt_verifier_pub_key", "fgt_verify_initrd", "fgt_verify_decrypt"]:
        try:
            fgt_addr = loc_db.get_name_offset(sym_name)
            if verbose:
                print(f"    Found {sym_name} at {hex(fgt_addr)}")
            break
        except Exception:
            continue

    if fgt_addr is None:
        # Try RandoriSec approach: find via objdump
        try:
            output = subprocess.check_output(
                f"""objdump -d --section=.init.text {elf_path} 2>/dev/null |
                egrep "rsa_parse_pub_key|push.*rbp" |
                egrep "rsa_parse_pub_key" -B1 |
                head -1 |
                cut -d':' -f1""",
                shell=True, text=True,
            ).strip()
            if output:
                fgt_addr = int(output, 16)
                if verbose:
                    print(f"    Found verify function at {hex(fgt_addr)} via objdump")
        except Exception:
            pass

    if fgt_addr is None:
        # Try searching .kernel section
        try:
            output = subprocess.check_output(
                f"""objdump -d --section=.kernel {elf_path} 2>/dev/null |
                egrep "rsa_parse_pub_key|push.*rbp" |
                egrep "rsa_parse_pub_key" -B1 |
                head -1 |
                cut -d':' -f1""",
                shell=True, text=True, timeout=120,
            ).strip()
            if output:
                fgt_addr = int(output, 16)
                if verbose:
                    print(f"    Found verify function at {hex(fgt_addr)} via objdump (.kernel)")
        except Exception:
            pass

    if fgt_addr is None:
        return None, None, None

    machine = Machine(container.arch)
    mdis = machine.dis_engine(container.bin_stream, loc_db=container.loc_db)

    # Disassemble from the found address
    try:
        asmcfg = mdis.dis_multiblock(fgt_addr)
    except Exception:
        return None, None, None

    # Search for MOV RSI (seed address) and MOV RDX (RSA key address)
    rsi_values = []
    rdx_values = []
    for block in asmcfg.blocks:
        for instr in block.lines:
            if instr.name == "MOV":
                dst, src = instr.get_args_expr()
                if dst.is_id() and dst.name == "RSI" and src.is_int():
                    rsi_values.append(src.arg)
                if dst.is_id() and dst.name == "RDX" and src.is_int():
                    rdx_values.append(src.arg)

    if not rsi_values or not rdx_values:
        return None, None, None

    seed_addr = min(rsi_values)
    rsapubkey_addr = rdx_values[0]

    if verbose:
        print(f"    Seed address: {hex(seed_addr)}")
        print(f"    RSA key address: {hex(rsapubkey_addr)}")

    # Read seed and encrypted RSA key
    virt = container.executable.get_virt()
    seed = virt.get(seed_addr, seed_addr + 32)
    enc_rsa = virt.get(rsapubkey_addr, rsapubkey_addr + 270)

    # Try multiple ChaCha20 key derivation split points
    split_combos = [
        (5, 2), (4, 5), (3, 1), (5, 5), (2, 5),
        (1, 3), (3, 2), (4, 2), (5, 3), (2, 3),
    ]

    for key_split, iv_split in split_combos:
        sha_key = sha256(seed[key_split:] + seed[:key_split]).digest()
        sha_iv = sha256(seed[iv_split:] + seed[:iv_split]).digest()[:16]

        try:
            chacha = ChaCha20.new(key=sha_key, nonce=sha_iv[4:])
            counter = int.from_bytes(sha_iv[:4], "little")
            chacha.seek(counter * 64)
            dec = chacha.decrypt(enc_rsa)
        except Exception:
            continue

        if dec[:4] == b"\x30\x82\x01\x0A" and dec[265:270] == b"\x02\x03\x01\x00\x01":
            if verbose:
                print(f"    ChaCha20 split: key={key_split}, iv={iv_split}")
            return seed, bytes(dec), "chacha20_aesctr"

    # Try dynamic extraction (nurfed1 approach for 7.6.x)
    rsi_edx_pairs = []
    for block in asmcfg.blocks:
        if "sha256_update" not in block.to_string():
            continue
        rsi_val, edx_val = 0, 0
        for instr in block.lines:
            if instr.name == "MOV":
                dst, src = instr.get_args_expr()
                dst_name = None
                if dst.is_id():
                    dst_name = dst.name
                elif dst.is_slice() and dst.arg.is_id():
                    base = dst.arg.name.upper()
                    start, stop = dst.start, dst.stop
                    if base == "RDX" and start == 0 and stop == 32:
                        dst_name = "EDX"
                    elif base == "RSI" and start == 0 and stop == 64:
                        dst_name = "RSI"
                if dst_name == "RSI" and src.is_int():
                    rsi_val = src.arg
                if dst_name == "EDX" and src.is_int():
                    edx_val = src.arg
        rsi_edx_pairs.append((rsi_val, edx_val))
        if len(rsi_edx_pairs) == 4:
            break

    if len(rsi_edx_pairs) == 4:
        try:
            sha_key_hash = sha256()
            sha_key_hash.update(virt.get(rsi_edx_pairs[0][0], rsi_edx_pairs[0][0] + rsi_edx_pairs[0][1]))
            sha_key_hash.update(virt.get(rsi_edx_pairs[1][0], rsi_edx_pairs[1][0] + rsi_edx_pairs[1][1]))
            chacha_key = sha_key_hash.digest()

            sha_iv_hash = sha256()
            sha_iv_hash.update(virt.get(rsi_edx_pairs[2][0], rsi_edx_pairs[2][0] + rsi_edx_pairs[2][1]))
            sha_iv_hash.update(virt.get(rsi_edx_pairs[3][0], rsi_edx_pairs[3][0] + rsi_edx_pairs[3][1]))
            chacha_iv = sha_iv_hash.digest()[:16]

            chacha = ChaCha20.new(key=chacha_key, nonce=chacha_iv[4:])
            counter = int.from_bytes(chacha_iv[:4], "little")
            chacha.seek(counter * 64)
            dec = chacha.decrypt(enc_rsa)

            if dec[:4] == b"\x30\x82\x01\x0A" and dec[265:270] == b"\x02\x03\x01\x00\x01":
                if verbose:
                    print(f"    Dynamic ChaCha20 key extraction succeeded")
                return seed, bytes(dec), "chacha20_aesctr"
        except Exception:
            pass

    return None, None, None


def stage3_kernel_analysis(flatkc_path, output_dir, verbose=False):
    """Extract crypto material from kernel."""
    print("[*] Stage 3: Kernel crypto material extraction")

    elf_path = os.path.join(output_dir, "flatkc.elf")
    arch = convert_flatkc_to_elf(flatkc_path, elf_path)
    print(f"[+] Kernel converted to ELF ({arch})")

    with open(elf_path, "rb") as f:
        elf_data = f.read()

    # Method 1: XOR brute-force (works for aarch64 7.6.x)
    print(f"    Scanning kernel ({len(elf_data)} bytes) for seed + RSA key...")
    seed, decrypted_rsa = find_seed_and_rsa_universal(elf_data, verbose)
    cipher_mode = "modified_rc4"

    # Method 2: ChaCha20 via miasm (fallback for x86_64)
    if seed is None:
        print("    XOR method failed, trying ChaCha20 + miasm...")
        seed, decrypted_rsa, cipher_mode = find_seed_and_rsa_chacha20(elf_path, verbose)

    if seed is None:
        raise RuntimeError(
            "Seed / RSA key not found in kernel.\n"
            "    For x86_64 firmware with obfuscated kernels, try:\n"
            "      pip install miasm pycryptodome\n"
            "    Or use --skip-rootfs to extract filesystem without decryption."
        )

    if verbose:
        print(f"    Seed: {seed.hex().upper()}")
        print(f"    Cipher mode: {cipher_mode}")

    # Parse RSA public key
    from pyasn1.codec.ber import decoder
    from pyasn1_modules import rfc3279

    decoded_key, _ = decoder.decode(bytes(decrypted_rsa), asn1Spec=rfc3279.RSAPublicKey())
    modulus = int(decoded_key["modulus"])
    exponent = int(decoded_key["publicExponent"])
    mod_bits = modulus.bit_length()
    print(f"[+] RSA public key: {mod_bits}-bit, e={exponent}")

    return {
        "seed": seed,
        "modulus": modulus,
        "exponent": exponent,
        "arch": arch,
        "cipher_mode": cipher_mode,
    }


# Stage 4: rootfs.gz Decryption (Modified RC4)

def modified_rc4(key, data, progress_callback=None, keep_j=False):
    """
    Modified RC4 cipher used in FortiOS 7.6.x
    Standard RC4 KSA + modified PRGA with:
    - Cross-rotated S-box indices (byte bit rotation mixed between i and j)
    - Multi-lookup output generation with XOR constant 0xAA

    keep_j: if True, PRGA starts with j from KSA's final value instead of 0.
            Some kernel builds (compiled with different optimization) don't reset j.
    """
    # KSA (standard RC4)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i & 0x1F]) & 0xFF
        S[i], S[j] = S[j], S[i]

    # Modified PRGA
    w14 = (-0x56) & 0xFFFFFFFF  # = 0xFFFFFFAA
    i_val = 0
    j_val = j if keep_j else 0
    result = bytearray(len(data))
    total = len(data)
    last_pct = -1

    for pos in range(total):
        ct = data[pos]
        i_val = (i_val + 1) & 0xFF

        # Cross-rotated indices
        i_lo = (i_val & 0x1F) << 3
        i_hi = (i_val >> 5) & 0x7

        si = S[i_val]
        j_val = (j_val + si) & 0xFF

        j_lo = (j_val & 0x1F) << 3
        j_hi = (j_val >> 5) & 0x7

        i_rot = (i_lo | j_hi) & 0xFF
        j_rot = (j_lo | i_hi) & 0xFF

        # Swap S[i], S[j]
        sj = S[j_val]
        S[i_val] = sj
        S[j_val] = si

        t = (si + sj) & 0xFF
        u = (sj + j_val) & 0xFF

        # Multi-lookup output
        v1 = ((S[i_rot] + S[j_rot]) ^ w14) & 0xFF
        v2 = ((S[v1] + S[t]) ^ S[u] ^ ct) & 0xFF
        result[pos] = v2

        if progress_callback and pos % (1 << 20) == 0:
            pct = pos * 100 // total
            if pct != last_pct:
                progress_callback(pct)
                last_pct = pct

    if progress_callback:
        progress_callback(100)

    return bytes(result)


def decrypt_rootfs_aesctr(rootfs_enc, sig_payload, verbose=False):
    """Decrypt rootfs.gz using AES-CTR (FortiOS 7.4.3+ / 7.6.x x86_64)."""
    import ctypes
    from Crypto.Cipher import AES

    # Parse the signature payload as crypto_ctx struct
    # FortiOS 7.6.x layout: padding(174) | null(1) | rootfs_hash(32) | counter(16) | aes_key(32)
    if len(sig_payload) < 255:
        raise RuntimeError(f"Signature payload too short: {len(sig_payload)} bytes")

    rootfs_hash = sig_payload[175:207]
    counter = bytearray(sig_payload[207:223])
    aes_key = bytes(sig_payload[223:255])

    # Verify hash
    sha = hashlib.sha256()
    sha.update(rootfs_enc)
    if sha.digest() != rootfs_hash:
        # Try 7.4.x layout: padding(174) | null(1) | counter(16) | aes_key(32) | rootfs_hash(32)
        counter = bytearray(sig_payload[175:191])
        aes_key = bytes(sig_payload[191:223])
        rootfs_hash = sig_payload[223:255]
        if sha.digest() != rootfs_hash:
            raise RuntimeError("SHA-256 hash mismatch in AES-CTR mode")

    if verbose:
        print(f"    AES-256 key: {aes_key.hex().upper()}")
        print(f"    Counter: {counter.hex().upper()}")

    # Calculate counter increment (FortiOS custom)
    ctr_increment = 0
    for i in range(16):
        ctr_increment ^= (counter[i] & 0xF) ^ (counter[i] >> 4)
    if ctr_increment == 0:
        ctr_increment = 1

    if verbose:
        print(f"    Counter increment: {ctr_increment}")

    # AES-CTR decryption
    cipher = AES.new(aes_key, AES.MODE_ECB)
    result = bytearray()

    nonce = int.from_bytes(counter[:8], "little")
    ctr_val = int.from_bytes(counter[8:16], "little")

    total = len(rootfs_enc)
    blk_off = 0
    last_pct = -1
    while blk_off < total:
        # Build counter block
        ctr_block = nonce.to_bytes(8, "little") + ctr_val.to_bytes(8, "little")
        keystream = cipher.encrypt(ctr_block)

        chunk = rootfs_enc[blk_off:blk_off + 16]
        result.extend(b ^ k for b, k in zip(chunk, keystream))

        ctr_val = (ctr_val + max(ctr_increment, 1)) & 0xFFFFFFFFFFFFFFFF
        blk_off += 16

        pct = blk_off * 100 // total
        if pct != last_pct:
            print(f"\r    Progress: {pct}%", end="", flush=True)
            last_pct = pct

    print()
    return bytes(result)


def stage4_decrypt_rootfs(rootfs_path, crypto_material, output_dir, verbose=False):
    """Decrypt rootfs.gz using crypto material from kernel."""
    print("[*] Stage 4: rootfs.gz decryption")

    with open(rootfs_path, "rb") as f:
        rootfs_data = f.read()

    rootfs_enc = rootfs_data[:-256]
    rootfs_sig = rootfs_data[-256:]

    modulus = crypto_material["modulus"]
    exponent = crypto_material["exponent"]
    cipher_mode = crypto_material.get("cipher_mode", "modified_rc4")

    # RSA signature decryption
    sig_int = int.from_bytes(rootfs_sig, "big")
    decrypted_int = pow(sig_int, exponent, modulus)
    num_bytes = (decrypted_int.bit_length() + 7) // 8
    sig_bytes = decrypted_int.to_bytes(max(num_bytes, 1), "big")

    # Parse PKCS#1 v1.5 structure
    if sig_bytes[0] != 0x01:
        raise RuntimeError(f"Invalid PKCS#1 signature (first byte: 0x{sig_bytes[0]:02x})")

    null_pos = sig_bytes.index(b"\x00", 1)
    payload = sig_bytes[null_pos + 1:]
    payload_len = len(payload)

    if verbose:
        print(f"    Signature payload: {payload_len} bytes")
        print(f"    Cipher mode: {cipher_mode}")

    if cipher_mode == "chacha20_aesctr":
        # AES-CTR mode (FortiOS 7.4.3+ / 7.6.x x86_64)
        print("[+] Decrypting rootfs.gz with AES-CTR...")
        decrypted = decrypt_rootfs_aesctr(rootfs_enc, payload, verbose)
    else:
        # Modified RC4 mode (FortiOS 7.6.x aarch64)
        # Find the hash in the payload (32 bytes)
        sha = hashlib.sha256()
        sha.update(rootfs_enc)
        actual_hash = sha.digest()

        hash_offset = None
        for i in range(payload_len - 32):
            if payload[i : i + 32] == actual_hash:
                hash_offset = i
                break

        if hash_offset is None:
            raise RuntimeError("SHA-256 hash not found in RSA signature")

        print("[+] SHA-256 hash verified")

        # Extract key: the last 32 bytes of the payload
        rc4_key = payload[-32:]

        if verbose:
            print(f"    RC4 key: {rc4_key.hex().upper()}")

        # Decrypt with modified RC4
        # Auto-detect j initialization: some kernel builds reset j to 0, others keep KSA's j
        test_j0 = modified_rc4(rc4_key, rootfs_enc[:4], keep_j=False)
        test_jk = modified_rc4(rc4_key, rootfs_enc[:4], keep_j=True)
        if test_j0[:2] == b"\x1f\x8b":
            keep_j = False
        elif test_jk[:2] == b"\x1f\x8b":
            keep_j = True
        else:
            raise RuntimeError(f"RC4 decryption failed: neither j=0 ({test_j0[:2].hex()}) nor j=keep ({test_jk[:2].hex()}) produces gzip")

        if verbose:
            print(f"    RC4 j_init: {'keep' if keep_j else 'reset'}")

        print(f"[+] Decrypting rootfs.gz ({len(rootfs_enc) / (1024*1024):.1f} MB)...")

        def progress(pct):
            print(f"\r    Progress: {pct}%", end="", flush=True)

        decrypted = modified_rc4(rc4_key, rootfs_enc, progress_callback=progress, keep_j=keep_j)
        print()

    # Verify gzip
    if decrypted[:2] != b"\x1f\x8b":
        raise RuntimeError(f"Decrypted data is not gzip (magic: {decrypted[:2].hex()})")

    dec_gz_path = os.path.join(output_dir, "rootfs.gz.dec")
    with open(dec_gz_path, "wb") as f:
        f.write(decrypted)
    print(f"[+] rootfs.gz decrypted -> {dec_gz_path}")

    # Decompress gzip
    rootfs_cpio_path = os.path.join(output_dir, "rootfs.cpio")
    with gzip.open(io.BytesIO(decrypted), "rb") as gz:
        with open(rootfs_cpio_path, "wb") as out:
            shutil.copyfileobj(gz, out)
    print(f"[+] Decompressed -> {rootfs_cpio_path}")

    # Extract CPIO
    rootfs_dir = os.path.join(output_dir, "rootfs")
    os.makedirs(rootfs_dir, exist_ok=True)
    subprocess.run(
        ["cpio", "-id"],
        input=open(rootfs_cpio_path, "rb").read(),
        cwd=rootfs_dir,
        capture_output=True,
    )

    # Count extracted files
    count = sum(len(files) for _, _, files in os.walk(rootfs_dir))
    print(f"[+] Extracted CPIO archive -> {rootfs_dir}/ ({count} files)")

    return rootfs_dir


# Main

def main():
    parser = argparse.ArgumentParser(
        description="fgx - FortiGate Firmware Extraction Toolkit (FortiOS 7.6.x)",
    )
    parser.add_argument("firmware", help="Path to .out firmware file")
    parser.add_argument("-o", "--output-dir", default="./fgx_output",
                        help="Output directory (default: ./fgx_output)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--skip-outer", action="store_true",
                        help="Skip outer decryption (input is already decrypted image)")
    parser.add_argument("--skip-rootfs", action="store_true",
                        help="Only extract filesystem, skip rootfs decryption")
    parser.add_argument("--keep-intermediate", action="store_true",
                        help="Keep intermediate files")
    args = parser.parse_args()

    print(BANNER)

    if not os.path.isfile(args.firmware):
        print(f"[-] File not found: {args.firmware}")
        sys.exit(1)

    output_dir = os.path.abspath(args.output_dir)
    os.makedirs(output_dir, exist_ok=True)

    try:
        # Stage 1: Outer layer
        if args.skip_outer:
            print("[*] Skipping outer layer (--skip-outer)")
            with open(args.firmware, "rb") as f:
                image_data = f.read()
        else:
            image_data = stage1_outer_decrypt(args.firmware, args.verbose)

        # Stage 2: Filesystem extraction
        extracted = stage2_extract_fs(image_data, output_dir, args.verbose)

        if args.skip_rootfs:
            print("[*] Skipping rootfs decryption (--skip-rootfs)")
            print(f"[*] Done! Files in {output_dir}/")
            return

        # Stage 3: Kernel analysis
        crypto = stage3_kernel_analysis(
            extracted["flatkc"], output_dir, args.verbose
        )

        # Stage 4: rootfs decryption
        rootfs_dir = stage4_decrypt_rootfs(
            extracted["rootfs.gz"], crypto, output_dir, args.verbose
        )

        # Cleanup intermediate files
        if not args.keep_intermediate:
            for name in ["flatkc.elf", "rootfs.gz.dec", "rootfs.cpio"]:
                path = os.path.join(output_dir, name)
                if os.path.exists(path):
                    os.remove(path)

        print(f"\n[*] Done! Extracted firmware in {output_dir}/")
        print(f"    rootfs/     - Root filesystem")
        if "datafs.tar.gz" in extracted:
            print(f"    datafs.tar.gz - Data filesystem archive")
        if "split_rootfs.tar.xz" in extracted:
            print(f"    split_rootfs.tar.xz - Additional binaries")

    except Exception as e:
        print(f"\n[-] Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
