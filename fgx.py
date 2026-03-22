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

    # Clean up ext image
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


def parse_elf_symbols(elf_data):
    """Parse ELF symbol table. Returns dict of addr -> name."""
    # ELF64 header
    e_shoff = struct.unpack_from("<Q", elf_data, 40)[0]
    e_shentsize = struct.unpack_from("<H", elf_data, 58)[0]
    e_shnum = struct.unpack_from("<H", elf_data, 60)[0]
    e_shstrndx = struct.unpack_from("<H", elf_data, 62)[0]

    # Section headers
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name = struct.unpack_from("<I", elf_data, off)[0]
        sh_type = struct.unpack_from("<I", elf_data, off + 4)[0]
        sh_addr = struct.unpack_from("<Q", elf_data, off + 16)[0]
        sh_offset = struct.unpack_from("<Q", elf_data, off + 24)[0]
        sh_size = struct.unpack_from("<Q", elf_data, off + 32)[0]
        sh_link = struct.unpack_from("<I", elf_data, off + 40)[0]
        sh_entsize = struct.unpack_from("<Q", elf_data, off + 56)[0]
        sections.append({
            "name_idx": sh_name, "type": sh_type, "addr": sh_addr,
            "offset": sh_offset, "size": sh_size, "link": sh_link,
            "entsize": sh_entsize,
        })

    # Find symbol table and string table
    symtab = None
    strtab_data = None
    for sec in sections:
        if sec["type"] == 2:  # SHT_SYMTAB
            symtab = sec
            strtab_sec = sections[sec["link"]]
            strtab_data = elf_data[strtab_sec["offset"]:strtab_sec["offset"] + strtab_sec["size"]]
            break

    if not symtab or not strtab_data:
        return {}, {}

    symbols = {}  # addr -> name
    symbols_by_name = {}  # name -> addr
    num_syms = symtab["size"] // symtab["entsize"]
    for i in range(num_syms):
        off = symtab["offset"] + i * symtab["entsize"]
        st_name = struct.unpack_from("<I", elf_data, off)[0]
        st_value = struct.unpack_from("<Q", elf_data, off + 8)[0]
        # Get symbol name
        end = strtab_data.index(b"\x00", st_name)
        name = strtab_data[st_name:end].decode("ascii", errors="ignore")
        if name and st_value:
            symbols[st_value] = name
            symbols_by_name[name] = st_value

    return symbols, symbols_by_name


def find_kernel_section(elf_data):
    """Find the main kernel section's vaddr, file offset, and size."""
    e_shoff = struct.unpack_from("<Q", elf_data, 40)[0]
    e_shentsize = struct.unpack_from("<H", elf_data, 58)[0]
    e_shnum = struct.unpack_from("<H", elf_data, 60)[0]
    e_shstrndx = struct.unpack_from("<H", elf_data, 62)[0]

    shstr_sec_off = e_shoff + e_shstrndx * e_shentsize
    shstr_offset = struct.unpack_from("<Q", elf_data, shstr_sec_off + 24)[0]

    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name_idx = struct.unpack_from("<I", elf_data, off)[0]
        sh_addr = struct.unpack_from("<Q", elf_data, off + 16)[0]
        sh_offset = struct.unpack_from("<Q", elf_data, off + 24)[0]
        sh_size = struct.unpack_from("<Q", elf_data, off + 32)[0]
        end = elf_data.index(b"\x00", shstr_offset + sh_name_idx)
        name = elf_data[shstr_offset + sh_name_idx:end].decode("ascii", errors="ignore")
        if name in (".kernel", ".text") and sh_size > 0x100000:
            return sh_addr, sh_offset, sh_size
    return None, None, None


def find_seed_aarch64(elf_data, rsa_addr, init_start, init_end, kernel_vaddr, kernel_foff):
    """Find seed address by scanning init text for BL to rsa_parse_pub_key (aarch64)."""
    init_foff = kernel_foff + (init_start - kernel_vaddr)

    # Find BL to rsa_parse_pub_key
    bl_pc = None
    for i in range(0, init_end - init_start, 4):
        fpos = init_foff + i
        insn = struct.unpack_from("<I", elf_data, fpos)[0]
        if (insn >> 26) == 0x25:  # BL
            imm26 = insn & 0x3FFFFFF
            if imm26 & 0x2000000:
                offset = struct.unpack("q", struct.pack("Q", ((imm26 | ~0x3FFFFFF) << 2) & 0xFFFFFFFFFFFFFFFF))[0]
            else:
                offset = imm26 << 2
            target = (init_start + i + offset) & 0xFFFFFFFFFFFFFFFF
            if target == rsa_addr:
                bl_pc = init_start + i
                break

    if not bl_pc:
        raise RuntimeError("BL to rsa_parse_pub_key not found in init section")

    # Search backward for ADRP + ADD pattern loading the seed address
    search_start = bl_pc - 256
    search_foff = kernel_foff + (search_start - kernel_vaddr)

    seed_addr = None
    for i in range(0, bl_pc - search_start, 4):
        fpos = search_foff + i
        insn = struct.unpack_from("<I", elf_data, fpos)[0]
        # ADRP
        if (insn & 0x9F000000) == 0x90000000:
            rd = insn & 0x1F
            immhi = (insn >> 5) & 0x7FFFF
            immlo = (insn >> 29) & 0x3
            imm = (immhi << 2) | immlo
            if imm & 0x100000:
                imm -= 0x200000
            pc = search_start + i
            page = ((pc >> 12) + imm) << 12

            # Check next instruction for ADD
            next_insn = struct.unpack_from("<I", elf_data, fpos + 4)[0]
            if (next_insn & 0xFFC00000) == 0x91000000:  # ADD (64-bit)
                add_rd = next_insn & 0x1F
                add_rn = (next_insn >> 5) & 0x1F
                add_imm = (next_insn >> 10) & 0xFFF
                if add_rn == rd:
                    full_addr = page + add_imm
                    # Check if next-next is ADD Xn, Xm, #0x20 (RSA key = seed + 32)
                    next2 = struct.unpack_from("<I", elf_data, fpos + 8)[0]
                    next2_imm = (next2 >> 10) & 0xFFF
                    next2_op = (next2 >> 24) & 0xFF
                    if next2_op == 0x91 and next2_imm == 0x20:
                        seed_addr = full_addr
                        break

    if not seed_addr:
        raise RuntimeError("Seed address not found")

    return seed_addr, bl_pc


def find_seed_x86_64(elf_data, rsa_addr, init_start, init_end, kernel_vaddr, kernel_foff):
    """Find seed address for x86_64 kernels."""
    # For x86_64, search for CALL to rsa_parse_pub_key and look for
    # preceding MOV RSI, <immediate> or LEA instructions
    raise RuntimeError("x86_64 kernel analysis not yet implemented - use forticrack tools")


def stage3_kernel_analysis(flatkc_path, output_dir, verbose=False):
    """Extract crypto material from kernel."""
    print("[*] Stage 3: Kernel crypto material extraction")

    elf_path = os.path.join(output_dir, "flatkc.elf")
    arch = convert_flatkc_to_elf(flatkc_path, elf_path)
    print(f"[+] Kernel converted to ELF ({arch})")

    with open(elf_path, "rb") as f:
        elf_data = f.read()

    symbols, symbols_by_name = parse_elf_symbols(elf_data)
    kernel_vaddr, kernel_foff, kernel_size = find_kernel_section(elf_data)

    if not kernel_vaddr:
        raise RuntimeError("Kernel section not found")

    rsa_addr = symbols_by_name.get("rsa_parse_pub_key")
    if not rsa_addr:
        raise RuntimeError("rsa_parse_pub_key symbol not found")
    if verbose:
        print(f"    rsa_parse_pub_key at 0x{rsa_addr:x}")

    # Get init text boundaries from symbols
    init_start = symbols_by_name.get("_sinittext") or symbols_by_name.get("__init_begin")
    init_end = symbols_by_name.get("_einittext")
    if not init_start or not init_end:
        raise RuntimeError("Init section boundaries not found")

    if verbose:
        print(f"    Init text: 0x{init_start:x} - 0x{init_end:x}")

    if arch == "aarch64":
        seed_addr, bl_pc = find_seed_aarch64(
            elf_data, rsa_addr, init_start, init_end, kernel_vaddr, kernel_foff
        )
    else:
        seed_addr, bl_pc = find_seed_x86_64(
            elf_data, rsa_addr, init_start, init_end, kernel_vaddr, kernel_foff
        )

    print(f"[+] Seed address: 0x{seed_addr:x}")

    # Read seed (32 bytes) and encrypted RSA key (270 bytes at seed+32)
    seed_foff = kernel_foff + (seed_addr - kernel_vaddr)
    seed = elf_data[seed_foff : seed_foff + 32]
    encrypted_rsa = elf_data[seed_foff + 32 : seed_foff + 32 + 270]

    if verbose:
        print(f"    Seed: {seed.hex().upper()}")

    # XOR decrypt RSA public key
    decrypted_rsa = bytearray(270)
    for i in range(270):
        decrypted_rsa[i] = encrypted_rsa[i] ^ seed[i & 0x1F]

    if decrypted_rsa[0] != 0x30:
        raise RuntimeError(f"Decrypted RSA key has invalid ASN.1 tag: 0x{decrypted_rsa[0]:02x}")

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
    }


# Stage 4: rootfs.gz Decryption (Modified RC4)

def modified_rc4(key, data, progress_callback=None):
    """
    Modified RC4 cipher used in FortiOS 7.6.x
    Standard RC4 KSA + modified PRGA with:
    - Cross-rotated S-box indices (byte bit rotation mixed between i and j)
    - Multi-lookup output generation with XOR constant 0xAA
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
    j_val = 0
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


def stage4_decrypt_rootfs(rootfs_path, crypto_material, output_dir, verbose=False):
    """Decrypt rootfs.gz using crypto material from kernel."""
    print("[*] Stage 4: rootfs.gz decryption")

    with open(rootfs_path, "rb") as f:
        rootfs_data = f.read()

    rootfs_enc = rootfs_data[:-256]
    rootfs_sig = rootfs_data[-256:]

    modulus = crypto_material["modulus"]
    exponent = crypto_material["exponent"]

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

    # Find the hash in the payload (32 bytes)
    sha = hashlib.sha256()
    sha.update(rootfs_enc)
    actual_hash = sha.digest()

    # Search for the hash in the payload
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
    print(f"[+] Decrypting rootfs.gz ({len(rootfs_enc) / (1024*1024):.1f} MB)...")

    def progress(pct):
        print(f"\r    Progress: {pct}%", end="", flush=True)

    decrypted = modified_rc4(rc4_key, rootfs_enc, progress_callback=progress)
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
