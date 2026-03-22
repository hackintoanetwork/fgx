# fgx

End-to-end FortiGate firmware decryption and extraction toolkit for FortiOS 7.6.x.

Automates the entire pipeline from encrypted `.out` firmware files to a fully extracted root filesystem with a single command. Supports both aarch64 (ARM64) and x86_64 FortiGate appliances. Developed through reverse engineering of FortiOS 7.6.6 firmware encryption, including the discovery of a previously undocumented modified RC4 stream cipher used in the latest FortiOS versions.

## Features

- Full pipeline automation: encrypted `.out` file to extracted rootfs in one command
- FortiCrack-compatible outer layer decryption (known-plaintext XOR block cipher)
- Architecture-independent kernel crypto material extraction (no symbol resolution required)
- Novel modified RC4 decryption for FortiOS 7.6.x rootfs.gz (first public implementation)
- Support for both aarch64 (ARM64) and x86_64 FortiGate appliances
- Auto-detection of crypto material layout and cipher variant
- No GUI required -- fully headless operation

## Requirements

### Python packages

```bash
pip install -r requirements.txt
```

### System tools

- `7z` (p7zip) -- for ext3 filesystem extraction
- `gunzip` -- for gzip decompression
- `cpio` -- for CPIO archive extraction
- Python 3.8+

## Usage

### Basic usage

```bash
python3 fgx.py FGT_60F-v7.6.6.M-build3652-FORTINET.out
```

### With options

```bash
# Specify output directory
python3 fgx.py firmware.out -o ./output

# Verbose output (show seed, keys, intermediate values)
python3 fgx.py firmware.out -v

# Skip outer decryption (input is already a decrypted image)
python3 fgx.py decrypted_image --skip-outer

# Only extract filesystem, skip rootfs decryption
python3 fgx.py firmware.out --skip-rootfs

# Keep intermediate files (ELF kernel, CPIO, decrypted rootfs)
python3 fgx.py firmware.out --keep-intermediate
```

## Decryption Pipeline

fgx performs four stages of decryption and extraction:

### Stage 1: Outer Layer Decryption

The `.out` firmware file is gzip-compressed. After decompression, the raw image is encrypted with a proprietary XOR block cipher (512-byte blocks, 32-byte alphanumeric key, CBC-like chaining with IV=0xFF).

fgx recovers the key using a known-plaintext attack: null bytes at offset 48-79 of the first valid block allow derivation of all 32 key bytes. This approach is compatible with Bishop Fox's FortiCrack.

### Stage 2: Filesystem Extraction

The decrypted image contains an MBR partition table with an ext3 filesystem (volume label "FORTIOS") at offset 512. fgx extracts the following files:

| File | Description |
|------|-------------|
| `rootfs.gz` | Encrypted root filesystem (gzip + custom cipher) |
| `flatkc` | Linux kernel image (contains crypto material) |
| `datafs.tar.gz` | Data filesystem (configs, IPS rules, AV signatures) |
| `split_rootfs.tar.xz` | Additional binaries (node, smbcd, smartctl) |
| `devicetree.dtb` | Device tree blob (aarch64 only) |

### Stage 3: Kernel Crypto Material Extraction

The kernel (`flatkc`) is converted to an ELF binary using `vmlinux-to-elf`, which recovers the kallsyms symbol table.

fgx uses a pure brute-force binary scan that requires **no symbol resolution or disassembly** -- it works even when `vmlinux-to-elf` produces incorrect symbol addresses (a known issue with FortiOS 7.6.x kernels based on Linux 3.2.16):

1. **Pass 1 (contiguous):** Scans for a 32-byte seed immediately followed by a 270-byte XOR-encrypted RSA public key. Works for aarch64 firmware where `[seed][RSA_key]` are adjacent.

2. **Pass 2 (non-contiguous):** If Pass 1 fails, builds an index of all 2-byte prefixes and searches for seed/RSA pairs separated by up to 512 bytes. Works for x86_64 firmware where the layout is `[RSA_key][18-byte alignment padding][seed]`.

3. **Validation:** Each candidate is XOR-decrypted and checked against the ASN.1 DER structure of an RSA-2048 public key (header `30 82 01 0A 02 82 01 01 00`, exponent `02 03 01 00 01`).

### Stage 4: rootfs.gz Decryption

The rootfs.gz encryption in FortiOS 7.6.x uses a novel scheme not previously documented:

1. The RSA public key (extracted in Stage 3) decrypts the PKCS#1 v1.5 signature appended to rootfs.gz (last 256 bytes)
2. The signature payload contains a SHA-256 hash (verified against the encrypted data) and a 32-byte RC4 key
3. The rootfs data is decrypted using a modified RC4 stream cipher
4. The cipher variant (PRGA j-initialization) is auto-detected by testing gzip magic on the first 4 decrypted bytes

#### Modified RC4 Algorithm (FortiOS 7.6.x)

This cipher uses a standard RC4 Key Scheduling Algorithm (KSA) with a 32-byte key, but the Pseudo-Random Generation Algorithm (PRGA) is significantly modified:

```
Standard RC4 PRGA:
  output = S[S[i] + S[j]]

FortiOS 7.6.x Modified PRGA:
  i = (i + 1) & 0xFF
  S_i = S[i]; j = (j + S_i) & 0xFF; S_j = S[j]

  # Cross-rotated indices (byte bit rotation mixed between i and j)
  rot1 = ((i & 0x1F) << 3) | ((j >> 5) & 0x7)
  rot2 = ((j & 0x1F) << 3) | ((i >> 5) & 0x7)

  swap S[i], S[j]

  t = (S_i + S_j) & 0xFF
  u = (S_j + j) & 0xFF

  # Multi-lookup output with XOR constant 0xAA
  combined = ((S[rot1] + S[rot2]) ^ 0xFFFFFFAA) & 0xFF
  keystream = ((S[combined] + S[t]) ^ S[u]) & 0xFF

  output = keystream ^ ciphertext_byte
```

**Compiler variant:** Some kernel builds (e.g., FGT_2500E, FGT_1000D) do not reset `j` to zero before the PRGA, retaining the final KSA value. fgx auto-detects this by testing both modes against the expected gzip header.

#### Crypto Material Layout

The seed and encrypted RSA key are stored differently depending on the architecture:

| Architecture | Layout | Gap |
|:------------:|--------|:---:|
| aarch64 | `[seed 32B][RSA 270B]` | 0 |
| x86_64 | `[RSA 270B][padding 18B][seed 32B]` | 18 (32-byte alignment) |

## Output Structure

```
output/
  rootfs/                 Root filesystem (CPIO extracted)
    sbin/init             FortiOS init process (ELF)
    bin.tar.xz            FortiOS binaries archive
    lib/                  Shared libraries
    node-scripts/         Node.js scripts and native module
    data/                 Configuration data
    var/                  Runtime directories
  datafs.tar.gz           Data filesystem (IPS/AV signatures, certs)
  split_rootfs.tar.xz     Additional binaries (node, smbcd)
  flatkc                  Kernel image (raw)
  rootfs.gz               Encrypted rootfs (original)
```

## Technical Notes

### FortiOS Binary Architecture

FortiOS uses a monolithic architecture where all major daemons (sslvpnd, httpsd, fgfmd, etc.) are symlinks to a single `init` binary. The binary determines its role based on `argv[0]`.

### vmlinux-to-elf Compatibility

FortiOS 7.6.x uses Linux kernel 3.2.16. Some versions of `vmlinux-to-elf` produce incorrect symbol addresses due to a base address detection issue (the decompressed kernel has a 1MB boot setup prefix that shifts all symbol mappings). fgx does not rely on symbol resolution -- the brute-force binary scan works regardless of symbol correctness.

For best results with external analysis tools, install the known-good version:

```bash
pip install git+https://github.com/marin-m/vmlinux-to-elf.git@fa5c9305ae
```

### Tested Firmware

| Model | Version | Build | Architecture | Status |
|-------|---------|-------|:------------:|:------:|
| FortiGate 60F | FortiOS 7.6.6 | 3652 | aarch64 | Fully supported |
| FortiGate 201E | FortiOS 7.6.6 | 3652 | x86_64 | Fully supported |
| FortiGate 1100E | FortiOS 7.6.6 | 3652 | x86_64 | Fully supported |
| FortiGate 2500E | FortiOS 7.6.6 | 3652 | x86_64 | Fully supported |
| FortiGate 1000D | FortiOS 7.6.6 | 6605 | x86_64 | Fully supported |

### Comparison with Existing Tools

| Tool | Outer Layer | rootfs.gz | FortiOS Version | Architecture |
|------|:-----------:|:---------:|:---------------:|:------------:|
| FortiCrack (Bishop Fox) | Yes | No | All | x86/ARM |
| fortigate-crypto (Optistream) | No | ChaCha20 | 7.4.2-7.4.3 | x86/ARM |
| decrypt-fortigate-rootfs (RandoriSec) | No | AES-CTR | 7.4.7 | x86 only |
| **fgx** | **Yes** | **Modified RC4** | **7.6.x** | **aarch64 + x86_64** |

### Cipher Evolution Across FortiOS Versions

| FortiOS Version | rootfs Cipher | RSA Key Protection | Key Derivation |
|:---------------:|:-------------:|:------------------:|:--------------:|
| 7.0.x | ChaCha20 | N/A (static key) | None |
| 7.4.2-7.4.3 | ChaCha20 | ChaCha20 from seed | SHA-256 rotation |
| 7.4.3-7.4.7 | AES-256-CTR | ChaCha20 from seed | SHA-256 rotation |
| **7.6.x** | **Modified RC4** | **XOR with seed** | **From RSA signature** |

## References

- [Bishop Fox - Breaking Fortinet Firmware Encryption](https://bishopfox.com/blog/breaking-fortinet-firmware-encryption)
- [Bishop Fox - Further Adventures in Fortinet Decryption](https://bishopfox.com/blog/further-adventures-in-fortinet-decryption)
- [RandoriSec - Recent modifications in FortiGate firmware crypto](https://blog.randorisec.fr/fortigate-rootfs-decryption/)
- [GreyNoise - Decrypting FortiOS 7.0.x](https://www.greynoise.io/blog/decrypting-fortinets-fortios-7-0-x)
- [BishopFox/forticrack](https://github.com/BishopFox/forticrack)
- [randorisec/decrypt-fortigate-rootfs](https://github.com/randorisec/decrypt-fortigate-rootfs)
- [noways-io/fortigate-crypto](https://github.com/noways-io/fortigate-crypto)

## Disclaimer

This tool is intended for authorized security research and educational purposes only. Use responsibly and in compliance with applicable laws and regulations.
