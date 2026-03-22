# fgx

End-to-end FortiGate firmware decryption and extraction toolkit for FortiOS 7.6.x.

Automates the entire pipeline from encrypted `.out` firmware files to a fully extracted root filesystem with a single command. Developed through reverse engineering of FortiOS 7.6.6 (build 3652) firmware encryption, including the discovery of a previously undocumented modified RC4 stream cipher used in the latest FortiOS versions.

## Features

- Full pipeline automation: encrypted `.out` file to extracted rootfs in one command
- FortiCrack-compatible outer layer decryption (known-plaintext XOR block cipher)
- Automatic kernel (flatkc) crypto material extraction via ELF symbol analysis
- Novel modified RC4 decryption for FortiOS 7.6.x rootfs.gz (first public implementation)
- Support for aarch64 (ARM64) FortiGate appliances
- No GUI required -- fully headless operation

## Requirements

### Python packages

```bash
pip3 install -r requirements.txt
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
| `devicetree.dtb` | Device tree blob |

### Stage 3: Kernel Crypto Material Extraction

The kernel (`flatkc`) is converted to an ELF binary using `vmlinux-to-elf`, which recovers the kallsyms symbol table. fgx then:

1. Locates the `rsa_parse_pub_key` symbol
2. Scans the `.init.text` section for BL (branch-link) instructions targeting this function
3. Traces backwards from the call site to find ADRP+ADD instruction pairs that load the seed address
4. Identifies the seed by detecting the `ADD Xn, X0, #0x20` pattern (RSA key = seed + 32 bytes)
5. Reads the 32-byte seed and 270-byte encrypted RSA public key
6. XOR-decrypts the RSA key: `decrypted[i] = encrypted[i] ^ seed[i % 32]`
7. Parses the BER-encoded RSA public key (modulus + exponent)

### Stage 4: rootfs.gz Decryption

The rootfs.gz encryption in FortiOS 7.6.x uses a novel scheme not previously documented:

1. The RSA public key (extracted in Stage 3) decrypts the PKCS#1 v1.5 signature appended to rootfs.gz (last 256 bytes)
2. The signature payload contains a SHA-256 hash (verified against the encrypted data) and a 32-byte RC4 key
3. The rootfs data is decrypted using a modified RC4 stream cipher

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

This modified PRGA was reverse-engineered from the `sub_73db4c` function in the FortiOS 7.6.6 kernel (`flatkc`), using Capstone disassembler for ARM64 instruction decoding.

## Output Structure

```
fgx_output/
  rootfs/                 Root filesystem (CPIO extracted)
    sbin/init             FortiOS init process (aarch64 ELF)
    bin.tar.xz            FortiOS binaries archive (227 binaries)
    lib/                  Shared libraries (83 .so files)
    node-scripts/         Node.js scripts and native module
    data/                 Configuration data
    var/                  Runtime directories
  datafs.tar.gz           Data filesystem (IPS/AV signatures, certs)
  split_rootfs.tar.xz     Additional binaries (node, smbcd)
  flatkc                  Kernel image (raw)
  rootfs.gz               Encrypted rootfs (original)
  devicetree.dtb          Device tree blob
```

## Technical Notes

### FortiOS Binary Architecture

FortiOS uses a monolithic architecture where all major daemons (sslvpnd, httpsd, fgfmd, etc.) are symlinks to a single `init` binary (75MB, ARM aarch64). The binary determines its role based on `argv[0]`.

### Tested Firmware

| Model | Version | Build | Architecture | Status |
|-------|---------|-------|--------------|--------|
| FortiGate 60F | FortiOS 7.6.6 | 3652 | ARM aarch64 | Fully supported |

### Comparison with Existing Tools

| Tool | Outer Layer | rootfs.gz | Architecture |
|------|:-----------:|:---------:|:------------:|
| FortiCrack (Bishop Fox) | Yes | No | x86/ARM |
| fortigate-crypto (Optistream) | No | ChaCha20 (7.4.x) | x86/ARM |
| decrypt-fortigate-rootfs (RandoriSec) | No | AES-CTR (7.4.7) | x86 only |
| **fgx** | **Yes** | **Modified RC4 (7.6.x)** | **aarch64** |

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
