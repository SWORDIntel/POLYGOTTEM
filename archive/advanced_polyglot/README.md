# Advanced Polyglot Tool v2.0

**Best-of-Both Implementation**

Combines the strongest features from VX Underground and Polyglot Research implementations into a unified, professional-grade tool.

---

## What Makes This "Best of Both"?

This implementation synthesizes the best features from two different approaches:

### From VX Underground (vx_underground/)
✅ **XOR Encryption** - Multi-byte XOR with APT TeamTNT keys
✅ **Post-EOF Steganography** - Hides payloads after image EOF markers
✅ **Payload Type Detection** - Identifies ELF, PE, Shell, ZIP, etc.
✅ **Real Image Preservation** - Works with existing images
✅ **Extract Capability** - Bidirectional embed/extract operations

### From Polyglot Research (polyglot_research/)
✅ **Professional CLI** - getopt argument parsing with long options
✅ **Verbose Mode** - Detailed progress and debugging output
✅ **Statistics & Analysis** - Entropy calculation, overhead metrics
✅ **Educational Focus** - Clear warnings and documentation
✅ **Multiple Modes** - Unified tool for all operations

### Unique Advanced Features
✅ **Analyze Mode** - Forensic analysis of suspicious images
✅ **Entropy Detection** - Identifies encrypted/compressed data
✅ **Unified Interface** - Single tool for embed, extract, analyze
✅ **Enhanced Error Handling** - Comprehensive validation
✅ **Security Warnings** - Educational use only notices

---

## Features

### 1. Steganography Mode

Hide encrypted payloads in existing images (APT TeamTNT technique).

**Capabilities:**
- Embeds payloads after image EOF markers
- XOR encryption with configurable keys
- Preserves original image (still displays normally)
- Supports GIF, JPEG, PNG formats
- Detects format automatically

**Example:**
```bash
./polyglot_advanced --mode stego \
    --embed meme.gif \
    --payload malware.sh \
    --output infected.gif \
    --key 9e0a61200d \
    --verbose
```

### 2. Extract Mode

Extract and decrypt hidden payloads from images.

**Capabilities:**
- Automatic format detection
- XOR decryption with key
- Payload type identification
- Entropy analysis
- Supports all embedding formats

**Example:**
```bash
./polyglot_advanced --mode extract \
    --input infected.gif \
    --output payload.bin \
    --key 9e0a61200d
```

### 3. Analyze Mode

Forensic analysis of suspicious images.

**Capabilities:**
- Detects extra data after EOF
- Calculates entropy (encryption indicator)
- Identifies payload types
- Shebang detection
- Security assessment

**Example:**
```bash
./polyglot_advanced --mode analyze \
    --input suspicious.gif \
    --verbose
```

**Sample Output:**
```
═══════════════════════════════════════════
FILE ANALYSIS: suspicious.gif
═══════════════════════════════════════════

✓ Image Format: GIF
  File size: 35284 bytes
  EOF marker at: 0x1a3c (6716 bytes)

⚠ ALERT: 28568 bytes found after EOF marker!
  Entropy: 7.89 bits/byte ⚠ HIGH (likely encrypted/compressed)
  Payload type: Unknown/Encrypted
  ⚠ SHEBANG DETECTED: Executable script!

═══════════════════════════════════════════
```

---

## Installation

### Build from Source

```bash
cd advanced_polyglot
make
```

**Requirements:**
- GCC compiler
- Standard C library
- Math library (libm)

**Output:**
- `polyglot_advanced` - Main executable

---

## Usage

### Quick Start

```bash
# Build
make

# Run tests
make test

# Run interactive demo
make demo

# Show help
./polyglot_advanced --help
```

### Command-Line Interface

```
./polyglot_advanced --mode <MODE> [OPTIONS]
```

**Modes:**
- `stego` - Steganography (encrypted post-EOF embedding)
- `extract` - Extract and decrypt payloads
- `analyze` - Analyze suspicious images
- `polyglot` - True polyglot generation (future)

### Steganography Mode

**Required:**
- `--embed FILE` - Source image
- `--payload FILE` - Payload to hide
- `--output FILE` - Output filename

**Optional:**
- `--key HEX` - XOR key (default: 9e0a61200d)
- `-v, --verbose` - Verbose output

**Example:**
```bash
./polyglot_advanced --mode stego \
    --embed photo.jpg \
    --payload script.sh \
    --output stego.jpg \
    --key d3
```

### Extract Mode

**Required:**
- `--input FILE` - Steganographic image
- `--output FILE` - Output filename

**Optional:**
- `--key HEX` - XOR key for decryption

**Example:**
```bash
./polyglot_advanced --mode extract \
    --input stego.jpg \
    --output script.sh \
    --key d3

chmod +x script.sh
./script.sh
```

### Analyze Mode

**Required:**
- `--input FILE` - Image to analyze

**Optional:**
- `-v, --verbose` - Detailed analysis

**Example:**
```bash
./polyglot_advanced --mode analyze --input image.gif -v
```

---

## Technical Details

### XOR Encryption

Multi-byte XOR cipher with repeating key:

```c
for (size_t i = 0; i < data_len; i++) {
    data[i] ^= key[i % key_len];
}
```

**Common APT TeamTNT Keys:**
- `9e` - Single-byte (simple)
- `d3` - Single-byte (alternative)
- `9e0a61200d` - Multi-byte (TeamTNT default)
- `410d200d` - Multi-byte (KEYPLUG variant)

### Entropy Analysis

Shannon entropy calculation (0.0 to 8.0 bits/byte):

```
H(X) = -Σ p(x) * log2(p(x))
```

**Interpretation:**
- **< 5.0** - Low entropy (plaintext, padding)
- **5.0 - 7.5** - Medium entropy (possibly obfuscated)
- **> 7.5** - High entropy (likely encrypted/compressed)

### Format Support

| Format | EOF Marker | Marker Bytes |
|--------|-----------|--------------|
| GIF | Trailer | `0x3B` |
| JPEG | EOI | `0xFF 0xD9` |
| PNG | IEND Chunk | `49 45 4E 44 AE 42 60 82` |

### Payload Detection

Automatic identification of:
- **ELF binaries** - `\x7FELF`
- **PE binaries** - `MZ`
- **Shell scripts** - `#!/bin/sh`
- **ZIP archives** - `PK\x03\x04`
- **Gzip** - `\x1F\x8B`
- **Bzip2** - `BZh`

---

## Comparison with Other Implementations

| Feature | VX Underground | Polyglot Research | **Advanced (This)** |
|---------|----------------|-------------------|---------------------|
| XOR Encryption | ✅ | ❌ | ✅ |
| Extract Tool | ✅ | ❌ | ✅ |
| Analyze Mode | ❌ | ❌ | ✅ |
| Entropy Detection | ❌ | ❌ | ✅ |
| Professional CLI | ❌ | ✅ | ✅ |
| Verbose Mode | ❌ | ✅ | ✅ |
| Payload Detection | ✅ | ❌ | ✅ |
| Statistics | ⚠️ Basic | ✅ | ✅ |
| Unified Tool | ❌ | ✅ | ✅ |
| **Lines of Code** | 710 | 598 | **~650** |

See `docs/IMPLEMENTATION_COMPARISON.md` for detailed analysis.

---

## Testing

### Automated Tests

```bash
make test
```

**Test Suite:**
1. Steganography embed with encryption
2. Analyze embedded file
3. Extract and decrypt payload
4. Verify extracted payload execution

### Interactive Demo

```bash
make demo
```

**Demonstrates:**
- Full embed → analyze → extract cycle
- Entropy detection
- Payload identification
- Successful execution

---

## Use Cases

### Security Research
- ✅ Test file upload filters
- ✅ Train security analysts
- ✅ Develop detection signatures
- ✅ Understand APT techniques

### Red Team Operations
- ✅ Bypass content filters (authorized testing)
- ✅ Demonstrate attack vectors
- ✅ Assess security controls
- ✅ Educational demonstrations

### Blue Team Defense
- ✅ Detect steganographic payloads
- ✅ Analyze suspicious images
- ✅ Develop YARA rules
- ✅ Improve security posture

### Malware Analysis
- ✅ Extract payloads from samples
- ✅ Analyze APT TeamTNT campaigns
- ✅ Understand evasion techniques
- ✅ Document IOCs

---

## Detection Methods

### For Security Teams

**Entropy-based Detection:**
```bash
# Scan for high-entropy data after EOF
./polyglot_advanced --mode analyze --input image.gif
```

**File Integrity:**
```bash
# Check for extra data
ls -l image.gif
# Compare with image viewer reported size
identify -verbose image.gif | grep "Filesize"
```

**YARA Rules:**
See `docs/ANALYSIS_FINDINGS.md` for complete YARA signatures.

**Suricata Signatures:**
Alert on images with high post-EOF entropy.

---

## Defense Recommendations

1. **Strict Image Validation**
   - Reject files with data after EOF markers
   - Use IMAGEHARDER's hardened decoders
   - Validate entire file structure

2. **Entropy Scanning**
   - Flag images with entropy > 7.5 after EOF
   - Automated scanning in upload pipelines
   - Quarantine suspicious files

3. **Metadata Analysis**
   - Scan GIF comments for shebangs
   - Check PNG tEXt chunks for code
   - Inspect JPEG COM markers

4. **Behavioral Monitoring**
   - Alert on executable permissions for images
   - Monitor for image files being executed
   - Track anomalous file access patterns

---

## Attribution

**APT TeamTNT**
- Cloud-focused cryptomining group (2020-2024)
- Uses polyglot steganography for payload delivery
- Targets: AWS, Azure, GCP, Kubernetes

**APT-41 KEYPLUG**
- Similar XOR-encrypted steganography
- Multi-stage malware deployment
- Advanced evasion techniques

---

## Responsible Use

### ✅ Authorized Uses
- Security research and education
- Authorized penetration testing
- Defensive security development
- Malware analysis and forensics
- CTF competitions and training

### ❌ Prohibited Uses
- Malicious attacks on systems
- Unauthorized access attempts
- Distribution of malware
- Illegal activities
- Evasion of law enforcement

**LEGAL NOTICE:** This tool is provided for educational and authorized security research only. Users are solely responsible for compliance with all applicable laws.

---

## Future Enhancements

Planned features for v3.0:

- [ ] Full true polyglot generation (integrate polyglot_research)
- [ ] Multi-layer encryption (XOR + AES)
- [ ] LSB steganography mode
- [ ] Batch processing of images
- [ ] Plugin system for custom formats
- [ ] GUI frontend
- [ ] Integration with threat intelligence feeds
- [ ] Automated IOC extraction

---

## License

MIT License - Educational Use Only

See repository root for full license text.

---

## References

- VX Underground Malware Database
- APT TeamTNT Campaign Analysis (Trend Micro, Palo Alto)
- IMAGEHARDER Security Research Project
- OWASP File Upload Guidelines

---

## Contact

**Security Research:** security@polygottem.io
**GitHub Issues:** https://github.com/SWORDIntel/POLYGOTTEM
**Documentation:** docs/IMPLEMENTATION_COMPARISON.md

---

**Version:** 2.0.0
**Release Date:** 2025-11-08
**Status:** Production Ready
