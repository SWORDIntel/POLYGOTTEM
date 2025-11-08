# POLYGOTTEM

APT TeamTNT Polyglot Steganography Research and Implementation

## Overview

This repository contains analysis and proof-of-concept implementations of polyglot image steganography techniques used by APT TeamTNT cryptomining campaigns (2020-2024). The research focuses on understanding how malicious payloads can be embedded in valid image files and automatically executed.

## Repository Structure

```
POLYGOTTEM/
├── vx_underground/          # Main C implementation for publication
│   ├── polyglot_embed.c     # Pure C payload embedder (9.3KB)
│   ├── polyglot_extract.c   # Pure C payload extractor (11KB)
│   ├── albanian_virus.sh    # Harmless demo payload (meme)
│   ├── Makefile             # Build system with tests
│   └── README.md            # VX Underground submission docs
│
├── tools/                   # Python PoC toolkit
│   ├── polyglot_embed.py    # Python payload embedder
│   ├── polyglot_extract.py  # Python payload extractor
│   ├── desktop_generator.py # .desktop auto-execution generator
│   ├── exploit_header_generator.py # CVE exploit headers (5 CVEs)
│   └── demo_full_attack.sh  # Interactive demonstration
│
├── docs/                    # Research documentation
│   ├── ANALYSIS_FINDINGS.md # Complete malware analysis with IOCs
│   ├── AUTO_EXECUTION_ANALYSIS.md # Auto-execution mechanisms
│   └── PUBLICATION_READY.md # Publication checklist
│
└── samples/                 # Malware samples (research only)
    ├── binaries/           # Binary analysis samples
    │   ├── aarch64         # XMRig Monero miner (4.2MB)
    │   ├── cryptd          # UPX-packed rootkit (122KB)
    │   └── cryptd_extracted/ # Unpacked rootkit analysis
    └── polyglot_images/    # Hundreds of polyglot meme images
        ├── Payloads2/      # 100+ brainlet memes with embedded payloads
        ├── Payloads3/      # 100+ additional samples
        ├── Payloads4/      # 100+ additional samples
        ├── Payloads5/      # Final batch of samples
        └── payloads_extra/ # Additional extracted samples
```

## Quick Start

### Build VX Underground Package

```bash
cd vx_underground
make              # Build both tools
make demo         # Run Albanian virus demonstration
make test         # Run automated tests
make clean        # Clean build artifacts
```

### Using the Tools

**Embed a payload in an image:**
```bash
./polyglot_embed input.gif payload.sh output.gif 9e0a61200d
```

**Extract a payload from an image:**
```bash
./polyglot_extract infected.gif output.bin 9e0a61200d
chmod +x output.bin
./output.bin
```

## Technical Details

### Polyglot Structure

- **Valid Images:** GIF, JPEG, PNG files remain fully viewable
- **Hidden Payloads:** XOR-encrypted data appended after EOF markers
- **Encryption:** Multi-byte XOR (TeamTNT keys: 9e, d3, a5, 9e0a61200d, 410d200d)
- **Portability:** Pure C, no external dependencies

### Auto-Execution Methods

1. **.desktop File Association** - XDG Desktop Entry exploitation
2. **Image Viewer CVE Exploits** - 5 CVEs implemented (libpng, libjpeg, giflib)
3. **Social Engineering Scripts** - User-initiated extraction
4. **Archive Auto-Extractors** - Self-extracting archives

See `docs/AUTO_EXECUTION_ANALYSIS.md` for complete details.

## Attribution

**APT TeamTNT** - Cloud-focused cryptomining group (2020-2024)
- Targets: AWS, Azure, GCP, Alibaba Cloud
- Techniques: Container escapes, credential theft, polyglot steganography
- Related: APT-41 KEYPLUG malware (similar techniques)

## Research Purpose

This repository is for **security research and education only**. The techniques documented here are based on real-world APT campaigns and are provided to:

- Help defenders understand polyglot steganography attacks
- Enable detection and analysis of similar campaigns
- Advance security research in image-based payload delivery
- Document APT TeamTNT tactics for threat intelligence

The demo payload (Albanian virus meme) is harmless and serves only as a technical demonstration.

## Detection

**YARA Rules:** See `docs/ANALYSIS_FINDINGS.md`
**Suricata Signatures:** Network traffic detection included
**File Analysis:** Use entropy scanning on images (>7.5 entropy after EOF)

## IOCs

- **cryptd MD5:** `fbf6bb336f808d1adf037599a08ba8e0`
- **XMRig Pool:** `randomx.xmrig.com:443`
- **Common XOR Keys:** `9e`, `d3`, `a5`, `9e0a61200d`, `410d200d`

See `docs/ANALYSIS_FINDINGS.md` for complete IOC list.

## Publications

VX Underground submission prepared in `vx_underground/` directory with complete documentation suitable for publication.

## License

Research and educational purposes only. Not for malicious use.

## References

- APT TeamTNT campaigns (2020-2024)
- APT-41 KEYPLUG malware analysis
- TeamTNT cryptomining infrastructure
- VX Underground malware database

---

**POLYGOTTEM** - Polyglot 'em! Understanding polyglot steganography in APT campaigns.
