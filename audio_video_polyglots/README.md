# Audio/Video Polyglot Research

**Advanced multimedia polyglot techniques and steganography for security research**

This directory contains implementations of audio and video file polyglots - files that are simultaneously valid in multiple formats or contain hidden embedded data.

## 🎯 Overview

Unlike traditional cross-format polyglots (PDF+ZIP, GIF+HTML), **audio/video polyglots** exploit multimedia format structures to:

1. **Hide archives in audio files** (MP3+ZIP)
2. **Embed executables in audio** (WAV+EXE)
3. **Conceal data in images** (PNG+Audio steganography)

These techniques are used by:
- **Malware** for delivery and evasion
- **APT groups** for data exfiltration
- **Security researchers** for defense development
- **Covert communication** systems

---

## 📁 Directory Structure

```
audio_video_polyglots/
├── mp3_zip/              # MP3+ZIP dual-format generator
├── wav_exe/              # WAV+EXE dual-format generator
├── png_audio/            # PNG+Audio steganography tool
├── tools/                # Analysis and detection tools
├── samples/              # Generated test files
├── Makefile              # Master build system
└── README.md             # This file
```

---

## 🔬 Implemented Techniques

### 1. MP3+ZIP Polyglot

**File**: `mp3_zip/mp3_zip_polyglot.c`

Creates files that are **simultaneously**:
- ✅ Valid MP3 audio (plays in all media players)
- ✅ Valid ZIP archive (extracts with all archive tools)

#### Technique

MP3 decoders scan for frame sync markers (0xFFE/0xFFF) and ignore trailing data after the last audio frame. We append a complete ZIP archive after the MP3 audio frames.

```
┌─────────────────────────┐
│ ID3v2 Tag (optional)    │ ← MP3 metadata
├─────────────────────────┤
│ MP3 Audio Frames        │ ← Players decode & play this
├─────────────────────────┤
│ ZIP Archive (complete)  │ ← Archive tools read from end
│  - Local headers        │
│  - File data            │
│  - Central directory    │
│  - EOCD                 │
└─────────────────────────┘
```

#### Security Implications

- **Filter bypass**: Upload "music file" to platforms with ZIP content restrictions
- **Hidden delivery**: Distribute malicious files disguised as legitimate audio
- **Data exfiltration**: Smuggle sensitive files in audio uploads
- **Detection evasion**: Simple magic byte checks only see MP3

#### Usage

```bash
# Build
cd mp3_zip && make

# Generate polyglot
./mp3_zip_gen --add payload.exe --add data.txt --output song.mp3

# Test as MP3
mpg123 song.mp3
vlc song.mp3

# Test as ZIP
unzip -l song.mp3
unzip song.mp3
```

#### Real-World Examples

- **APT28** (Fancy Bear): Used MP3+RAR polyglots for C2 delivery (2016)
- **Turla**: Audio file polyglots in watering hole attacks (2017)
- **Various ransomware**: Payload delivery via "music" files

---

### 2. WAV+EXE Polyglot

**File**: `wav_exe/wav_exe_polyglot.c`

Creates files that are **simultaneously**:
- ✅ Valid WAV audio (plays in media players)
- ✅ Contains Windows PE executable

#### Technique

WAV files use RIFF chunk structure. We embed a PE executable in a custom RIFF chunk (e.g., "JUNK" chunk) that audio players ignore but can be extracted and executed.

```
┌─────────────────────────┐
│ RIFF Header             │
├─────────────────────────┤
│ fmt  chunk              │ ← Audio format metadata
├─────────────────────────┤
│ data chunk              │ ← Audio samples (plays normally)
├─────────────────────────┤
│ JUNK chunk (custom)     │ ← Contains PE executable (MZ header)
│  - Windows executable   │
│  - Complete PE structure│
└─────────────────────────┘
```

#### Security Implications

- **Critical evasion**: Audio files that contain full executables
- **AV bypass**: Antivirus scans may miss embedded PE in audio container
- **Social engineering**: "Voice message.wav" actually contains malware
- **Sandbox evasion**: Audio files may not be fully analyzed

#### Usage

```bash
# Build
cd wav_exe && make

# Generate polyglot
./wav_exe_gen --exe malware.exe --output voice.wav

# Test as WAV
aplay voice.wav
vlc voice.wav

# Extract executable
dd if=voice.wav of=extracted.exe bs=1 skip=[offset_to_JUNK]
```

#### Detection

Look for:
- MZ header (0x4D5A) inside WAV file
- Unknown or suspicious RIFF chunks
- File size much larger than audio duration suggests

---

### 3. PNG+Audio Steganography

**File**: `png_audio/png_audio_steg.c`

Hides audio data inside PNG images using **ancillary chunks**.

#### Technique

PNG format uses chunk-based structure. Chunks with lowercase first letter are "ancillary" (optional) and safely ignored by image viewers. We create a custom `auDT` (audio data) chunk.

```
┌─────────────────────────┐
│ PNG Signature (8 bytes) │
├─────────────────────────┤
│ IHDR chunk (critical)   │ ← Image dimensions, color type
├─────────────────────────┤
│ IDAT chunk (critical)   │ ← Compressed image data
├─────────────────────────┤
│ auDT chunk (ancillary)  │ ← Hidden audio data (custom)
│  - Full audio file      │   Viewers ignore this!
│  - With CRC checksum    │
├─────────────────────────┤
│ IEND chunk (critical)   │ ← End marker
└─────────────────────────┘
```

#### Security Implications

- **Covert channels**: Communicate via "innocent" image uploads
- **Data exfiltration**: Smuggle sensitive data in images
- **Steganography**: Hide audio messages in plain sight
- **Platform evasion**: Social media, forums display image normally

#### Usage

```bash
# Build
cd png_audio && make

# Embed audio in PNG
./png_audio_steg --png photo.png --audio secret.mp3 --output steg.png

# Display image (shows normally)
firefox steg.png
display steg.png

# Extract hidden audio
./png_audio_steg --extract steg.png --output extracted.mp3
```

#### Detection

Look for:
- Unknown ancillary chunks in PNG
- Chunks with lowercase first letter that aren't standard (tEXt, iTXt, etc.)
- File size larger than expected for image dimensions
- Entropy analysis of chunk data

---

## 🛠 Analysis Tools

### Multimedia Polyglot Analyzer

**File**: `tools/multimedia_analyzer.c`

Detects audio/video polyglots and steganography.

#### Features

- ✅ **Multi-signature detection**: Finds files valid in multiple formats
- ✅ **Anomaly detection**: Identifies suspicious chunks, trailing data
- ✅ **Entropy analysis**: Detects encrypted or compressed hidden data
- ✅ **Detailed reporting**: Shows offsets, risks, and mitigation steps

#### Detects

1. **MP3+ZIP polyglots**
2. **WAV+EXE polyglots**
3. **PNG+Audio steganography**
4. **Other multimedia format anomalies**

#### Usage

```bash
cd tools && make
./multimedia_analyzer suspicious.mp3
./multimedia_analyzer image.png
./multimedia_analyzer *.wav
```

#### Example Output

```
╔══════════════════════════════════════════════════════════════╗
║     Multimedia Polyglot Analyzer v1.0.0                     ║
╚══════════════════════════════════════════════════════════════╝

Analyzing: song.mp3
═══════════════════════════════════════════════════════════════

File size: 524288 bytes

FORMAT DETECTION:
─────────────────────────────────────────────────────────────
✓ MP3 signature found at offset 0
✓ ZIP signature found at offset 196608
  ⚠ WARNING: ZIP not at start → Possible polyglot

🚨 POLYGLOT DETECTED!
═══════════════════════════════════════════════════════════════
This file is valid in MULTIPLE formats:

  🎯 MP3+ZIP POLYGLOT
     - Plays as MP3 audio
     - Contains ZIP archive at offset 196608
     - Technique: MP3 decoders ignore trailing data
     - Risk: HIGH - Hidden file delivery

SECURITY RECOMMENDATIONS:
─────────────────────────────────────────────────────────────
  • QUARANTINE this file immediately
  • DO NOT execute or open in untrusted environments
  • Use strict file validation (not just magic bytes)
  • Scan with updated antivirus/malware tools
```

---

## 🏗 Building

### Requirements

- GCC compiler with C99 support
- Make build system
- Linux/Unix environment (or WSL on Windows)

### Build All Tools

```bash
# Build everything
make all

# Build specific tool
cd mp3_zip && make
cd wav_exe && make
cd png_audio && make
cd tools && make

# Clean build artifacts
make clean
```

### Run Tests

```bash
# Automated test suite
make test

# Interactive demo
make demo
```

---

## 🔒 Security Applications

### Offensive Research

1. **Penetration Testing**
   - Test file upload filters
   - Evaluate content inspection
   - Assess detection capabilities

2. **Red Team Operations**
   - Payload delivery mechanisms
   - Evasion technique development
   - Social engineering scenarios

### Defensive Research

1. **Detection Development**
   - Build polyglot scanners
   - Enhance AV signatures
   - Improve content filtering

2. **Incident Response**
   - Analyze suspected polyglots
   - Extract hidden payloads
   - Forensic investigation

### Training & Education

1. **Security Training**
   - Demonstrate evasion techniques
   - Teach file format internals
   - Explain steganography methods

2. **Malware Analysis**
   - Study real-world samples
   - Reverse engineer techniques
   - Develop countermeasures

---

## ⚠️ Ethical Considerations

### Responsible Use

✅ **Authorized testing** with explicit permission
✅ **Defensive security** research and development
✅ **Educational** purposes in controlled environments
✅ **Malware analysis** for threat intelligence

### Prohibited Use

❌ **Unauthorized** system access or testing
❌ **Malware distribution** or actual attacks
❌ **Data theft** or exfiltration
❌ **Harmful** or illegal activities

---

## 📚 Technical References

### Research Papers

1. **Polyglot Files**
   - Albertini, A. (2014). "Funky File Formats"
   - Gynvael Coldwind (2015). "Polyglot file format tricks"

2. **Audio Steganography**
   - Cvejic, N. & Seppänen, T. (2002). "Audio steganography techniques"
   - Gopalan, K. (2003). "Audio steganography using LSB"

3. **Malware Techniques**
   - FireEye (2016). "APT28 Technical Analysis"
   - Kaspersky (2017). "Turla Watering Hole Attacks"

### File Format Specifications

- **MP3**: ISO/IEC 11172-3 (MPEG-1 Audio Layer III)
- **WAV**: Microsoft RIFF WAVE format specification
- **PNG**: PNG Specification (ISO/IEC 15948:2003)
- **ZIP**: PKWARE ZIP File Format Specification

### Tools & Resources

- **Corkami**: File format posters and documentation
- **PoC||GTFO**: Journal of polyglot research
- **Malware Traffic Analysis**: Real-world samples

---

## 🧪 Testing Matrix

| Test Case | MP3+ZIP | WAV+EXE | PNG+Audio |
|-----------|---------|---------|-----------|
| Format validation | ✅ Pass | ✅ Pass | ✅ Pass |
| Player compatibility | ✅ VLC, mpg123 | ✅ aplay, VLC | ✅ All browsers |
| Archive extraction | ✅ unzip, 7z | ✅ dd, custom | ✅ Custom tool |
| Detection evasion | ⚠️ Moderate | ⚠️ High | ⚠️ High |
| AV detection | 🔴 Low | 🔴 Very Low | 🔴 Very Low |

---

## 🔍 Detection Strategies

### For Defenders

1. **Deep Content Inspection**
   ```bash
   # Scan entire file, not just headers
   binwalk suspicious.mp3
   exiftool -a -G1 -s suspicious.wav
   ```

2. **Signature Scanning**
   ```bash
   # Look for multiple format signatures
   sigfind -t file suspicious.png
   ```

3. **Entropy Analysis**
   ```bash
   # High entropy = possible encryption/compression
   ent suspicious.mp3
   ```

4. **Size Heuristics**
   ```bash
   # File much larger than audio duration suggests?
   ffprobe -show_format suspicious.mp3
   ```

### YARA Rules

```yara
rule MP3_ZIP_Polyglot {
    meta:
        description = "Detects MP3 files with embedded ZIP archives"
        author = "POLYGOTTEM Research"
    strings:
        $mp3_id3 = { 49 44 33 }
        $mp3_frame = { FF FB }
        $zip_sig = { 50 4B 03 04 }
    condition:
        ($mp3_id3 at 0 or $mp3_frame in (0..4096)) and
        $zip_sig in (4096..filesize)
}

rule PNG_Custom_Chunks {
    meta:
        description = "Detects PNG files with suspicious custom chunks"
    strings:
        $png_sig = { 89 50 4E 47 0D 0A 1A 0A }
        $custom = /[a-z]{4}/ // Ancillary chunk (lowercase)
    condition:
        $png_sig at 0 and #custom > 5  // More than 5 custom chunks
}
```

---

## 📊 Comparison with Cross-Format Polyglots

| Feature | Audio/Video | Cross-Format (PDF+ZIP) |
|---------|-------------|----------------------|
| **Stealth** | ⭐⭐⭐⭐⭐ Very High | ⭐⭐⭐⭐ High |
| **AV Detection** | 🔴 Very Low | 🟡 Moderate |
| **Complexity** | ⭐⭐⭐ Moderate | ⭐⭐⭐⭐ High |
| **Real-world Use** | ✅ Active malware | ✅ Active malware |
| **Upload Filters** | ⚠️ Often bypassed | ⚠️ Sometimes caught |

**Key Difference**: Audio/video polyglots exploit **media format tolerance** for trailing/embedded data, while cross-format polyglots exploit **parser differentials** between completely different formats.

---

## 🎓 Learning Path

1. **Start Here**: `mp3_zip/` (simplest technique)
2. **Intermediate**: `png_audio/` (chunk-based steganography)
3. **Advanced**: `wav_exe/` (executable embedding)
4. **Expert**: Combine with cross-format techniques

---

## 📝 License & Attribution

**Research**: POLYGOTTEM Project, 2025
**Techniques**: Based on public research and malware analysis
**Purpose**: Educational and defensive security research only

**Use responsibly. Always obtain authorization before testing.**

---

## 🤝 Contributing

To extend this research:

1. **Add new formats**: MP4+ZIP, OGG+RAR, etc.
2. **Improve detection**: Better entropy analysis, ML-based detection
3. **Real-world samples**: Analyze APT malware samples
4. **Automation**: Batch processing, CI/CD integration

---

## 📧 Contact

For responsible disclosure of vulnerabilities or research collaboration:

**Project**: POLYGOTTEM
**Focus**: Polyglot file format security research
**Status**: Active development (2025)

---

*"The best defense is understanding the offense."*
