# Polyglot Format Combinations Matrix
## Which Files Can Be Multiple Formats Simultaneously

## 🎯 **Quick Answer**

**Maximum Formats in One File**: Up to **4-5 formats** simultaneously!

Best example: **ZIP+PDF+HTML+JavaScript** polyglot

---

## 📊 **Format Tolerance Analysis**

### Formats That TOLERATE PREPENDING (can come AFTER another format)

| Format | Max Prepend | Why | Use Case |
|--------|-------------|-----|----------|
| **PDF** | ~1024 bytes | Spec allows whitespace before `%PDF` | ZIP+PDF, GIF+PDF |
| **HTML** | ~1024 bytes | Can have comments/whitespace before `<!DOCTYPE>` | GIF+HTML |
| **GIF** | Limited | Via comment extension | Rare |
| **JPEG** | 0 bytes | Must start with `\xFF\xD8\xFF` | Cannot prepend |
| **PNG** | 0 bytes | Must start with signature | Cannot prepend |

### Formats That TOLERATE APPENDING (can have stuff AFTER)

| Format | Why Append Works | Use Case |
|--------|-----------------|----------|
| **ZIP** | Central directory at END points to data | BASE for polyglots |
| **JPEG** | Data after `\xFF\xD9` (EOI) ignored | JPEG+ZIP |
| **GIF** | Data after `\x3B` trailer ignored | GIF+anything |
| **MP3** | Players ignore trailing data | MP3+ZIP |
| **WAV** | RIFF parsers stop at chunk end | WAV+data |
| **PDF** | Data after `%%EOF` often ignored | PDF+data |
| **PE/ELF** | Overlay data ignored by loader | EXE+data |

---

## ✅ **VERIFIED POLYGLOT COMBINATIONS**

### 2-Way Polyglots (Dual Format)

| Combination | How It Works | Status | Use Case |
|-------------|--------------|--------|----------|
| **ZIP + PDF** | ZIP first, PDF after (PDF tolerates prepend) | ✅ Tested | Bypass filters, dual delivery |
| **GIF + HTML** | HTML in GIF comment extension | ✅ Ready | Web upload → HTML execution |
| **JPEG + ZIP** | JPEG complete, ZIP appended after EOF | ✅ Ready | Image with hidden archive |
| **GIF + ZIP** | GIF complete, ZIP appended after trailer | ✅ Ready | Animated GIF with archive |
| **PDF + JavaScript** | JS in PDF `/JS` object with OpenAction | ✅ Tested | Auto-execute on PDF open |
| **MP3 + ZIP** | MP3 audio, ZIP in ID3 tag or appended | ✅ Ready | Music file with data |
| **WAV + data** | Data in custom RIFF chunk | ✅ Ready | Audio steganography |
| **PE + ZIP** | ZIP appended to .exe overlay | ✅ Ready | Executable with archive |

### 3-Way Polyglots (Triple Format)

| Combination | Structure | Status | Notes |
|-------------|-----------|--------|-------|
| **ZIP + PDF + HTML** | ZIP → PDF (with prepend) → HTML in PDF JS | ✅ Possible | Ultimate bypass |
| **GIF + HTML + JavaScript** | GIF → HTML in comment → JS in HTML | ✅ Possible | Web polyglot |
| **JPEG + ZIP + PDF** | JPEG → ZIP appended → PDF in ZIP | ✅ Possible | Image/archive/doc |
| **GIF + ZIP + PDF** | GIF → ZIP appended → PDF in ZIP | ✅ Possible | Animated polyglot |

### 4-Way Polyglots (Quad Format)

| Combination | Structure | Status | Notes |
|-------------|-----------|--------|-------|
| **ZIP + PDF + HTML + JS** | ZIP → PDF → HTML metadata → JS execution | ⚠️ Complex | Research grade |
| **GIF + HTML + ZIP + PDF** | GIF → HTML comment → ZIP append → PDF in ZIP | ⚠️ Complex | Maximum evasion |

### 5-Way Polyglots (EXTREME)

| Combination | Status | Notes |
|-------------|--------|-------|
| **GIF + HTML + JS + ZIP + PDF** | 🔬 Theoretical | Likely fragile, needs careful construction |

---

## 🔧 **How to Build Common Polyglots**

### Example 1: ZIP+PDF (Most Useful)

```python
# Structure:
# [ZIP archive with file.txt]
# [PDF document starting with %PDF]

# Step 1: Create ZIP
zip_data = create_zip_archive(['file.txt'])

# Step 2: Create PDF
pdf_data = b'%PDF-1.7\n...[PDF content]...%%EOF\n'

# Step 3: Combine
polyglot = zip_data + pdf_data

# Result:
# - Opens as ZIP: extracts file.txt
# - Opens as PDF: displays document
```

**Verified**: ✅ Working

### Example 2: GIF+HTML

```python
# Structure:
# [GIF header]
# [GIF comment extension containing HTML]
# [GIF image data]
# [GIF trailer]

gif = b'GIF89a' + dimensions + color_table
gif += b'\x21\xFE'  # Comment extension
gif += encode_in_chunks(html_code)
gif += image_data + b'\x3B'

# Result:
# - Displays as GIF: shows image
# - Parsed as HTML: executes code
```

**Verified**: ✅ Ready (in polyglot_synthesizer.py)

### Example 3: JPEG+ZIP

```python
# Structure:
# [Complete JPEG image]
# [\xFF\xD9 - JPEG EOI marker]
# [ZIP archive]

jpeg_complete = jpeg_data + b'\xFF\xD9'
polyglot = jpeg_complete + zip_data

# Result:
# - Image viewers: display JPEG, ignore ZIP
# - unzip: extracts ZIP, ignores JPEG
```

**Verified**: ✅ Ready

---

## 📋 **Polyglot Compatibility Matrix**

### Can Format A contain Format B?

|        | ZIP | PDF | GIF | JPEG | HTML | PNG | MP3 | PE |
|--------|-----|-----|-----|------|------|-----|-----|-----|
| **ZIP**    | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **PDF**    | ⚠️ | ❌ | ⚠️ | ⚠️ | ✅ | ⚠️ | ⚠️ | ⚠️ |
| **GIF**    | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| **JPEG**   | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ |
| **HTML**   | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ❌ | ⚠️ | ⚠️ | ⚠️ |
| **PNG**    | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **MP3**    | ✅ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ❌ | ❌ | ❌ |
| **PE**     | ✅ | ✅ | ✅ | ✅ | ⚠️ | ❌ | ✅ | ❌ |

**Legend**:
- ✅ = Easy/Verified (format A can append/embed format B)
- ⚠️ = Possible but complex
- ❌ = Not possible (format constraints)

---

## 🎯 **Practical Polyglot Recipes**

### Recipe 1: "The Ultimate Bypass" (ZIP+PDF+HTML)

**Use Case**: Bypass upload filters, execute on open

```
Structure:
┌─────────────────────────────────────┐
│ ZIP Archive (file.txt)              │ ← Detected as ZIP by `file`
├─────────────────────────────────────┤
│ %PDF-1.7                            │ ← Opens in PDF reader
│ /OpenAction << /S /JavaScript       │
│   /JS (var html='<html>...';        │ ← HTML embedded in JS
│        eval(html);)                 │
│ >>                                  │
│ %%EOF                               │
└─────────────────────────────────────┘

Opens as:
- ZIP: extracts file.txt
- PDF: displays document, executes JavaScript
- JavaScript: contains HTML
```

**Formats**: 3 (ZIP, PDF, HTML embedded)

### Recipe 2: "The Image Archive" (JPEG+ZIP)

**Use Case**: Hide files in photos

```
Structure:
┌─────────────────────────────────────┐
│ \xFF\xD8\xFF JPEG header            │
│ [JPEG image data]                   │
│ \xFF\xD9 (EOI marker)               │ ← JPEG ends here
├─────────────────────────────────────┤
│ PK\x03\x04 ZIP header               │ ← Ignored by image viewers
│ [ZIP archive with payload.exe]      │
│ PK\x05\x06 EOCD                     │
└─────────────────────────────────────┘

Usage:
- Display: Shows normal photo
- Extract: unzip photo.jpg → payload.exe
```

**Formats**: 2 (JPEG, ZIP)

### Recipe 3: "The Animated Polyglot" (GIF+HTML+ZIP)

**Use Case**: Animated GIF that's also HTML and contains archive

```
Structure:
┌─────────────────────────────────────┐
│ GIF89a [dimensions]                 │
│ [Color table]                       │
│ \x21\xFE (Comment extension)        │
│   └─> HTML code in chunks           │ ← HTML in GIF comment
│ [GIF frames]                        │
│ \x3B (Trailer)                      │ ← GIF ends here
├─────────────────────────────────────┤
│ PK\x03\x04 ZIP archive              │ ← Appended, ignored by GIF
└─────────────────────────────────────┘

Opens as:
- GIF: Animated image
- HTML: (need to rename to .html) Executes code
- ZIP: (need to unzip) Extracts files
```

**Formats**: 3 (GIF, HTML, ZIP)

### Recipe 4: "The Executable Archive" (PE+ZIP)

**Use Case**: .exe that also contains hidden files

```
Structure:
┌─────────────────────────────────────┐
│ MZ PE header                        │
│ [PE sections]                       │
│ [Code, data]                        │
│ [End of last section]               │ ← EXE ends here
├─────────────────────────────────────┤
│ PK\x03\x04 ZIP archive              │ ← Overlay data
│ [Hidden files]                      │
└─────────────────────────────────────┘

Usage:
- Execute: Runs as normal .exe
- Extract: unzip program.exe → hidden files
```

**Formats**: 2 (PE, ZIP)

---

## 🔬 **Advanced Polyglot Techniques**

### Technique 1: Nested Polyglots

```
GIF+HTML where HTML contains:
└─> <img src="data:image/jpeg;base64,JPEG+ZIP">
    └─> JPEG that contains ZIP
        └─> ZIP contains PDF
            └─> PDF contains JavaScript
```

**Nesting depth**: 5 levels

### Technique 2: Fractal Polyglots

```
ZIP containing:
├─> file1.pdf (PDF+ZIP polyglot)
│   └─> contains nested.zip
├─> file2.jpg (JPEG+ZIP polyglot)
│   └─> contains more.zip
└─> file3.gif (GIF+HTML polyglot)
    └─> HTML loads external ZIP
```

**Self-similar structure**

### Technique 3: Format Confusion

```
File with extension .pdf but actually:
├─> Starts with PK\x03\x04 (ZIP signature)
├─> Contains %PDF-1.7 at offset 1024
└─> Opens differently in different programs
```

**Context-dependent parsing**

---

## 📊 **Polyglot Complexity Comparison**

| Polyglot Type | Formats | Difficulty | Stability | Use Case |
|---------------|---------|------------|-----------|----------|
| ZIP+PDF | 2 | ⭐ Easy | ✅ Stable | File upload bypass |
| JPEG+ZIP | 2 | ⭐ Easy | ✅ Stable | Image with payload |
| GIF+HTML | 2 | ⭐⭐ Medium | ✅ Stable | Web polyglot |
| ZIP+PDF+HTML | 3 | ⭐⭐⭐ Hard | ⚠️ Fragile | Advanced evasion |
| GIF+HTML+ZIP | 3 | ⭐⭐⭐ Hard | ⚠️ Fragile | Multi-layer |
| ZIP+PDF+HTML+JS | 4 | ⭐⭐⭐⭐ Expert | ❌ Very Fragile | Research only |
| 5+ formats | 5+ | ⭐⭐⭐⭐⭐ Insane | ❌ Extremely Fragile | PoC\|\|GTFO material |

---

## 🛠️ **Building Polyglots with POLYGOTTEM Tools**

### Method 1: Use polyglot_synthesizer.py

```bash
# Generate PDF+ZIP polyglot
python3 polyglot_synthesizer.py --pdf-zip --output dual.pdf

# Generate GIF+HTML polyglot
python3 polyglot_synthesizer.py --gif-html --html page.html --output page.gif
```

### Method 2: Manual Construction

```bash
# Create JPEG+ZIP manually
cat photo.jpg > polyglot.jpg
echo -en '\xFF\xD9' >> polyglot.jpg  # Add EOI marker if missing
cat archive.zip >> polyglot.jpg

# Verify
file polyglot.jpg  # Shows: JPEG image data
unzip -l polyglot.jpg  # Shows: Archive contents
```

### Method 3: Nested with multi_format_embedder.py

```bash
# Step 1: Create JPEG+ZIP
cat photo.jpg payload.zip > image.jpg

# Step 2: Embed in DOCX
python3 multi_format_embedder.py --embed doc.docx image.jpg stego.docx

# Result: DOCX containing (JPEG+ZIP)
# Extract: unzip stego.docx .rels/.hidden_data.bin
#          unzip .hidden_data.bin (which is JPEG+ZIP)
```

---

## 🎯 **Polyglot Detection & Extraction**

### How to Detect Polyglots

```bash
# Check multiple signatures
file suspicious.pdf
unzip -l suspicious.pdf
strings suspicious.pdf | grep -E "(GIF|JPEG|HTML)"

# Examine with hex editor
hexdump -C suspicious.pdf | head -50

# Look for multiple magic bytes
grep -obUaP '\x89PNG|\xFF\xD8\xFF|PK\x03\x04|%PDF' file.bin
```

### How to Extract All Formats

```bash
# Try each format
file polyglot.bin           # Identify primary
unzip polyglot.bin          # Extract ZIP
pdftotext polyglot.bin      # Extract PDF text
convert polyglot.bin out.png # Extract image
strings polyglot.bin > text.txt  # Extract strings
```

---

## 📈 **Real-World Polyglot Examples**

### Example 1: PoC||GTFO Journal

The famous PoC||GTFO journal PDFs are polyglots:
- Valid PDF document
- Valid ZIP archive containing source code
- Sometimes also ISO images
- Sometimes also NES ROMs!

**Formats**: Up to 4-5 simultaneously

### Example 2: GIFAR (GIF+JAR)

Historical attack vector:
- GIF image
- JAR (Java ARchive, which is ZIP-based)
- Uploaded as image, executed as Java

**Formats**: 2 (GIF, ZIP/JAR)

### Example 3: JPG+PDF Exploits

APT campaigns used:
- JPEG image in email
- PDF exploit appended
- Email clients showed image
- PDF readers executed exploit

**Formats**: 2 (JPEG, PDF)

---

## ⚠️ **Security Implications**

### Attack Vectors

1. **Upload Filter Bypass**: Upload as image, extract as executable
2. **Content Type Confusion**: Different apps parse differently
3. **Nested Exploitation**: Outer format hides inner malicious content
4. **Multi-Stage Delivery**: Each format layer enables next stage

### Defense Strategies

1. **Deep Content Inspection**: Check entire file, not just header
2. **Multiple Parser Validation**: Verify with all possible format parsers
3. **Size Anomaly Detection**: 1KB image → 10MB file is suspicious
4. **Entropy Analysis**: Polyglots often have unusual entropy patterns

---

## 🏆 **Maximum Polyglot Challenge**

**Can you create a 6-way polyglot?**

Theoretical structure:
```
GIF (animated)
├─> HTML in comment
│   └─> JavaScript inline
│       └─> References data URI
└─> After GIF trailer:
    └─> ZIP archive
        └─> Contains PDF
            └─> PDF has /OpenAction JavaScript
```

**Formats**: GIF, HTML, JavaScript, ZIP, PDF, JavaScript (6)

**Status**: 🔬 Theoretical - Not yet verified

---

## 📚 **Further Reading**

- **Corkami**: Ange Albertini's file format tricks
- **PoC||GTFO**: Polyglot research papers
- **Matasano**: File format exploitation
- **OWASP**: Polyglot injection techniques

---

## ✅ **Summary Table: All Possible Combinations**

| Primary | Secondary | Tertiary | Verified | Difficulty |
|---------|-----------|----------|----------|------------|
| ZIP | PDF | - | ✅ | Easy |
| ZIP | PDF | HTML | ⚠️ | Medium |
| ZIP | PDF | HTML+JS | ⚠️ | Hard |
| GIF | HTML | - | ✅ | Easy |
| GIF | HTML | ZIP | ⚠️ | Medium |
| GIF | ZIP | PDF | ⚠️ | Medium |
| JPEG | ZIP | - | ✅ | Easy |
| JPEG | ZIP | PDF | ⚠️ | Medium |
| MP3 | ZIP | - | ✅ | Easy |
| PE | ZIP | - | ✅ | Easy |
| WAV | data | - | ✅ | Easy |

**Total Verified**: 7 combinations
**Total Possible**: 20+ combinations
**Maximum Formats**: 5-6 (theoretical)

---

**Last Updated**: 2025-11-08
**Status**: Research-grade polyglot capabilities
**Next**: Verify 3-way and 4-way polyglots
