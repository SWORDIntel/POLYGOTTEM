# IWAR Malware Analyzer - Blue Team Analysis Tool

## Overview

The IWAR Malware Analyzer is a comprehensive defensive security tool for analyzing sophisticated malware, particularly PDF-based threats and binary payloads. It implements all analysis methods described in the IWAR archive reports.

**Classification:** DEFENSIVE SECURITY / BLUE TEAM
**Purpose:** Threat detection, malware analysis, incident response
**Use Cases:** SOC analysis, incident response, threat hunting, research

---

## Capabilities

### 1. PE Executable Detection
- Scans for embedded PE (Windows executables) signatures
- Extracts PE candidates with MZ headers
- Analyzes entropy to detect encryption/obfuscation
- Maps to CVE-2010-1240 (embedded EXE exploitation)

### 2. LSB Steganography Detection
- Extracts embedded images (JPEG, PNG) from files
- Calculates LSB (Least Significant Bit) entropy for each color channel
- Detects hidden data carriers (threshold: >0.45 entropy)
- Maps to OceanLotus/APT32 and IcedID/BokBot TTPs
- Related CVEs: CVE-2009-0927, CVE-2009-0658, CVE-2009-1858

### 3. Entropy Analysis
- Calculates Shannon entropy for entire file
- Detects encryption (entropy >7.5 bits/byte)
- Identifies compressed binary payloads
- Matches AES-128 encryption patterns

### 4. PDF Structure Analysis
- Parses PDF version and object count
- Detects compressed streams (FlateDecode)
- Identifies extreme compression ratios (<10%)
- Finds suspicious PDF keywords (/JavaScript, /AA, /OpenAction, etc.)
- Related CVEs: CVE-2016-4265, CVE-2011-2462, CVE-2009-0658

### 5. Base64 Detection
- Identifies base64-encoded strings
- Common payload obfuscation technique
- Maps to CVE-2018-8414, CVE-2010-0188, CVE-2011-2462

### 6. CVE Correlation
- 25 CVE database from IWAR threat intelligence
- Pattern matching to known exploit techniques
- Confidence scoring for each CVE match
- Covers PDF exploits, image vulnerabilities, multi-stage attacks

### 7. Malware Family Attribution
- 5 malware families: OceanLotus, Epic Turla, IcedID, DarkCloud Stealer, Winos4.0
- TTP (Tactics, Techniques, Procedures) matching
- Confidence scoring based on indicator combinations
- References to threat intelligence sources

### 8. Comprehensive Reporting
- JSON export for automation/SIEM integration
- Console output with severity levels
- IOC (Indicators of Compromise) extraction
- File hashing (MD5, SHA1, SHA256)
- Threat level assessment: CRITICAL, HIGH, MEDIUM, LOW

---

## Usage

### Command Line

```bash
# Basic analysis
./polygottem.py analyze-malware suspicious.pdf

# Verbose output
./polygottem.py analyze-malware suspicious.pdf -v

# Export JSON report
./polygottem.py analyze-malware suspicious.pdf -o report.json

# Skip image analysis (faster)
./polygottem.py analyze-malware suspicious.pdf --no-images
```

### Standalone Module

```python
from tools.iwar_malware_analyzer import IWARMalwareAnalyzer

# Create analyzer
analyzer = IWARMalwareAnalyzer(verbose=True)

# Analyze file
report = analyzer.analyze_file('suspicious.pdf')

# Print report
analyzer.print_report(report)

# Export JSON
analyzer.export_report(report, 'report.json')
```

---

## CVE Database

The IWAR analyzer includes 25 CVEs from the IWAR threat intelligence archive:

### Critical Severity (CVSS 9.0+)
- **CVE-2013-2729** - Adobe Acrobat numeric error (Epic Turla APT)
- **CVE-2011-2462** - U3D component zero-day
- **CVE-2010-2883** - TrueType font buffer overflow
- **CVE-2010-0188** - TIFF image integer overflow
- **CVE-2009-0927** - JPEG memory corruption
- **CVE-2009-0658** - JBIG2 buffer overflow
- **CVE-2009-1858** - JBIG2 filter memory corruption

### High Severity (CVSS 7.0-8.9)
- **CVE-2023-26369** - TTF font RCE (North Korean APT)
- **CVE-2018-8414** - Windows Shell SettingContent-ms RCE
- **CVE-2023-21608** - Adobe Acrobat resetForm RCE
- **CVE-2010-1240** - PDF embedded EXE exploitation

### Attack Vectors Covered
- Embedded PE executables
- JPEG/PNG steganography
- Multi-stage payload delivery
- JavaScript exploitation
- Font-based attacks
- Compression-based obfuscation
- Base64 encoding

---

## Malware Families

### 1. OceanLotus/APT32 (Vietnam)
**Confidence Threshold:** 75%
**TTPs:**
- LSB steganography in PNG/JPEG
- AES128 encrypted payloads
- Multi-stage delivery
- Government/diplomatic targeting

**Matching Indicators:**
- LSB steganography: 100%
- AES encryption: 100%
- Multi-stage: 100%
- High entropy: 95%

### 2. Epic Turla (Russia)
**Confidence Threshold:** 70%
**TTPs:**
- PDF malware delivery
- Multi-stage infection
- Government-level targets
- CVE-2013-2729 exploitation
- 400+ infections in 45+ countries

### 3. IcedID/BokBot
**Confidence Threshold:** 65%
**TTPs:**
- LSB steganography in images
- Banking trojan delivery
- Configuration files via steganography

### 4. DarkCloud Stealer
**Confidence Threshold:** 60%
**TTPs:**
- PDF initial delivery
- Multi-stage encrypted payload
- XOR encryption obfuscation
- Encrypted PE executables

### 5. Winos4.0
**Confidence Threshold:** 55%
**TTPs:**
- PDF malware delivery
- Multi-stage payload deployment
- Encrypted shellcode
- Anti-forensic techniques

---

## Analysis Methods (from IWAR Archive)

All methods are derived from the IWAR archive .md files:

### From IWAR_CVE_CORRELATION_MATRIX.md
- CVE-to-attack-pattern mapping
- 25 CVE correlation table
- Attack chain mapping (4 stages)
- Malware family correlation
- IOC summary

### From IWAR_COMPREHENSIVE_UNCERTAINTY_ANALYSIS.md
- Entropy-based confidence scoring
- Alternative scenario assessment
- Gap identification
- Confidence hierarchy (Tier 1-4)

### From IWAR_CVE_THREAT_INTELLIGENCE_REPORT.md
- Detailed CVE database (severity, attack vectors)
- Malware family TTP matching
- Exploitation status tracking
- YARA rule candidates
- Defensive measures

### From IWAR_SCAN_REPORT.md
- File structure analysis
- PE executable extraction
- LSB steganography detection
- Compression pattern analysis
- Threat assessment levels

---

## Output Example

```
================================================================================
IWAR MALWARE ANALYSIS REPORT
================================================================================

File: suspicious.pdf
Size: 350,915 bytes
Threat Level: CRITICAL
Analysis Date: 2025-11-16T12:34:56

--- FILE HASHES ---
MD5:    d6e4c4f9c8e0b8e8e0c8d6e4f9c8b8e
SHA1:   e0c8d6e4f9c8b8e0c8d6e4f9c8e0c8d6
SHA256: c8d6e4f9c8b8e0c8d6e4f9c8e0c8d6e4f9c8b8e0

--- ENTROPY ANALYSIS ---
File Entropy: 7.9495 bits/byte
Assessment: Encrypted/Compressed

--- THREAT INDICATORS (5) ---

1. High File Entropy
   Severity: HIGH | Confidence: 90%
   Description: Entropy 7.9495 indicates encryption or heavy compression
   Related CVEs: CVE-2010-2883, CVE-2023-26369

2. Embedded PE Executable #1
   Severity: CRITICAL | Confidence: 100%
   Description: PE executable signature detected with high entropy
   Related CVEs: CVE-2010-1240, CVE-2018-8414, CVE-2010-2883

3. LSB Steganography in Image 1
   Severity: CRITICAL | Confidence: 95%
   Description: JPEG image with high LSB entropy (hidden data carrier)
   Related CVEs: CVE-2009-0927, CVE-2009-0658, CVE-2009-1858

--- MALWARE FAMILY ATTRIBUTION (2) ---

OceanLotus/APT32: 95% confidence
  Description: Vietnam-linked APT group
  Matching TTPs:
    - LSB steganography in PNG/JPEG
    - AES128 encrypted payloads
    - Multi-stage delivery

Epic Turla: 85% confidence
  Description: Russia-linked APT group
  Matching TTPs:
    - PDF malware delivery
    - Multi-stage infection
    - Government-level targets

--- SUMMARY ---
Total Indicators: 5
  CRITICAL: 2
  HIGH:     2
  MEDIUM:   1
  LOW:      0
PE Candidates: 2
LSB Images: 2
Base64 Strings: 19

================================================================================
END OF REPORT
================================================================================
```

---

## Integration with SIEM/SOC

### JSON Export Format

```json
{
  "metadata": {
    "file_path": "/path/to/file.pdf",
    "file_size": 350915,
    "analysis_date": "2025-11-16T12:34:56",
    "threat_level": "CRITICAL"
  },
  "file_hashes": {
    "md5": "d6e4c4f9c8e0b8e8e0c8d6e4f9c8b8e",
    "sha1": "e0c8d6e4f9c8b8e0c8d6e4f9c8e0c8d6",
    "sha256": "c8d6e4f9c8b8e0c8d6e4f9c8e0c8d6e4f9c8b8e0"
  },
  "indicators": [
    {
      "name": "High File Entropy",
      "severity": "HIGH",
      "confidence": 90,
      "related_cves": ["CVE-2010-2883"]
    }
  ],
  "malware_attribution": [
    {
      "family": "OceanLotus/APT32",
      "confidence": 95
    }
  ]
}
```

### Exit Codes
- **0** - Low/Medium threat
- **1** - High threat
- **2** - Critical threat

Perfect for automation in incident response pipelines.

---

## Dependencies

### Required
- Python 3.7+
- Standard library (os, sys, struct, math, hashlib, etc.)

### Optional (for image analysis)
- Pillow (PIL) - `pip install Pillow`
- NumPy - `pip install numpy`

If PIL/NumPy not available, image analysis will be skipped.

---

## Performance

- Small files (<1MB): <1 second
- Medium files (1-10MB): 1-5 seconds
- Large files (>10MB): 5-30 seconds

Image analysis adds 2-10 seconds per embedded image.

---

## Use Cases

### 1. SOC Triage
Quick analysis of suspicious email attachments (PDFs, images).

```bash
./polygottem.py analyze-malware email_attachment.pdf -o triage_report.json
```

### 2. Incident Response
Detailed analysis during incident investigation.

```bash
./polygottem.py analyze-malware malware_sample.bin -v -o ir_report.json
```

### 3. Threat Hunting
Batch analysis of files from endpoints.

```bash
for file in /suspicious/*; do
    ./polygottem.py analyze-malware "$file" -o "reports/$(basename $file).json"
done
```

### 4. Malware Research
In-depth analysis for threat intelligence.

```bash
./polygottem.py analyze-malware apt_sample.pdf -v --no-images
```

---

## Limitations

1. **Image Analysis**: Requires PIL/NumPy. Install with `pip install Pillow numpy`
2. **PDF Parsing**: Simplified parsing (not full PDF spec implementation)
3. **Compression Analysis**: Estimates only (requires full decompression for accuracy)
4. **Attribution**: Pattern-based (not definitive without additional intel)

---

## References

### IWAR Archive Sources
- `archive/IWAR_CVE_CORRELATION_MATRIX.md`
- `archive/IWAR_COMPREHENSIVE_UNCERTAINTY_ANALYSIS.md`
- `archive/IWAR_CVE_THREAT_INTELLIGENCE_REPORT.md`
- `archive/IWAR_SCAN_REPORT.md`

### Threat Intelligence
- BlackBerry Cylance OceanLotus Analysis
- Microsoft Threat Intelligence
- Palo Alto Networks Unit42
- Malwarebytes ThreatDown
- NVD (National Vulnerability Database)

---

## License

EDUCATIONAL/RESEARCH USE ONLY - DEFENSIVE SECURITY PURPOSES

This tool is designed for:
- Security Operations Centers (SOCs)
- Incident Response teams
- Threat Intelligence analysts
- Malware researchers
- Red Team/Blue Team exercises

**DO NOT** use for unauthorized analysis of files you don't own or have permission to analyze.

---

## Author

SWORDIntel
Date: 2025-11-16
Version: 1.0.0

---

## Support

For issues or feature requests, please file a GitHub issue in the POLYGOTTEM repository.
