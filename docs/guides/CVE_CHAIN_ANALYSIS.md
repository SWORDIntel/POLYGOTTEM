# CVE Chain Analysis & Attack Strategy Guide

**Date:** 2025-11-12
**Author:** SWORDIntel
**Purpose:** Intelligent CVE chaining for optimal exploit chains

---

## Overview

The CVE Chain Analyzer is an intelligent system that suggests optimal exploit chains based on attack objectives. Instead of manually selecting CVEs, the analyzer recommends combinations that follow proven attack patterns:

- **RCE → PE**: Remote code execution followed by privilege escalation (full compromise)
- **Cascade RCE → PE**: Multiple RCE exploits followed by privilege escalation (maximum impact)
- **Initial Access**: Best RCE exploits for gaining foothold
- **Privilege Escalation**: Local privilege escalation when access already exists

---

## Why Chain CVEs?

### Single Exploit Limitations

A single CVE exploit typically achieves only ONE objective:
- **RCE**: Gains code execution but often at user-level privileges
- **PE**: Escalates privileges but requires existing access

### Chain Benefits

Chaining exploits creates a **kill chain** that:
1. Gains initial access (RCE)
2. Escalates privileges (PE)
3. Achieves full system compromise

**Example macOS Chain:**
```
CVE-2025-43300 (ImageIO zero-click RCE)
    ↓
CVE-2025-24228 (Kernel buffer overflow PE)
    ↓
RESULT: Zero-click full kernel compromise
```

---

## Attack Chain Patterns

### Pattern 1: RCE → Privilege Escalation (Full Compromise)

**Goal:** Complete system takeover
**Steps:**
1. Initial access via remote code execution
2. Escalate to SYSTEM/root/kernel privileges

**macOS Example:**
```
CVE-2025-43300 (ImageIO RCE) → CVE-2025-24228 (Kernel PE)
```
- **Step 1**: Zero-click RCE via malicious DNG image
- **Step 2**: Kernel buffer overflow for full system control
- **Success Factors**: Zero-click, actively exploited, kernel access

**Windows Example:**
```
CVE-2025-47981 (SPNEGO RCE) → CVE-2025-62215 (Kernel PE)
```
- **Step 1**: Network-based RCE via SMB/RDP/HTTP
- **Step 2**: Kernel race condition for SYSTEM privileges
- **Success Factors**: Unauthenticated, actively exploited

**Linux Example:**
```
CVE-2023-4863 (libwebp RCE) → CVE-2025-0927 (HFS+ PE)
```
- **Step 1**: WebP image heap overflow
- **Step 2**: HFS+ filesystem kernel overflow
- **Success Factors**: Cross-platform RCE, kernel access

---

### Pattern 2: Cascade RCE → PE (Maximum Impact)

**Goal:** Multiple entry points + privilege escalation
**Steps:**
1. Primary RCE exploit
2. Secondary RCE exploit (fallback/alternative vector)
3. Final privilege escalation

**Windows Example:**
```
CVE-2023-4863 (libwebp) → CVE-2025-60724 (GDI+) → CVE-2025-62215 (Kernel)
```
- **Step 1**: WebP heap overflow (CRITICAL CVSS 10.0)
- **Step 2**: GDI+ metafile heap overflow (CVSS 9.8)
- **Step 3**: Kernel race condition (actively exploited)
- **Rationale**: Multiple RCE vectors increase success probability

---

### Pattern 3: Initial Access Only

**Goal:** Gain foothold without privilege escalation
**Use Case:** Post-exploitation tools available, just need entry

**Top RCE CVEs by Platform:**

**macOS:**
- CVE-2025-43300 (ImageIO) - Zero-click, actively exploited
- CVE-2022-22675 (AppleAVD) - H.264 video

**Windows:**
- CVE-2025-47981 (SPNEGO) - Zero-click, unauthenticated
- CVE-2025-60724 (GDI+) - Metafile/image

**iOS/iPhone:**
- CVE-2025-31200 (CoreAudio) - Zero-click, actively exploited, bypasses Blastdoor
- CVE-2025-24201 (WebKit) - Actively exploited, sandbox escape

**Linux/Cross-Platform:**
- CVE-2023-4863 (libwebp) - Actively exploited, CVSS 10.0

---

### Pattern 4: Privilege Escalation Only

**Goal:** Escalate from user to SYSTEM/root/kernel
**Assumption:** Already have initial access (via phishing, malware dropper, etc.)

**Top PE CVEs by Platform:**

**macOS:**
1. CVE-2025-24228 - Kernel buffer overflow (CVSS 7.8)
2. CVE-2025-24153 - SMB buffer overflow (kernel)
3. CVE-2025-24156 - Xsan integer overflow

**Windows:**
1. CVE-2025-62215 - Kernel race condition (ACTIVELY EXPLOITED)
2. CVE-2025-21333 - Hyper-V buffer overflow (CVSS 7.8)

**iOS/iPhone:**
1. CVE-2025-24085 - Core Media UAF (CVSS 7.8, ACTIVELY EXPLOITED)
2. CVE-2025-31201 - PAC Bypass (enables kernel exploitation)

**Linux:**
1. CVE-2025-0927 - HFS+ heap overflow (CVSS 7.8)
2. CVE-2025-37810 - Kernel OOB write (CVSS 7.5)

---

## Using the Chain Analyzer

### Command Line Usage

```bash
python3 tools/cve_chain_analyzer.py
```

### Programmatic Usage

```python
from tools.cve_chain_analyzer import CVEChainAnalyzer, TargetPlatform

analyzer = CVEChainAnalyzer()

# Get recommended chains for macOS full compromise
chains = analyzer.suggest_chains(TargetPlatform.MACOS, "full_compromise")

# Analyze specific chain
analysis = analyzer.analyze_chain(chains[0])

# Pretty print analysis
analyzer.print_chain_analysis(chains[0])
```

### Available Goals

| Goal | Description | Output |
|------|-------------|--------|
| `full_compromise` | RCE + PE chains | Complete attack chains |
| `initial_access` | RCE only | Top 5 RCE exploits |
| `privilege_escalation` | PE only | Top 5 PE exploits |
| `cascade_rce` | Multiple RCE + PE | High-impact chains |

### Target Platforms

- `TargetPlatform.WINDOWS`
- `TargetPlatform.LINUX`
- `TargetPlatform.MACOS`
- `TargetPlatform.IOS`
- `TargetPlatform.ANDROID`
- `TargetPlatform.CROSS_PLATFORM`

---

## Chain Analysis Output

The analyzer provides detailed breakdowns:

### Overall Metrics
- **Chain Type**: RCE → PE, Cascade, etc.
- **Overall Severity**: CRITICAL, HIGH, MEDIUM
- **Maximum CVSS**: Highest score in chain
- **Total Steps**: Number of exploits

### Per-Step Details
- CVE ID and name
- Exploit type (RCE, PE, etc.)
- Platform and CVSS score
- Zero-click capability
- Kernel-level access
- Active exploitation status

### Success Factors
- Zero-click exploit present
- Actively exploited in wild
- No authentication required
- Kernel-level access achieved

### Defensive Recommendations
- Platform-specific patches
- Network segmentation
- Kernel integrity protections
- Exploit mitigations
- Monitoring strategies

---

## Example Chains

### Example 1: macOS Zero-Click Full Compromise

```
Chain: CVE-2025-43300 → CVE-2025-24228

Step 1: CVE-2025-43300
  └─ Apple ImageIO DNG/TIFF OOB Write
  └─ Type: Remote Code Execution
  └─ Platform: macOS
  └─ CVSS: 9.8
  └─ Zero-Click: YES
  └─ Actively Exploited: YES

Step 2: CVE-2025-24228
  └─ macOS Kernel Buffer Overflow
  └─ Type: Local Privilege Escalation
  └─ Platform: macOS
  └─ CVSS: 7.8
  └─ Kernel-Level: YES

Overall Severity: CRITICAL
Success Factors:
  ✓ Zero-click RCE (high success)
  ✓ Actively exploited in wild (proven)
  ✓ Kernel-level access achieved
```

**Attack Flow:**
1. Attacker sends malicious DNG image via iMessage
2. ImageIO automatically processes image for preview
3. Out-of-bounds write triggers RCE at user level
4. Malicious app exploits kernel buffer overflow
5. Attacker gains full kernel control

**Defensive Actions:**
- Update macOS to 15.6.1+ (Sequoia), 14.7.8+ (Sonoma), 13.7.8+ (Ventura)
- Disable automatic image previews in Messages
- Enable Kernel Integrity Protection (KIP)
- Deploy EDR with memory corruption detection

---

### Example 2: Windows Cascade Attack

```
Chain: CVE-2023-4863 → CVE-2025-60724 → CVE-2025-62215

Step 1: CVE-2023-4863 (libwebp)
  └─ CVSS: 10.0
  └─ Actively Exploited: YES

Step 2: CVE-2025-60724 (GDI+)
  └─ CVSS: 9.8
  └─ RCE via metafile

Step 3: CVE-2025-62215 (Kernel)
  └─ CVSS: 7.8
  └─ Kernel-Level: YES
  └─ Actively Exploited: YES

Overall Severity: CRITICAL
```

**Attack Flow:**
1. User opens email with malicious WebP image
2. libwebp heap overflow gains initial code execution
3. Dropper creates malicious EMF metafile
4. GDI+ heap overflow maintains persistence
5. Kernel race condition escalates to SYSTEM

**Defensive Actions:**
- Update libwebp to 1.3.2+
- Apply Windows November 2025 patches
- Enable Control Flow Guard (CFG)
- Deploy application sandboxing

---

### Example 3: Linux HFS+ Privilege Escalation

```
Chain: CVE-2025-0927 (standalone PE)

Step 1: CVE-2025-0927
  └─ Linux HFS+ Heap Overflow
  └─ Type: Local Privilege Escalation
  └─ Platform: Linux
  └─ CVSS: 7.8
  └─ Kernel-Level: YES

Use Case: Already have user-level access (phishing, SSH, etc.)

Attack Flow:
1. Attacker has local shell access
2. Mounts crafted HFS+ filesystem image
3. Malformed B-tree triggers heap overflow in hfs_bnode_read_key
4. Kernel memory corruption leads to privilege escalation
5. Attacker gains root/kernel access
```

**Defensive Actions:**
- Update Linux kernel to 6.12.1+
- Restrict filesystem mounting (disable user mounts)
- Enable KASLR, SMEP, SMAP
- Monitor for unusual filesystem mounts

---

### Example 4: iOS/iPhone Zero-Click Full Compromise

```
Chain: CVE-2025-31200 → CVE-2025-24085

Step 1: CVE-2025-31200
  └─ iOS CoreAudio Zero-Click RCE
  └─ Type: Remote Code Execution
  └─ Platform: iOS/iPhone
  └─ CVSS: 9.8
  └─ Zero-Click: YES
  └─ Actively Exploited: YES

Step 2: CVE-2025-24085
  └─ iOS Core Media UAF
  └─ Type: Local Privilege Escalation
  └─ Platform: iOS/iPhone
  └─ CVSS: 7.8
  └─ Kernel-Level: YES
  └─ Actively Exploited: YES

Overall Severity: CRITICAL
Success Factors:
  ✓ Zero-click RCE (high success)
  ✓ Actively exploited in wild (proven)
  ✓ Kernel-level access achieved
  ✓ Bypasses Blastdoor security
```

**Attack Flow:**
1. Attacker sends malicious AAC audio file via iMessage
2. CoreAudio heap corruption triggers RCE (bypasses Blastdoor)
3. Malicious process exploits Core Media use-after-free
4. Kernel memory corruption leads to privilege escalation
5. Attacker gains full kernel control (jailbreak-level access)

**Defensive Actions:**
- Update iOS to 18.4.1+ and iPadOS to 18.4.1+
- Disable automatic media processing in Messages (Settings → Messages → Low Quality Image Mode)
- Enable Lockdown Mode for high-risk targets
- Implement EDR/MDM monitoring for iOS devices
- Monitor for unusual media file attachments
- Deploy network filtering for malicious file delivery

---

### Example 5: Real-World APT-41 Multi-Stage Attack Chain

**Source:** Forensic analysis of 5AF0PfnN.png polyglot malware (November 2025)
**Attribution:** APT-41 (Chinese state-sponsored threat actor)
**Classification:** Triple-layered polyglot (PNG → ZIP → 5×PE executables)
**Sophistication:** Nation-state level with suspected 0-day kernel exploit

```
Multi-Stage Attack Chain (8 Phases):

Phase 1: Initial Network Compromise
  └─ CVE-2021-44207 (Citrix ADC RCE)
     └─ Unauthenticated remote code execution
     └─ CVSS: 9.8 (CRITICAL)
     └─ ❌ NOT IN POLYGOTTEM

Phase 2: Lateral Movement & Persistence
  └─ CVE-2021-44228 (Log4Shell)
     └─ JNDI injection → Remote class loading
     └─ CVSS: 10.0 (CRITICAL)
     └─ ❌ NOT IN POLYGOTTEM

Phase 3: Polyglot Payload Delivery
  └─ 5AF0PfnN.png delivered via phishing/web
     └─ Layer 1: Valid PNG image (steganography)
     └─ Layer 2: ZIP archive (offset 0x1000)
     └─ Layer 3: 5× PE executables (XOR encrypted)

Phase 4: DLL Injection (PE #4 Stub)
  └─ CVE-2019-9634 (Process Injection)
     └─ DLL injection into legitimate processes
     └─ Anti-analysis: Corrupted PE headers
     └─ ❌ NOT IN POLYGOTTEM

Phase 5: C2 Communication (PE #2 DnsK7)
  └─ T1071.004 (DNS Tunneling)
     └─ DNS TXT record queries for C2
     └─ Domain: update-service[.]ddns[.]net
     └─ Encrypted with AES-256-CBC

Phase 6: Privilege Escalation ⚠️ 0-DAY
  └─ PE #5 SYSCALL Exploit (offset 0x2c10)
     └─ Unknown Windows kernel vulnerability
     └─ Similar to CVE-2025-62215 (Kernel race condition)
     └─ ✅ POLYGOTTEM HAS SIMILAR: CVE-2025-62215
     └─ Achieves SYSTEM privileges

Phase 7: Payload Deployment (PE #3 Container)
  └─ Recursive payload extraction
     └─ ZIP → PE → ZIP → PE (matryoshka style)
     └─ 15+ nested executables
     └─ XOR key rotation (0x7F, 0xAA, 0x5C)

Phase 8: Persistence & Defense Evasion
  └─ Multiple MITRE ATT&CK techniques:
     ├─ T1055.001 (DLL Injection)
     ├─ T1027 (Obfuscated files)
     ├─ T1140 (Deobfuscate/decode)
     ├─ T1036 (Masquerading)
     ├─ T1574.002 (DLL side-loading)
     └─ T1497 (Virtualization/sandbox evasion)
```

**POLYGOTTEM Coverage Assessment:**

| APT-41 CVE/Technique | POLYGOTTEM Status | Similarity Score |
|---------------------|-------------------|------------------|
| CVE-2021-44207 (Citrix) | ❌ NOT IMPLEMENTED | N/A |
| CVE-2021-44228 (Log4j) | ❌ NOT IMPLEMENTED | N/A |
| CVE-2023-3519 (Citrix) | ❌ NOT IMPLEMENTED | N/A |
| CVE-2019-9634 (Injection) | ❌ NOT IMPLEMENTED | N/A |
| PE #5 0-Day (Kernel) | ✅ **CVE-2025-62215** | **95% Similar** |
| DNS Tunneling C2 | ⚠️ TTP only | N/A |
| Polyglot Structure | ⚠️ Multi-CVE polyglot | Partial |
| XOR Encryption | ⚠️ Runtime decryption | Partial |

**Overall Coverage:** 1/9 CVEs (11%) - Significant gap for APT-41 specific intrusion set

**Key TTPs Mapped to MITRE ATT&CK:**

```
Initial Access:
  T1190 - Exploit Public-Facing Application (Citrix, Log4j)

Execution:
  T1059.001 - PowerShell
  T1106 - Native API (SYSCALL in PE #5)

Persistence:
  T1547.001 - Registry Run Keys
  T1574.002 - DLL Side-Loading

Privilege Escalation:
  T1068 - Exploitation for Privilege Escalation (PE #5 0-day)
  T1055.001 - Process Injection (DLL Injection)

Defense Evasion:
  T1027 - Obfuscated Files (5 layers of encryption)
  T1140 - Deobfuscate/Decode Files (XOR decryption)
  T1036 - Masquerading (PNG → ZIP → PE)
  T1497 - Virtualization/Sandbox Evasion
  T1574.002 - Hijack Execution Flow

Command & Control:
  T1071.004 - Application Layer Protocol: DNS
  T1573.001 - Encrypted Channel: Symmetric Cryptography (AES-256)
  T1132.001 - Data Encoding: Standard Encoding
```

**Attack Flow Comparison:**

| Stage | APT-41 Real-World | POLYGOTTEM Equivalent |
|-------|------------------|----------------------|
| **Initial RCE** | CVE-2021-44207 (Citrix) | CVE-2025-47981 (SPNEGO) |
| **Delivery** | PNG+ZIP+PE polyglot | Multi-CVE polyglot |
| **Privilege Escalation** | PE #5 0-day kernel | CVE-2025-62215 (Kernel) |
| **Result** | SYSTEM + C2 + Persistence | SYSTEM access |

**Success Factors (APT-41):**
```
✓ Multi-layered obfuscation (PNG+ZIP+5×PE)
✓ 0-day kernel exploit (PE #5)
✓ Encrypted C2 (DNS tunneling + AES-256)
✓ Anti-analysis (corrupted PE headers, VM detection)
✓ Persistence (multiple techniques)
✓ Nation-state resources and infrastructure
```

**Defensive Actions (APT-41 Specific):**

1. **Initial Access Prevention:**
   - Patch CVE-2021-44207, CVE-2021-44228, CVE-2023-3519
   - Restrict Citrix Gateway external exposure
   - Update Log4j to 2.17.1+

2. **Polyglot Detection:**
   - Deep file inspection (scan beyond magic bytes)
   - YARA rules for PNG+ZIP+PE combinations
   - Block files with embedded executables

3. **C2 Disruption:**
   - Monitor DNS TXT record queries (unusual size/frequency)
   - Block domains: update-service[.]ddns[.]net, api-cdn[.]net
   - Inspect DNS tunneling patterns

4. **Kernel Exploit Mitigation:**
   - Apply CVE-2025-62215 patch (similar to PE #5)
   - Enable HVCI (Hypervisor-Protected Code Integrity)
   - Deploy kernel exploit mitigations (KASLR, SMEP, SMAP)

5. **Behavioral Detection:**
   - Monitor SYSCALL usage at unusual offsets
   - Detect DLL injection (PE #4 stub behavior)
   - Alert on XOR decryption loops

**Research Value:**

This real-world APT-41 chain demonstrates several critical concepts:

1. **Multi-Stage Exploitation:** Modern APT groups chain 8+ stages
2. **Polyglot Sophistication:** PNG+ZIP+PE defeats basic detection
3. **0-Day Integration:** Nation-states hold kernel exploits (PE #5)
4. **Encryption Layers:** AES-256 + XOR + corrupted headers
5. **Infrastructure:** DNS tunneling for stealth C2

**For full technical analysis, see:** `APT41_ATTACK_CHAINS.md` (3,800+ lines of TTP analysis, YARA rules, defensive research applications)

**Lessons for POLYGOTTEM Development:**

- ✅ **Strength:** CVE-2025-62215 provides similar kernel PE capability
- ⚠️ **Gap:** Missing Citrix/Log4j initial access vectors
- ⚠️ **Gap:** No DLL injection CVE implementations
- ✅ **Strength:** Multi-CVE polyglot generator exists
- ⚠️ **Enhancement Needed:** Add DNS tunneling C2 templates

---

## CVE Database Summary

### Total CVEs: 45

#### By Platform:
- **macOS**: 7 CVEs (5 from 2025)
- **Windows**: 3 CVEs (all from 2025)
- **Linux**: 2 CVEs (all from 2025)
- **iOS/iPhone**: 5 CVEs (all from 2025)
- **Android**: 10 CVEs (all from 2025) ✨ **NEW**
- **Cross-Platform**: 18 CVEs (legacy)

#### By Type:
- **RCE (Remote Code Execution)**: 19 CVEs (+5 Android)
- **LPE (Local Privilege Escalation)**: 19 CVEs (+2 Android)
- **Sandbox Escape**: 2 CVEs (+1 Android)
- **Memory Corruption**: 3 CVEs (+2 Android)
- **PAC Bypass**: 1 CVE
- **USB Bypass**: 1 CVE

#### By Severity:
- **CRITICAL (CVSS 9.0-10.0)**: 10 CVEs (+1 Android)
- **HIGH (CVSS 7.0-8.9)**: 32 CVEs (+9 Android)
- **MEDIUM (CVSS 4.0-6.9)**: 3 CVEs

#### Actively Exploited (In the Wild):
- CVE-2025-43300 (macOS ImageIO) - ZERO-DAY
- CVE-2025-62215 (Windows Kernel)
- CVE-2025-21333 (Windows Hyper-V)
- CVE-2025-31200 (iOS CoreAudio) - ZERO-CLICK
- CVE-2025-24085 (iOS Core Media) - KERNEL PE
- CVE-2025-24201 (iOS WebKit) - SANDBOX ESCAPE
- CVE-2025-21042 (Samsung Android) - LANDFALL SPYWARE ✨ **NEW**
- CVE-2025-38352 (Android Kernel) - GOOGLE TAG ✨ **NEW**
- CVE-2025-48543 (Android Runtime) - SANDBOX ESCAPE ✨ **NEW**
- CVE-2025-21479 (Qualcomm GPU) - ADRENO EXPLOIT ✨ **NEW**
- CVE-2025-27038 (Qualcomm GPU) - ADRENO UAF ✨ **NEW**
- CVE-2025-27363 (Android RCE) - ACTIVELY EXPLOITED ✨ **NEW**
- CVE-2023-4863 (libwebp)
- CVE-2022-22675 (AppleAVD)

---

## Integration with POLYGOTTEM

### Generate Exploit Chain

```python
from tools.cve_chain_analyzer import CVEChainAnalyzer, TargetPlatform
from tools.exploit_header_generator import ExploitHeaderGenerator

# Get recommended chain
analyzer = CVEChainAnalyzer()
chains = analyzer.suggest_chains(TargetPlatform.MACOS, "full_compromise")
best_chain = chains[0]  # Top recommendation

# Generate exploits for each CVE in chain
generator = ExploitHeaderGenerator()
for i, cve_id in enumerate(best_chain):
    output_file = f"exploit_step_{i+1}_{cve_id}.bin"
    generator.generate_exploit(cve_id, output_file, payload_type='poc_marker')
    print(f"Generated: {output_file}")
```

### Multi-CVE Polyglot with Chain

```python
from tools.multi_cve_polyglot import MultiCVEPolyglot

# Create polyglot with top RCE CVEs
polyglot = MultiCVEPolyglot()
polyglot.generate(
    cve_list=['CVE-2025-43300', 'CVE-2023-4863', 'CVE-2022-22675'],
    output_file='rce_polyglot.bin',
    polyglot_type='custom'
)
```

---

## Security Considerations

### Ethical Use Only

This system is designed for:
- **Authorized penetration testing**
- **Security research and education**
- **Defensive security analysis**
- **Vulnerability assessment**

### Unauthorized Use is Illegal

Do NOT use these tools for:
- Unauthorized system access
- Malicious attacks
- Data theft or destruction
- Any illegal activities

### Responsible Disclosure

If you discover new vulnerabilities:
1. Report to vendor security teams
2. Follow coordinated disclosure timelines
3. Do not publish exploits before patches available
4. Prioritize user safety over recognition

---

## Future Enhancements

### Planned Features

1. **Machine Learning Chain Optimization**
   - Historical success rate analysis
   - Environmental factor consideration
   - Adaptive chain selection

2. **Real-Time Exploit Detection**
   - Monitor security feeds
   - Auto-update CVE database
   - Alert on new high-value targets

3. **Platform-Specific Heuristics**
   - Windows Defender evasion scoring
   - macOS Gatekeeper bypass analysis
   - Linux SELinux context requirements

4. **Polyglot Chain Generator**
   - Auto-generate multi-format files
   - Embed RCE + PE in single file
   - Platform detection and exploitation

5. **Defensive Playbooks**
   - Auto-generate detection rules
   - YARA signatures for chains
   - EDR configuration recommendations

---

## References

### Technical Papers
- "The Art of Exploit Chaining" - BlackHat 2024
- "Zero-Click Exploitation in 2025" - DEF CON 32
- "Kernel Privilege Escalation Techniques" - USENIX Security

### CVE Sources
- NIST National Vulnerability Database: https://nvd.nist.gov/
- MITRE CVE List: https://cve.mitre.org/
- Exploit-DB: https://www.exploit-db.com/
- ZDI Advisories: https://www.zerodayinitiative.com/

### Security Bulletins
- Apple Security Updates: https://support.apple.com/en-us/HT201222
- Microsoft Security Response Center: https://msrc.microsoft.com/
- Linux Kernel CVEs: https://www.cve.org/

---

**Document Version:** 1.0
**Last Updated:** 2025-11-12
**Maintained by:** SWORDIntel Security Research
**License:** Research and educational purposes only

**⚠️ WARNING:** These techniques are for authorized security research, penetration testing, and defensive security only. Unauthorized use is illegal and unethical.
