# POLYGOTTEM - Windows Installation & Usage Guide

Complete guide for running POLYGOTTEM on Windows with full GUARANTEE cascade enhancements.

---

## 🚀 Quick Start (Windows)

### Prerequisites
- **Windows 10/11/2019/2022** (x86-64)
- **Python 3.8+** (download from [python.org](https://www.python.org/downloads/))
- **Git** (for cloning the repository)
- **Administrator access** (optional, for some features)

### Installation Steps

**Step 1: Clone Repository**
```powershell
git clone https://github.com/SWORDIntel/POLYGOTTEM.git
cd POLYGOTTEM
```

**Step 2: Run Installer**
```batch
install.bat
```

The installer will:
- ✓ Verify Python 3.8+ installation
- ✓ Create virtual environment (`venv/`)
- ✓ Install core dependencies (NumPy, cryptography, etc.)
- ✓ Verify GUARANTEE cascade system
- ✓ Offer optional Intel acceleration setup

**Step 3: Launch POLYGOTTEM**
```batch
launch.bat
```

That's it! You're ready to use POLYGOTTEM.

---

## 📋 Installation Modes

### 1. **Default (Interactive)**
```batch
install.bat
```
- Creates venv
- Installs core dependencies
- Prompts for hardware acceleration (optional)

### 2. **Minimal (CPU Only)**
```batch
install.bat --auto
```
- Fast installation
- No prompts
- Works on any system
- **Recommended for beginners**

### 3. **Full Intel Optimization**
```batch
install.bat --intel
```
- Installs Intel acceleration packages
- OpenVINO, PyOpenCL, Neural Compressor
- 10-50x speedup for XOR encryption
- **Requires Intel Core Ultra (Meteor Lake) with NPU**
- Takes 10-30 minutes

---

## 🎯 Launching POLYGOTTEM

### Basic Launch
```batch
launch.bat
```
Launches interactive TUI with default settings (interactive mode + Intel acceleration)

### With Custom Settings
```batch
REM Launch with specific command
launch.bat list cves

REM Run benchmark tests
launch.bat --benchmark

REM Show all options
launch.bat --help
```

### Configuration Commands
```batch
REM Set defaults to interactive mode
launch.bat --set-interactive

REM Set defaults to Intel acceleration
launch.bat --set-intel

REM Set both
launch.bat --set-interactive --set-intel

REM View current configuration
launch.bat --show-config

REM Reset to defaults
launch.bat --clear-config
```

---

## 🛡️ GUARANTEE Cascade Mode (NEW!)

POLYGOTTEM now includes advanced GUARANTEE cascade mode with:

### **Features**
- ✅ Intelligent method chaining (up to 10 execution methods)
- ✅ Biometric authentication (Yubikey FIDO2 + fingerprint)
- ✅ Network beaconing to C2 infrastructure
- ✅ YARA/Sigma rule auto-generation
- ✅ Classified document theme (CONFIDENTIAL)
- ✅ Audit logging and compliance tracking

### **Using GUARANTEE Cascade**
```batch
launch.bat interactive
```

Then select from the menu:
```
┌─ Cascade Mode Selection ─┐
│ 1. Standard cascade      │
│ 2. Smart cascade         │
│ 3. GUARANTEE cascade ⭐  │  ← Select this
│ 4. Custom cascade        │
└──────────────────────────┘
```

### **GUARANTEE Cascade Workflow**
1. **Authorization Verification** - Legal compliance & consent
2. **Biometric Authentication** - Yubikey/Fingerprint (first-run setup)
3. **Chain Creation** - Generate optimal exploit chain
4. **Network Beaconing** - Real-time callback to C2
5. **Rule Generation** - Auto-generate YARA/Sigma rules
6. **Audit Logging** - Complete compliance trail

---

## 🔐 Biometric Authentication Setup (First Run)

When you first use GUARANTEE cascade mode:

### **Hardware Support**
- ✅ **Yubikey 4/5** (FIDO2 U2F) - Via libfprint
- ✅ **Broadcom Fingerprint** - Direct driver support
- ✅ **Windows Hello** - (future enhancement)

### **Setup Wizard**
The system will:
1. Detect available biometric hardware
2. Test hardware connectivity
3. Enroll biometric data
4. Generate recovery codes (32-byte hex, SHA256 hashed)
5. Create secure configuration (`~/.polygottem/`)

### **Recovery Codes**
Save these in secure location:
```
~/.polygottem/.recovery_code (hashed, 0600 permissions)
~/.polygottem/.owner (owner info)
~/.polygottem/.hardware_config (detected devices)
```

---

## 📊 System Requirements & Hardware

### **Minimum (CPU Only)**
- Python 3.8+
- 2GB RAM
- 500MB disk space

### **Recommended (Full Features)**
- Python 3.8+
- 4GB+ RAM
- 2GB disk space
- Intel Core i5+ (CPU XOR baseline)

### **Optimal (Maximum Performance)**
- Python 3.8+
- 8GB+ RAM
- 3GB disk space
- Intel Core Ultra with NPU (Meteor Lake)
- Intel Arc GPU (optional)

### **Hardware Acceleration**

| Package | Speed | Requirements | Size |
|---------|-------|--------------|------|
| **NumPy (default)** | 1x | All systems | 100MB |
| **OpenVINO** | 10-50x | Intel Core Ultra NPU | 2GB |
| **PyOpenCL** | 3-15x | Any OpenCL GPU | 50MB |
| **Intel Scikit-learn** | 2-5x | Intel CPU | 200MB |
| **Neural Compressor** | Custom | Intel Core Ultra | 1GB |

---

## 🐛 Troubleshooting

### Issue: "Python not found"
**Solution:**
1. Install Python 3.8+ from [python.org](https://www.python.org/downloads/)
2. **Important:** Check "Add Python to PATH" during installation
3. Restart terminal/PowerShell
4. Run `python --version` to verify

### Issue: "venv creation failed"
**Solution:**
```powershell
# Install venv support
python -m pip install --user virtualenv

# Try install again
install.bat
```

### Issue: "GUARANTEE cascade not available"
**Solution:**
```batch
REM Verify installation
launch.bat --show-config

REM Reinstall cascade components
install.bat --auto

REM Launch again
launch.bat
```

### Issue: Biometric hardware not detected
**Solution:**
```batch
REM Use password fallback (12+ characters)
REM Or reinstall with: install.bat --auto
REM This disables biometric requirement
```

### Issue: "Intel packages failed to install"
**Solution:**
```batch
REM Use CPU-only mode (still works fine)
launch.bat

REM Or try minimal install
install.bat --auto
```

---

## 📂 Directory Structure

```
POLYGOTTEM/
├── install.bat              ← Windows installer
├── launch.bat               ← Windows launcher
├── install.sh               ← Linux/macOS installer
├── launch.sh                ← Linux/macOS launcher
├── polygottem.py            ← Main CLI
├── requirements.txt         ← Core dependencies
├── requirements-intel.txt   ← Intel acceleration packages
├── venv/                    ← Virtual environment (created by install.bat)
│   └── Scripts/
│       ├── python.exe       ← Python executable
│       ├── pip.exe          ← Package manager
│       └── activate.bat     ← Activation script
├── tools/                   ← Core framework
│   ├── guarantee_chainer.py              ← Method chaining
│   ├── guarantee_validator.py            ← Authorization
│   ├── guarantee_fingerprint_setup.py    ← Biometric setup
│   ├── guarantee_fingerprint_auth.py     ← Biometric auth
│   ├── guarantee_network_beacon.py       ← Network callbacks
│   ├── guarantee_beacon_integrator.py    ← Component integration
│   ├── guarantee_report_generator.py     ← YARA/Sigma generation
│   ├── tui_theme_classified.py           ← Military UI theme
│   └── ... (other components)
├── docs/                    ← Documentation
└── payloads/                ← Payload templates

~/.polygottem/ (User Home Directory)
├── launch.conf              ← Launch preferences
├── .fingerprint_setup_complete
├── .recovery_code           ← Emergency access (hashed)
├── .hardware_config         ← Detected devices
└── .owner                   ← Owner registration
```

---

## 🔑 Configuration Files

### Launch Configuration (`~/.polygottem/launch.conf`)
```ini
# POLYGOTTEM Launch Configuration
# Auto-generated by launch.bat

LAUNCH_MODE=interactive
HARDWARE_ACCEL=intel
```

**Change configuration:**
```batch
launch.bat --set-interactive      # Change to interactive mode
launch.bat --set-intel            # Enable Intel acceleration
launch.bat --show-config          # View current settings
launch.bat --clear-config         # Reset to defaults
```

---

## 📝 Common Tasks

### Generate Single CVE Exploit
```batch
launch.bat
# Select: Exploit Generation → CVE-XXXX-XXXXX
```

### Create GUARANTEE Cascade Chain
```batch
launch.bat
# Select: Cascade Mode → GUARANTEE Cascade ⭐
# Answer authorization questions
# Chain generation starts automatically
```

### Run Benchmarks
```batch
launch.bat --benchmark
```

### Verify Installation
```batch
REM Check GUARANTEE cascade
launch.bat
# TUI should show "GUARANTEE Cascade (NEW!)" option

REM Check configuration
launch.bat --show-config
```

### Use Recovery Code
```batch
REM If biometric auth fails, use recovery code
# System will prompt for recovery code
# Enter 32-byte hex code from ~/.polygottem/.recovery_code
```

---

## 🌐 Network Requirements

### GUARANTEE Network Beacon
If using GUARANTEE cascade with network beaconing:

- **Target Host:** articbastion.duckdns.org
- **Target Port:** 443 (HTTPS)
- **Protocol:** HTTPS with callbacks
- **Offline Mode:** Available for lab testing (no actual network calls)

### Firewall Configuration
If behind corporate firewall:
```batch
REM Use offline simulation mode
launch.bat interactive
# Select GUARANTEE cascade
# Enable "Simulation Mode" for testing without network
```

---

## ⚙️ Advanced Configuration

### Disable Biometric Authentication
Edit `~/.polygottem/launch.conf`:
```ini
LAUNCH_MODE=interactive
HARDWARE_ACCEL=intel
BIOMETRIC_DISABLED=true  # Add this line
```

### Force CPU-Only Mode
```batch
REM Uninstall Intel packages
install.bat --auto

REM Or set environment variable
set HARDWARE_ACCEL=none
launch.bat
```

### Enable Debug Logging
```batch
REM Set environment variable
set DEBUG=1
launch.bat
```

---

## 📚 Documentation

- **Main README:** `README.md`
- **CVE Documentation:** `docs/` directory
- **API Documentation:** `tools/README.md`
- **GUARANTEE Cascade:** Search for "GUARANTEE" in polyglot_orchestrator_enhanced.py

---

## 🤝 Support

### If You Encounter Issues:

1. **Check Python Installation:**
   ```batch
   python --version
   # Should be 3.8 or higher
   ```

2. **Verify Venv:**
   ```batch
   .\venv\Scripts\activate.bat
   pip list
   # Should show installed packages
   ```

3. **Reinstall Everything:**
   ```batch
   rmdir /s venv
   install.bat
   ```

4. **Check Logs:**
   ```batch
   REM GUARANTEE audit log
   type guarantee_audit.log
   ```

---

## ✅ Verification Checklist

- [ ] Python 3.8+ installed (`python --version`)
- [ ] Git installed (`git --version`)
- [ ] Repository cloned
- [ ] `install.bat` ran successfully
- [ ] `launch.bat` launches TUI
- [ ] GUARANTEE cascade option visible in menu
- [ ] Configuration saved correctly

---

## 🎯 Next Steps

1. **Run Tutorial:**
   ```batch
   launch.bat
   # Select: Help → Tutorial
   ```

2. **Generate First Exploit:**
   ```batch
   launch.bat
   # Select: Exploit Generation → Choose CVE
   ```

3. **Try GUARANTEE Cascade:**
   ```batch
   launch.bat
   # Select: Cascade Mode → GUARANTEE Cascade
   ```

4. **View Documentation:**
   Open `docs/` folder for detailed guides

---

**Happy exploiting! 🚀**

For official documentation, visit: https://github.com/SWORDIntel/POLYGOTTEM
