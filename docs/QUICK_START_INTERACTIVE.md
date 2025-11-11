# Quick Start Guide - Interactive TUI Mode

## 🚀 Fastest Way to Get Started

### Step 1: Launch Interactive Mode

```bash
cd /path/to/POLYGOTTEM

# Option 1: Direct orchestrator
python tools/polyglot_orchestrator.py

# Option 2: Via multi_cve_polyglot.py
python tools/multi_cve_polyglot.py --interactive
python tools/multi_cve_polyglot.py -i
```

### Step 2: Follow the Interactive Workflow

The system will guide you through:

1. **CVE Selection** - Choose exploits (use numbers, 'A' for all, 'N' for none)
2. **Format Selection** - Pick polyglot type (Image, Audio, MEGA, etc.)
3. **Execution Methods** - Select auto-execution vectors
4. **Encryption** - Configure XOR encryption (optional)
5. **Redundancy** - Choose fallback strategy
6. **Review** - Confirm configuration
7. **Generate** - Create polyglot file
8. **Execute** - Test auto-execution methods
9. **Results** - View success/failure report

### Step 3: Review Output

The system generates:
- Main polyglot file (combined CVE exploits)
- Auto-execution files for each selected method
- Validation report
- Success/failure summary

---

## 🎯 Quick Examples

### Example 1: High-Impact Polyglot with Auto-Execution

```bash
python tools/polyglot_orchestrator.py
```

**When prompted:**
- CVEs: Select `1, 2, 3` (WebP, MP3, TIFF)
- Format: Choose `3` (MEGA - everything)
- Methods: Select `1, 2, 5, 7` (PDF, HTML, Bash, LNK)
- Encryption: Yes, keys `1, 3` (0x9e, 0x0a61200d)
- Redundancy: `1` (Stop on first success)
- Review: `Y` (Confirm)

**Result:** MEGA polyglot with 12+ formats, 4 auto-execution methods, multi-layer XOR encryption

### Example 2: Cross-Platform Polyglot

```bash
python tools/multi_cve_polyglot.py -i
```

**When prompted:**
- CVEs: Select `1, 2` (WebP, MP3)
- Format: Choose `1` (Image polyglot)
- Methods: Select `2, 3, 9, 14` (HTML onload, HTML script, Python, JAR)
- Encryption: Yes, key `1` (0x9e), 3 layers
- Redundancy: `2` (Try all methods)

**Result:** Image polyglot with cross-platform auto-execution

### Example 3: Stealth Document-Based

```bash
python tools/polyglot_orchestrator.py
```

**When prompted:**
- CVEs: Select `1` (WebP - critical browser exploit)
- Format: Choose `4` (Document polyglot)
- Methods: Select `1, 5` (PDF OpenAction, HTML meta refresh)
- Encryption: Yes, keys `1, 5` (0x9e, deadbeef), 5 layers
- Redundancy: `1` (Stop on first success)

**Result:** Document-based stealth polyglot

---

## 📋 Menu Navigation

### Multi-Select Menus

**Keyboard (if curses available):**
- `↑/↓` - Navigate options
- `Space` - Toggle selection
- `A` - Select all
- `N` - Select none
- `Enter` - Confirm selection
- `Q` - Quit

**Numbered Input (fallback):**
- `1-9` - Toggle option by number
- `A` - Select all
- `N` - Select none
- `Enter` - Confirm selection

### Single-Select Menus

**Input:**
- `1-9` - Select option
- `Enter` - Use default
- `C` - Cancel (if allowed)

### Confirmation Prompts

**Input:**
- `Y/y` - Yes
- `N/n` - No
- `Enter` - Use default

---

## 🎨 Visual Guide

### Status Symbols

- ✓ **Success** - Operation completed successfully
- ✗ **Failure** - Operation failed
- ⚠ **Warning** - Proceed with caution
- ℹ **Info** - Additional information
- 🔥 **Critical** - High severity
- 🎯 **Target** - Focus item
- 💣 **Bomb** - Exploit payload
- ☠ **Skull** - Dangerous operation
- 🛡 **Shield** - Security measure

### Color Coding

- **Green** - Success, safe, high confidence
- **Red** - Error, danger, critical
- **Yellow** - Warning, medium confidence
- **Cyan** - Info, headers, navigation
- **Bright colors** - Emphasis, selection

### Progress Indicators

- **Red bar** - 0-33% (starting)
- **Yellow bar** - 34-66% (in progress)
- **Green bar** - 67-100% (completing)

---

## 🔧 Configuration Tips

### For Maximum Success Rate

1. **Select high-reliability methods:**
   - HTML onload/script (cross-platform browsers)
   - Bash shebang (Linux/macOS)
   - Windows BAT (Windows)
   - ELF/PE binaries (native executables)

2. **Enable redundancy:**
   - Choose "Try all methods"
   - Enable validation
   - Enable fallback generation

3. **Multi-layer encryption:**
   - Use 3-5 layers
   - Mix single-byte and multi-byte keys
   - Include TeamTNT signature keys

### For Stealth

1. **Select document-based methods:**
   - PDF OpenAction
   - HTML meta refresh
   - Office macros (if target has Office)

2. **Use 5+ encryption layers**

3. **Stop on first success** to minimize file generation

### For Cross-Platform

1. **Select CVEs affecting multiple platforms:**
   - WebP (browsers on all platforms)
   - MP3 (media players on all platforms)

2. **Select cross-platform methods:**
   - HTML (all platforms with browsers)
   - PDF (all platforms with PDF readers)
   - JAR (all platforms with Java)
   - Python (if installed on target)

---

## 🛠 Troubleshooting

### "ImportError: No module named 'interactive_menu'"

**Solution:**
```bash
# Ensure you're in the POLYGOTTEM directory
cd /path/to/POLYGOTTEM

# Run with proper path
python tools/polyglot_orchestrator.py
```

### "Curses menu not available"

**Solution:** This is not an error. The system automatically falls back to numbered input. If you want curses support:

```bash
# Linux
sudo apt-get install python3-curses

# Windows
pip install windows-curses
```

### "Validation failed for method X"

**Solution:** This is expected. Some methods don't work on all platforms:
- Windows methods (LNK, SCF, HTA, VBS, BAT, PS1, INF) - Windows only
- Linux methods (Bash, Desktop files) - Linux/macOS only
- Binary methods (ELF, PE) - Architecture-specific

The validator automatically filters incompatible methods.

### "No methods selected"

**Solution:** At least one method must be selected. If all are incompatible:
1. Run on the target platform
2. Or select cross-platform methods (PDF, HTML, JAR)

---

## 📊 Understanding Results

### Cascade Execution Results

```
Execution Results
┌──────────────────┬───────────────┐
│ Metric           │ Value         │
├──────────────────┼───────────────┤
│ Total Attempts   │ 5             │
│ Succeeded        │ 3             │
│ Failed           │ 2             │
│ Files Generated  │ 3             │
└──────────────────┴───────────────┘
```

**Interpretation:**
- **Total Attempts** - Number of methods tried
- **Succeeded** - Methods that passed validation
- **Failed** - Methods that failed (platform incompatible, dependencies missing, etc.)
- **Files Generated** - Number of auto-execution files created

### Validation Report

```
Method                          Status      Reliability   Reason
──────────────────────────────────────────────────────────────
pdf_openaction                  ✓ PASS      85%          Validation passed
html_onload                     ✓ PASS      95%          Validation passed
windows_lnk                     ⊗ SKIP      N/A          Platform mismatch
bash_shebang                    ✓ PASS      90%          Validation passed
office_macro                    ✗ FAIL      N/A          Missing dependencies
```

**Status:**
- ✓ PASS - Method validated successfully
- ⊗ SKIP - Skipped (platform incompatible)
- ✗ FAIL - Failed validation (dependencies, structure, etc.)

**Reliability:**
- 90-100% - Very High (use these!)
- 75-89% - High (good choice)
- 50-74% - Medium (works often)
- 25-49% - Low (unreliable)
- <25% - Very Low (rarely works)

---

## 🎓 Learning Path

### Beginner

1. **Run demo scripts** to see features:
   ```bash
   python tools/interactive_menu.py
   python tools/auto_execution_engine.py
   python tools/execution_validator.py
   ```

2. **Try simple polyglot** with defaults:
   ```bash
   python tools/polyglot_orchestrator.py
   # Accept all defaults by pressing Enter
   ```

3. **Review generated files** and understand structure

### Intermediate

1. **Experiment with different CVEs** - understand each exploit
2. **Try different execution methods** - see which work best
3. **Test encryption** - verify XOR encryption/decryption
4. **Study validation reports** - understand platform limitations

### Advanced

1. **Programmatic usage** - integrate into your tools:
   ```python
   from tools.auto_execution_engine import AutoExecutionEngine
   engine = AutoExecutionEngine()
   results = engine.execute_cascade(payload, methods=[...])
   ```

2. **Custom validators** - add your own validation logic
3. **Extend methods** - add new auto-execution techniques
4. **Create presets** - save favorite configurations

---

## 💡 Pro Tips

1. **Test locally first** - Always validate in safe environment
2. **Use validation** - Run validator before executing
3. **Check logs** - Review validation reports for issues
4. **Start small** - Begin with 1-2 CVEs and methods
5. **Scale up** - Gradually add more complexity
6. **Document tests** - Keep records of what works
7. **Stay legal** - Only test with authorization

---

## 🔗 Related Documentation

- **Full Documentation:** [INTERACTIVE_TUI_FEATURES.md](INTERACTIVE_TUI_FEATURES.md)
- **Auto-Execution Analysis:** [AUTO_EXECUTION_ANALYSIS.md](AUTO_EXECUTION_ANALYSIS.md)
- **Auto-Execution Polyglots:** [AUTO_EXECUTION_POLYGLOTS.md](../AUTO_EXECUTION_POLYGLOTS.md)
- **CVE Details:** [CVE_DETAILS.md](CVE_DETAILS.md)

---

## ⚠️ Legal Disclaimer

**FOR AUTHORIZED SECURITY TESTING ONLY**

This tool is provided for:
- Educational purposes
- Authorized penetration testing
- Security research
- CTF competitions
- Defensive security

**NEVER use without:**
- Written authorization
- Controlled environment
- Proper legal framework

The authors are not responsible for misuse.

---

## 📞 Support

Having issues? Check:
1. This Quick Start Guide
2. Full documentation (INTERACTIVE_TUI_FEATURES.md)
3. Troubleshooting section above
4. GitHub issues: https://github.com/SWORDIntel/POLYGOTTEM/issues

---

**Happy (authorized) testing! 🎯**
