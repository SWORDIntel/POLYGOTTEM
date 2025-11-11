# POLYGOTTEM Interactive TUI Features

## Overview

POLYGOTTEM now includes comprehensive interactive Terminal User Interface (TUI) features with multi-choice selection, cascading auto-execution with redundancy, and real-time validation.

## New Components

### 1. Interactive Menu System (`tools/interactive_menu.py`)

Provides intuitive multi-choice selection menus with:

- **Multi-select checkboxes** - Select multiple options with visual feedback
- **Single-select radio buttons** - Choose one option from a list
- **Confirmation prompts** - Yes/No confirmations with defaults
- **Text input** - Validated text input prompts
- **Curses support** - Arrow key navigation when available
- **Fallback mode** - Numbered selection when curses unavailable

#### Features:

- ✓ **Visual feedback** with colors and symbols
- ✓ **Keyboard navigation** (arrow keys, space, enter)
- ✓ **Min/max selection limits**
- ✓ **Disabled options** support
- ✓ **Pre-selected defaults**
- ✓ **Custom colors per option**
- ✓ **Descriptions** for each option
- ✓ **Fluent MenuBuilder** for chaining menus

#### Example Usage:

```python
from tools.interactive_menu import InteractiveMenu

menu = InteractiveMenu()

# Multi-select example
options = [
    {'label': 'Option 1', 'description': 'First option', 'selected': True},
    {'label': 'Option 2', 'description': 'Second option'},
    {'label': 'Option 3', 'description': 'Third option', 'disabled': True},
]

selected = menu.multi_select("Choose Options", options, min_selections=1)
print(f"Selected indices: {selected}")

# Single-select example
choice = menu.single_select("Choose One", options)
print(f"Selected index: {choice}")

# Confirmation
if menu.confirm("Proceed?", default=True):
    print("Confirmed!")

# Menu builder for chaining
from tools.interactive_menu import MenuBuilder

builder = MenuBuilder()
results = builder \
    .add_single_select('format', 'Choose format', options) \
    .add_input('filename', 'Output filename', default='output.bin') \
    .add_confirm('encrypt', 'Apply encryption?') \
    .get_results()
```

---

### 2. Auto-Execution Engine (`tools/auto_execution_engine.py`)

Comprehensive auto-execution system with 20+ execution methods and cascading redundancy.

#### Supported Execution Methods:

**Document-Based:**
- `pdf_openaction` - PDF with JavaScript auto-execution
- `pdf_launch` - PDF Launch action
- `html_onload` - HTML body onload event
- `html_script` - HTML script tag self-invocation
- `html_meta_refresh` - HTML meta refresh to data: URI

**Windows-Specific:**
- `windows_lnk` - LNK shortcut files
- `windows_scf` - SCF explorer files
- `windows_hta` - HTML Applications (HTA)
- `windows_vbs` - VBScript files
- `windows_bat` - Batch files
- `windows_ps1` - PowerShell scripts
- `windows_inf` - INF setup files

**Unix/Linux:**
- `bash_shebang` - Bash scripts with shebang
- `python_shebang` - Python scripts with shebang
- `desktop_file` - .desktop files

**Binaries:**
- `elf_binary` - ELF executables
- `pe_binary` - PE/EXE executables
- `jar_file` - Java JAR files

**Office Documents:**
- `office_macro` - VBA macros
- `office_dde` - DDE fields (often blocked)

#### Reliability Ratings:

- **VERY_HIGH (5)** - 95%+ success rate (Bash, HTML, BAT, ELF, PE)
- **HIGH (4)** - 75-95% success rate (PDF JavaScript, Python, LNK, JAR)
- **MEDIUM (3)** - 50-75% success rate (PDF Launch, Office Macros)
- **LOW (2)** - 25-50% success rate (Office DDE)
- **VERY_LOW (1)** - <25% success rate

#### Cascading Execution:

The engine supports automatic fallback - if one method fails, it tries the next:

```python
from tools.auto_execution_engine import AutoExecutionEngine

engine = AutoExecutionEngine()

payload = b'echo "test"'

# Execute with cascading fallback
results = engine.execute_cascade(
    payload,
    methods=['pdf_openaction', 'html_onload', 'bash_shebang'],
    stop_on_success=True  # Stop after first success
)

print(f"Succeeded: {results['methods_succeeded']}")
print(f"Failed: {results['methods_failed']}")
print(f"Files: {results['files_generated']}")
```

#### Platform-Aware Selection:

```python
# Get methods compatible with current platform
available = engine.get_available_methods()

# Filter by minimum reliability
high_reliability = engine.get_available_methods(
    min_reliability=ExecutionReliability.HIGH
)
```

---

### 3. Execution Validator (`tools/execution_validator.py`)

Real-time validation and testing of execution methods.

#### Features:

- **Environment detection** - Checks installed software and capabilities
- **Dependency verification** - Validates requirements are met
- **Platform compatibility** - Checks OS/architecture compatibility
- **Method testing** - Safe validation of each method
- **Reliability estimation** - Predicts success probability
- **Comprehensive reporting** - Detailed validation reports

#### Usage:

```python
from tools.execution_validator import ExecutionValidator
from tools.auto_execution_engine import AutoExecutionEngine

validator = ExecutionValidator()
engine = AutoExecutionEngine()

# Validate environment
env = validator.validate_environment()
print(f"Platform: {env['platform']}")
print(f"Installed: {env['installed_software']}")

# Validate all methods
results = validator.validate_all_methods(engine.methods)

# Show report
validator.show_validation_report(results)

# Get recommended methods
recommended = validator.get_recommended_methods(results, min_reliability=0.75)
print(f"Recommended: {recommended}")
```

---

### 4. Polyglot Orchestrator (`tools/polyglot_orchestrator.py`)

Main interactive orchestration system that ties everything together.

#### Full Interactive Workflow:

1. **CVE Selection** - Multi-select from 10+ CVE exploits
2. **Format Selection** - Choose polyglot type (Image, Audio, MEGA, etc.)
3. **Execution Methods** - Select auto-execution vectors
4. **Encryption Configuration** - Choose XOR keys and layers
5. **Redundancy Configuration** - Configure fallback behavior
6. **Configuration Review** - Confirm all settings
7. **Polyglot Generation** - Generate combined file
8. **Cascade Execution** - Execute with redundancy
9. **Results Summary** - View success/failure reports

#### Interactive Mode:

```bash
# Launch full interactive workflow
python tools/polyglot_orchestrator.py

# Or via multi_cve_polyglot.py
python tools/multi_cve_polyglot.py --interactive
```

#### Headless Mode:

```bash
python tools/polyglot_orchestrator.py --headless \
    --cves CVE-2023-4863 CVE-2024-10573 \
    --format mega \
    --methods pdf_openaction html_onload bash_shebang \
    --output polyglot.dat \
    --encrypt \
    --keys 9e 0a61200d
```

---

## Integration with Existing Tools

### Multi-CVE Polyglot Generator

```bash
# Traditional CLI mode (still works)
python tools/multi_cve_polyglot.py mega output.dat

# NEW: Interactive mode
python tools/multi_cve_polyglot.py --interactive
python tools/multi_cve_polyglot.py -i
```

### Desktop Generator

The desktop generator can now be integrated with interactive menus for template selection:

```python
from tools.interactive_menu import InteractiveMenu

menu = InteractiveMenu()
templates = [
    {'label': 'Basic', 'description': 'Simple desktop entry'},
    {'label': 'Obfuscated', 'description': 'Hidden execution'},
    {'label': 'Persistent', 'description': 'Auto-start on login'},
]
choice = menu.single_select("Select Template", templates)
```

---

## Configuration Examples

### Example 1: High-Reliability Multi-Vector Attack

```python
from tools.polyglot_orchestrator import PolyglotOrchestrator

orchestrator = PolyglotOrchestrator()

# Select high-reliability methods only
methods = [
    'html_onload',
    'bash_shebang',
    'windows_bat',
    'elf_binary',
    'pe_binary'
]

# Configure for maximum success
redundancy = {
    'stop_on_success': False,  # Try all methods
    'validate': True,
    'fallback': True,
    'persistence': True
}
```

### Example 2: Stealth Configuration

```python
# Select stealthy, document-based methods
methods = [
    'pdf_openaction',
    'html_meta_refresh',
    'office_macro'
]

# Multi-layer encryption
encryption = {
    'enabled': True,
    'keys': ['9e', '0a61200d', 'deadbeef'],
    'layers': 5
}
```

### Example 3: Cross-Platform Polyglot

```python
# CVEs targeting multiple platforms
cves = [
    'CVE-2023-4863',  # WebP (cross-platform browsers)
    'CVE-2024-10573',  # MP3 (cross-platform media players)
]

# Execution methods for all platforms
methods = [
    'html_onload',     # Windows, Linux, macOS
    'pdf_openaction',  # Cross-platform PDF readers
    'jar_file',        # Cross-platform Java
    'python_shebang',  # Windows (if Python), Linux, macOS
]
```

---

## Redundancy Strategies

### Strategy 1: Stop on First Success

```python
redundancy_config = {
    'stop_on_success': True,  # Stop after first method succeeds
    'validate': True,
    'fallback': False,
    'persistence': False
}
```

**Use case:** Quick execution, minimize detection

### Strategy 2: Try All Methods

```python
redundancy_config = {
    'stop_on_success': False,  # Try every method
    'validate': True,
    'fallback': True,
    'persistence': True
}
```

**Use case:** Maximum coverage, ensure at least one succeeds

### Strategy 3: Adaptive Cascade

```python
redundancy_config = {
    'stop_on_success': False,
    'validate': True,
    'adaptive': True,  # Intelligently select based on environment
    'fallback': True,
    'persistence': True
}
```

**Use case:** Best of both worlds, smart selection

---

## Visual Features

### TUI Components

- **Progress Bars** - Color-coded progress (red → yellow → green)
- **Spinners** - Animated loading indicators
- **Tables** - Formatted data tables with borders
- **Boxes** - Highlighted information boxes
- **Banners** - Centered title banners
- **Sections** - Section dividers
- **Key-Value Pairs** - Aligned key-value output
- **Lists** - Hierarchical bulleted lists
- **Status Messages** - Success/Error/Warning/Info with symbols

### Color Scheme

- **Green** - Success, passed, high reliability
- **Red** - Error, failed, critical
- **Yellow** - Warning, medium reliability
- **Cyan** - Info, headers, borders
- **Bright colors** - Emphasis, current selection

### Symbols

- ✓ Success
- ✗ Failure
- ⚠ Warning
- ℹ Info
- → Arrow
- • Bullet
- 🔥 Critical
- 🎯 Target
- 💣 Bomb
- ☠ Skull
- 🛡 Shield

---

## Testing the Features

### Test Interactive Menus

```bash
python tools/interactive_menu.py
```

This runs a demo showing:
- Multi-select CVE selection
- Single-select payload type
- Confirmation prompt
- Menu builder chain

### Test Auto-Execution Engine

```bash
python tools/auto_execution_engine.py
```

Shows:
- Available execution methods
- Reliability ratings
- Cascading execution demo
- Generated files

### Test Validation

```bash
python tools/execution_validator.py
```

Shows:
- Environment detection
- Software availability
- Platform capabilities

### Test Full Orchestrator

```bash
python tools/polyglot_orchestrator.py
```

Launches the complete interactive workflow.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Polyglot Orchestrator                     │
│                  (Main Interactive UI)                      │
└─────────────────┬───────────────────────────────────────────┘
                  │
        ┌─────────┴──────────┬──────────────────┬─────────────┐
        │                    │                  │             │
┌───────▼────────┐  ┌────────▼───────┐  ┌──────▼──────┐  ┌──▼─────┐
│ Interactive    │  │ Auto-Execution │  │ Execution   │  │  TUI   │
│ Menu System    │  │ Engine         │  │ Validator   │  │ Helper │
│                │  │                │  │             │  │        │
│ - Multi-select │  │ - 20+ methods  │  │ - Env check │  │ Colors │
│ - Single-select│  │ - Cascading    │  │ - Deps check│  │ Symbols│
│ - Confirmation │  │ - Redundancy   │  │ - Testing   │  │ Tables │
│ - Input        │  │ - Platform-    │  │ - Reporting │  │ Boxes  │
│ - MenuBuilder  │  │   aware        │  │             │  │ Progress│
└────────────────┘  └────────────────┘  └─────────────┘  └────────┘
        │                    │                  │
        └────────────────────┴──────────────────┘
                             │
                    ┌────────▼────────┐
                    │ Multi-CVE       │
                    │ Polyglot        │
                    │ Generator       │
                    │                 │
                    │ - Image polyglot│
                    │ - Audio polyglot│
                    │ - MEGA polyglot │
                    │ - XOR encryption│
                    └─────────────────┘
```

---

## Advanced Usage

### Custom Validators

```python
def validate_filename(filename):
    if not filename.endswith('.bin'):
        return False, "Filename must end with .bin"
    if len(filename) < 5:
        return False, "Filename too short"
    return True, ""

filename = menu.prompt_input(
    "Enter filename",
    default="output.bin",
    validator=validate_filename
)
```

### Custom Menu Builder Chains

```python
builder = MenuBuilder()

results = builder \
    .add_multi_select('cves', 'Select CVEs', cve_options, min_selections=1) \
    .add_single_select('format', 'Select format', format_options) \
    .add_confirm('encrypt', 'Encrypt?', default=True) \
    .add_input('output', 'Output file', default='polyglot.bin') \
    .get_results()

# results = {
#     'cves': [0, 2, 5],
#     'format': 1,
#     'encrypt': True,
#     'output': 'polyglot.bin'
# }
```

### Programmatic Execution

```python
from tools.auto_execution_engine import AutoExecutionEngine, ExecutionPlatform
from tools.execution_validator import ExecutionValidator

# Initialize
engine = AutoExecutionEngine()
validator = ExecutionValidator()

# Validate environment
env = validator.validate_environment()

# Validate methods
results = validator.validate_all_methods(engine.methods)

# Get recommended methods
recommended = validator.get_recommended_methods(results, min_reliability=0.75)

# Execute cascade
payload = b'echo "test"'
cascade_results = engine.execute_cascade(
    payload,
    methods=recommended,
    stop_on_success=True
)

print(f"Success: {len(cascade_results['methods_succeeded'])}/{len(recommended)}")
```

---

## Security Considerations

⚠️ **WARNING:** These tools are for authorized security testing only!

- **Always** obtain written authorization before testing
- **Never** use on systems you don't own or have permission to test
- **Always** validate you're in a controlled environment
- **Never** distribute generated files without proper disclosure
- **Always** follow responsible disclosure practices

### Ethical Use Guidelines

1. **Authorization** - Written permission required
2. **Controlled Environment** - Isolated test systems only
3. **Documentation** - Keep detailed records of testing
4. **Responsible Disclosure** - Report findings properly
5. **Educational Purpose** - Research and learning only

---

## Troubleshooting

### Issue: Curses menu doesn't work

**Solution:** Fallback to numbered selection automatically happens. If you want curses support:

```bash
# Linux
sudo apt-get install python3-curses

# macOS
# Curses included with Python

# Windows
pip install windows-curses
```

### Issue: Some execution methods fail validation

**Solution:** This is expected. Not all methods work on all platforms. Check the validation report:

```python
validator.show_validation_report(results)
```

Look for:
- Platform compatibility
- Missing dependencies
- Permission issues

### Issue: Interactive mode import error

**Solution:** Ensure all files are in the correct location:

```
tools/
├── tui_helper.py
├── interactive_menu.py
├── auto_execution_engine.py
├── execution_validator.py
├── polyglot_orchestrator.py
└── multi_cve_polyglot.py
```

---

## Performance

### Hardware Acceleration

The system supports Intel NPU/GPU acceleration for:
- XOR encryption/decryption
- Large file processing
- Polyglot generation

Enable with:
```python
engine = AutoExecutionEngine()  # Auto-detects and enables
```

Disable with:
```bash
python tools/multi_cve_polyglot.py --no-accel
```

### Benchmarks

Test acceleration performance:
```bash
python tools/multi_cve_polyglot.py --benchmark
```

---

## Future Enhancements

Planned features:
- [ ] ARM architecture support
- [ ] macOS-specific methods (.app bundles, .dmg)
- [ ] Android APK auto-execution
- [ ] Network-based delivery methods
- [ ] Cloud storage polyglots (S3, GCS, Azure)
- [ ] Container escape methods
- [ ] Browser extension polyglots

---

## Credits

**POLYGOTTEM** - SWORDIntel Team
Date: 2025-11-11

For educational and authorized security testing only.

---

## License

See main repository LICENSE file.

**DISCLAIMER:** This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool.
