# File Dialog Integration

## Overview

POLYGOTTEM now supports graphical file dialogs for selecting custom container files when creating polyglots. This makes it much easier to browse and select files instead of typing paths manually.

## Features

### Automatic Detection
- Detects if `tkinter` is available on your system
- Gracefully falls back to text input if not available
- No configuration required

### Supported Workflows

File dialog is available in all workflows that support custom containers:

1. **Quick Exploit** (workflow 1) - Single exploit polyglot packaging
2. **Smart Polyglot** (workflow 2) - Platform polyglot generation
3. **Full Campaign** (workflow 3) - Exploit chain polyglot packaging
4. **APT-41 Replication** (workflow 4) - Custom PNG container
5. **Platform Attack Chain** (workflow 5) - Platform chain polyglot packaging
6. **Linux CVE Cascade** - PNG container selection

### Usage

When prompted for a custom container file, you'll see:

**With tkinter available:**
```
Select [type] file:
  • Press 'B' to browse with file dialog
  • Press Enter to use default (generated file)
  • Or type file path directly

Container file path (or 'B' to browse, Enter for default):
```

**Without tkinter:**
```
Select [type] file:
  • Press Enter to use default (generated file)
  • Or type file path directly

Container file path (or press Enter for default):
```

### Supported File Types

The file dialog filters by:
- All Files (`*.*`)
- PNG Images (`*.png`)
- JPEG Images (`*.jpg`, `*.jpeg`)
- ZIP Archives (`*.zip`)
- PDF Documents (`*.pdf`)
- GIF Images (`*.gif`)

## Installation

### Linux (Ubuntu/Debian)
```bash
sudo apt install python3-tk
```

### Linux (Fedora/RHEL)
```bash
sudo dnf install python3-tkinter
```

### macOS
Tkinter is usually pre-installed with Python. If not:
```bash
brew install python-tk
```

### Windows
Tkinter is included with Python installations from python.org

## Example Workflow

1. **Run POLYGOTTEM in interactive mode:**
   ```bash
   ./launch.sh interactive
   ```

2. **Select a workflow** (e.g., Smart Polyglot)

3. **When prompted for custom container:**
   ```
   Select PNG container file:
     • Press 'B' to browse with file dialog
     • Press Enter to use default (generated file)
     • Or type file path directly

   Container file path (or 'B' to browse, Enter for default): B
   ```

4. **Browse and select your file** using the graphical dialog

5. **Continue with polyglot generation**

## Technical Details

### Implementation
- Uses `tkinter.filedialog.askopenfilename()` for file browsing
- Creates hidden root window that auto-destroys after selection
- Window appears on top of all other windows (`-topmost` attribute)
- Handles cancellation gracefully

### Method
```python
_prompt_custom_file(file_type: str = "container") -> Optional[str]
```

**Parameters:**
- `file_type`: Description of file being selected (e.g., "PNG container", "ZIP archive")

**Returns:**
- `str`: Path to selected file
- `None`: If user cancels or selects default

### Error Handling
- Catches and reports dialog errors
- Falls back to text input on error
- Validates file existence before use

## Benefits

✅ **User-friendly** - Browse files instead of typing paths
✅ **Visual** - See file names, sizes, and locations
✅ **Fast** - Quick navigation with native file browser
✅ **Safe** - Validates file existence automatically
✅ **Graceful** - Falls back to text input if unavailable
✅ **Cross-platform** - Works on Linux, macOS, and Windows

## Backward Compatibility

The feature is **fully backward compatible:**
- Typing paths directly still works
- Default (generated) files work as before
- No changes to command-line arguments
- No breaking changes to workflows

---

**Note:** If tkinter is not available, the tool functions identically to before with text-based input.
