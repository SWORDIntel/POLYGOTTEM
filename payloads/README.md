# Payloads Directory

## Overview

This directory is where you place files for the interactive file browser. No more typing full paths - just browse visually!

## Directory Structure

```
payloads/
├── carriers/          # Carrier files (PNG, PDF, MP3, etc.)
├── samples/           # Sample payloads and examples
├── custom/            # Your custom payloads
└── README.md          # This file
```

## Usage

### 1. Add Carrier Files

Place carrier files in `carriers/`:

```bash
# Copy your carrier files
cp my_image.png payloads/carriers/
cp my_document.pdf payloads/carriers/
cp my_audio.mp3 payloads/carriers/
```

**Supported carrier types:**
- **Images:** PNG, JPEG, GIF, WebP, TIFF, BMP, ICO
- **Documents:** PDF, DOC, DOCX, RTF, ODT
- **Audio:** MP3, WAV, FLAC, OGG, M4A, AAC
- **Video:** MP4, AVI, MKV, MOV, WMV, FLV
- **Any file type works!**

### 2. Add Payload Files

Place payload files anywhere in the payloads/ directory:

```bash
# Shellcode
cp shellcode.bin payloads/custom/

# Scripts
cp payload.sh payloads/custom/
cp payload.py payloads/custom/
cp payload.ps1 payloads/custom/

# Executables
cp malware.exe payloads/custom/
cp backdoor.elf payloads/custom/
```

### 3. Organize As You Like

Create subdirectories for organization:

```bash
# Organize by project
mkdir -p payloads/project-alpha/carriers
mkdir -p payloads/project-alpha/payloads

# Organize by file type
mkdir -p payloads/images
mkdir -p payloads/documents
mkdir -p payloads/executables

# Organize by CVE
mkdir -p payloads/cve-2023-4863
mkdir -p payloads/cve-2024-10573
```

## Sample Files

### Generate Samples

The file browser will automatically offer to create sample files if the directory is empty.

Or create them manually:

```bash
# Run sample generator
python tools/file_browser.py
```

### Sample Structure

```
payloads/samples/
├── carriers/
│   ├── sample_image.png     # 1x1 PNG image
│   └── sample_document.pdf  # Minimal PDF
└── payloads/
    ├── sample_shellcode.bin # NOP sled + INT3
    └── sample_payload.sh    # Echo script
```

## File Browser Features

When you use the interactive file browser:

### Visual Icons

- 🖼️ Images
- 📄 Documents
- ⚙️ Executables
- 📝 Scripts
- 🎵 Audio
- 🎬 Video
- 📦 Archives

### File Information

For each file, you'll see:
- **Icon** - Visual file type indicator
- **Filename** - Name with extension
- **Size** - Human-readable (KB, MB, GB)
- **Modified** - Last modification date/time

### Navigation

- **Folders** - Navigate into directories
- **Parent (..)** - Go up one level
- **Multi-select** - Select multiple files at once
- **Filter** - Filter by file type
- **Recent** - Recently selected files marked

### Example Display

```
Current Selection:
  1. [ ] 🖼️ carrier_image.png (45.3KB)
      Modified: 2025-11-11 10:30

  2. [✓] 📄 carrier_document.pdf (123.7KB)
      Modified: 2025-11-10 15:45

  3. [ ] 📁 project-alpha/
      Modified: 2025-11-09 09:20

Navigation: Number = Select | Enter = Confirm | Space = Toggle
```

## Tips

### Naming Conventions

Use descriptive names:

```bash
# Good
carrier_webp_critical.png
payload_reverse_shell.bin
exploit_cve-2023-4863.sh

# Avoid
file.png
test.bin
payload.sh
```

### Organization

Keep related files together:

```bash
payloads/
└── attack-campaign-2025/
    ├── carriers/
    │   ├── benign_image.png
    │   └── document.pdf
    └── payloads/
        ├── stage1.sh
        ├── stage2.py
        └── persistence.ps1
```

### Security

**DON'T commit actual malware to git:**

```bash
# Add to .gitignore
echo "payloads/custom/*" >> .gitignore
echo "!payloads/custom/README.md" >> .gitignore
```

**Keep samples safe:**

```bash
# Use encrypted storage
zip -e sensitive_payloads.zip payloads/custom/*

# Or use separate secure storage
mv payloads/custom/* /secure/storage/
ln -s /secure/storage/ payloads/custom
```

## Quick Examples

### Example 1: Image Polyglot

```bash
# 1. Add carrier image
cp logo.png payloads/carriers/

# 2. Add shellcode
cp reverse_shell.bin payloads/custom/

# 3. Launch orchestrator
python tools/polyglot_orchestrator_enhanced.py

# 4. In the UI:
#    - Step 1: Browse and select logo.png
#    - Step 2: Browse and select reverse_shell.bin
#    - Continue through workflow...
```

### Example 2: PDF with Commands

```bash
# 1. Add carrier PDF
cp report.pdf payloads/carriers/

# 2. Launch orchestrator
python tools/polyglot_orchestrator_enhanced.py

# 3. In the UI:
#    - Step 1: Browse and select report.pdf
#    - Step 2: Select "Command" as payload source
#    - Step 2b: Choose OS-specific commands
#    - Continue through workflow...
```

### Example 3: Multiple Carriers

```bash
# Add multiple carriers
cp image1.png payloads/carriers/
cp image2.jpg payloads/carriers/
cp doc.pdf payloads/carriers/
cp audio.mp3 payloads/carriers/

# Test each carrier type through the file browser
```

## File Type Reference

### Images

| Extension | MIME Type | Usage |
|-----------|-----------|-------|
| .png      | image/png | Common, lossless |
| .jpg, .jpeg | image/jpeg | Common, lossy |
| .gif      | image/gif | Animated support |
| .webp     | image/webp | Modern format |
| .tiff, .tif | image/tiff | Professional |
| .bmp      | image/bmp | Windows native |

### Documents

| Extension | MIME Type | Usage |
|-----------|-----------|-------|
| .pdf      | application/pdf | Universal |
| .doc      | application/msword | Legacy Office |
| .docx     | application/vnd.openxmlformats... | Modern Office |
| .rtf      | application/rtf | Cross-platform |
| .odt      | application/vnd.oasis... | LibreOffice |

### Executables

| Extension | Platform | Usage |
|-----------|----------|-------|
| .exe, .dll | Windows | Native executables |
| .elf, .so | Linux | Native executables |
| .app, .dylib | macOS | Native executables |
| .jar      | Cross-platform | Java applications |

### Scripts

| Extension | Interpreter | Usage |
|-----------|-------------|-------|
| .sh, .bash | Bash | Linux/macOS |
| .py       | Python | Cross-platform |
| .ps1      | PowerShell | Windows |
| .vbs      | VBScript | Windows |
| .js       | JavaScript | Cross-platform |

## Troubleshooting

### Issue: File browser shows empty

**Solution:**
```bash
# Check directory exists
ls -la payloads/

# Create if missing
mkdir -p payloads/carriers payloads/samples payloads/custom

# Add files
cp some_file.png payloads/carriers/

# Or generate samples
python tools/file_browser.py
```

### Issue: File not showing up

**Solution:**
```bash
# Verify file is in payloads/ or subdirectory
find payloads/ -name "filename.*"

# Check file permissions
ls -l payloads/filename.ext

# Refresh file browser (re-navigate)
```

### Issue: Can't select certain files

**Solution:**
```bash
# Check file type filter
# If filter is set to "images", only images will show

# Change filter to "all" to see all files

# Or navigate to correct filtered view
```

## Advanced

### Symbolic Links

Use symlinks to organize files:

```bash
# Link external directory
ln -s /path/to/external/payloads payloads/external

# Link specific file
ln -s ~/important_carrier.png payloads/carriers/carrier.png
```

### Automation

Generate payloads programmatically:

```python
from pathlib import Path

# Create payload
payload_dir = Path("payloads/custom")
payload_dir.mkdir(exist_ok=True)

shellcode = b'\x90' * 100 + b'\xcc'  # NOP sled + INT3
(payload_dir / "auto_generated.bin").write_bytes(shellcode)
```

### Batch Operations

Process multiple files:

```bash
# Convert all PNGs to JPEGs for testing
for f in payloads/carriers/*.png; do
    convert "$f" "${f%.png}.jpg"
done

# Generate shellcode variants
for size in 100 500 1000; do
    python -c "print('\\x90' * $size + '\\xcc')" > "payloads/custom/shellcode_${size}.bin"
done
```

## Security Best Practices

1. **Never commit real malware** to version control
2. **Use .gitignore** for custom payloads
3. **Encrypt sensitive files** when storing
4. **Use separate storage** for production payloads
5. **Clean up after testing** - don't leave payloads around
6. **Document everything** - keep notes on what each file does

## Need Help?

- **Documentation:** [POLISHED_WORKFLOW_GUIDE.md](../docs/POLISHED_WORKFLOW_GUIDE.md)
- **Interactive Tutorial:** Run `python tools/file_browser.py`
- **Examples:** See `payloads/samples/` directory

---

**Happy (authorized) testing!** 🎯

For educational and authorized security testing only.
