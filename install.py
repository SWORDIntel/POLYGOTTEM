#!/usr/bin/env python3
"""
POLYGOTTEM Universal Installer
Detects OS and runs appropriate installation script
"""

import os
import sys
import platform
import subprocess
from pathlib import Path

def print_banner():
    """Print installation banner"""
    print("\n" + "=" * 63)
    print("  POLYGOTTEM - Polyglot Exploit Generator Installer")
    print("=" * 63 + "\n")

def detect_os():
    """Detect operating system"""
    system = platform.system()
    return system.lower()

def run_windows_installer():
    """Run Windows installer"""
    installer_path = Path(__file__).parent / "installers" / "install.bat"

    if not installer_path.exists():
        print(f"❌ ERROR: Windows installer not found at {installer_path}")
        print("   Please ensure 'installers/install.bat' exists")
        return False

    print("🪟 Detected Windows system")
    print(f"📂 Running installer: {installer_path}")
    print()

    try:
        # Run the batch file
        if sys.platform == "win32":
            os.system(str(installer_path))
            return True
        else:
            print("❌ ERROR: Windows installer detected but running on non-Windows system")
            return False
    except Exception as e:
        print(f"❌ ERROR: Failed to run installer: {e}")
        return False

def run_unix_installer():
    """Run Unix/Linux/macOS installer"""
    installer_path = Path(__file__).parent / "installers" / "install.sh"

    if not installer_path.exists():
        print(f"❌ ERROR: Unix installer not found at {installer_path}")
        print("   Please ensure 'installers/install.sh' exists")
        return False

    system = platform.system()
    if system == "Darwin":
        print("🍎 Detected macOS system")
    else:
        print("🐧 Detected Linux system")

    print(f"📂 Running installer: {installer_path}")
    print()

    try:
        # Make executable and run
        os.chmod(installer_path, 0o755)
        result = subprocess.run(
            ["bash", str(installer_path)] + sys.argv[1:],
            check=False
        )
        return result.returncode == 0
    except Exception as e:
        print(f"❌ ERROR: Failed to run installer: {e}")
        return False

def main():
    """Main installer dispatcher"""
    print_banner()

    system = detect_os()

    if system == "windows":
        success = run_windows_installer()
    elif system in ("linux", "darwin"):
        success = run_unix_installer()
    else:
        print(f"❌ ERROR: Unsupported operating system: {system}")
        print("   Supported: Windows, Linux, macOS")
        return 1

    if success:
        print("\n" + "=" * 63)
        print("  ✓ Installation completed successfully!")
        print("=" * 63)
        print("\n📚 Next steps:")
        print("   • ./launch.py              (Launch POLYGOTTEM)")
        print("   • ./polygottem.py --help   (Show help)")
        print()
        return 0
    else:
        print("\n" + "=" * 63)
        print("  ❌ Installation encountered an error")
        print("=" * 63)
        return 1

if __name__ == "__main__":
    sys.exit(main())
