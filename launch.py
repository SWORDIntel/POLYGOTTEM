#!/usr/bin/env python3
"""
POLYGOTTEM Universal Launcher
Detects OS and runs appropriate launch script/command
"""

import os
import sys
import platform
import subprocess
from pathlib import Path

def detect_os():
    """Detect operating system"""
    return platform.system().lower()

def launch_windows():
    """Launch on Windows"""
    launcher_path = Path(__file__).parent / "launch.bat"

    if not launcher_path.exists():
        print(f"❌ ERROR: Windows launcher not found at {launcher_path}")
        return False

    try:
        # On Windows, directly execute the batch file
        if sys.platform == "win32":
            # Pass all arguments to the batch file
            args = [str(launcher_path)] + sys.argv[1:]
            os.system(" ".join(args))
            return True
        else:
            print("❌ ERROR: Windows launcher detected but running on non-Windows system")
            return False
    except Exception as e:
        print(f"❌ ERROR: Failed to launch: {e}")
        return False

def launch_unix():
    """Launch on Unix/Linux/macOS"""
    launcher_path = Path(__file__).parent / "launch.sh"

    if not launcher_path.exists():
        print(f"❌ ERROR: Unix launcher not found at {launcher_path}")
        return False

    try:
        # Make executable and run
        os.chmod(launcher_path, 0o755)
        result = subprocess.run(
            ["bash", str(launcher_path)] + sys.argv[1:],
            check=False
        )
        return result.returncode == 0
    except Exception as e:
        print(f"❌ ERROR: Failed to launch: {e}")
        return False

def main():
    """Main launcher dispatcher"""
    system = detect_os()

    if system == "windows":
        return 0 if launch_windows() else 1
    elif system in ("linux", "darwin"):
        return 0 if launch_unix() else 1
    else:
        print(f"❌ ERROR: Unsupported operating system: {system}")
        print("   Supported: Windows, Linux, macOS")
        return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Installation cancelled by user")
        sys.exit(130)
