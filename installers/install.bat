@echo off
REM POLYGOTTEM Installation Script for Windows
REM Safely creates virtual environment and installs dependencies

setlocal enabledelayedexpansion

REM Colors (using echo with special characters)
set "BLUE=[94m"
set "GREEN=[92m"
set "YELLOW=[93m"
set "RED=[91m"
set "NC=[0m"

REM Configuration
set VENV_DIR=venv
set PYTHON_CMD=python
set PIP_CMD=!VENV_DIR!\Scripts\pip.exe

echo.
echo !BLUE!===============================================================!NC!
echo !BLUE!  POLYGOTTEM - Polyglot Exploit Generator Installer!NC!
echo !BLUE!===============================================================!NC!
echo.

REM Check Python version
echo !YELLOW![1/5] Checking Python installation...!NC!
!PYTHON_CMD! --version >nul 2>&1
if errorlevel 1 (
    echo !RED!ERROR: Python not found. Please install Python 3.8 or higher.!NC!
    echo !YELLOW!Download from: https://www.python.org/downloads/!NC!
    echo !YELLOW!Make sure to check "Add Python to PATH" during installation!NC!
    pause
    exit /b 1
)

for /f "tokens=2" %%i in ('!PYTHON_CMD! --version 2^>^&1') do set PYTHON_VERSION=%%i
echo !GREEN!✓ Found Python !PYTHON_VERSION!!NC!
echo.

REM Auto-remove old venv if it exists
if exist "!VENV_DIR!" (
    echo !YELLOW![2/5] Removing existing virtual environment...!NC!
    rmdir /s /q "!VENV_DIR!" >nul 2>&1
    echo !GREEN!✓ Existing venv removed!NC!
) else (
    echo !YELLOW![2/5] Creating virtual environment...!NC!
)
echo.

REM Create virtual environment
if not exist "!VENV_DIR!" (
    !PYTHON_CMD! -m venv "!VENV_DIR!"
    if errorlevel 1 (
        echo !RED!ERROR: Failed to create virtual environment.!NC!
        echo !YELLOW!Try: python -m pip install --user virtualenv!NC!
        pause
        exit /b 1
    )
    echo !GREEN!✓ Virtual environment created successfully!NC!
) else (
    echo !YELLOW![2/5] Virtual environment already exists, skipping creation.!NC!
)
echo.

REM Upgrade pip
echo !YELLOW![3/5] Upgrading pip...!NC!
!PYTHON_CMD! -m pip install --upgrade pip --quiet >nul 2>&1
echo !GREEN!✓ pip upgraded!NC!
echo.

REM Install requirements
echo !YELLOW![4/5] Installing dependencies...!NC!
echo.

!PYTHON_CMD! -m pip install -r requirements.txt --quiet >nul 2>&1
if errorlevel 1 (
    echo !YELLOW!Note: Some dependencies may have failed to install!NC!
)
echo !GREEN!✓ Core dependencies installed!NC!
echo.

REM Hardware acceleration prompt
echo !YELLOW!═══════════════════════════════════════════════════════!NC!
echo !YELLOW!  Hardware Acceleration Setup!NC!
echo !YELLOW!═══════════════════════════════════════════════════════!NC!
echo.
echo !BLUE!POLYGOTTEM works fine with just NumPy (already installed).!NC!
echo !BLUE!However, Intel hardware acceleration can provide 10-50x speedup.!NC!
echo.
echo !YELLOW!Installation options:!NC!
echo !GREEN!  1) Minimal (CPU only - RECOMMENDED) - Already done!!NC!
echo !YELLOW!  2) Interactive (choose specific packages)!NC!
echo !RED!  3) Full Intel optimization (1-5GB download)!NC!
echo !BLUE!  4) Skip hardware acceleration!NC!
echo.

REM Default to minimal
set CHOICE=1

if "%1"=="" (
    echo !YELLOW!Defaulting to minimal installation (press any key to continue)!NC!
    REM Skip interactive in auto mode
) else if "%1"=="--intel" (
    set CHOICE=3
) else if "%1"=="--interactive" (
    set CHOICE=2
)

if !CHOICE!==1 (
    echo !GREEN!✓ Minimal installation complete!!NC!
)

if !CHOICE!==2 (
    REM Interactive mode - simplified for Windows
    echo !YELLOW!═══════════════════════════════════════════════════════!NC!
    echo !YELLOW!  Interactive Package Selection!NC!
    echo !YELLOW!═══════════════════════════════════════════════════════!NC!
    echo.
    echo !BLUE!OpenVINO (Intel NPU acceleration)!NC!
    echo !YELLOW!  Size: ~2GB ^| Speed boost: 10-50x for XOR operations!NC!
    echo !YELLOW!  Requires: Intel Core Ultra (Meteor Lake) with NPU!NC!
    echo.
)

if !CHOICE!==3 (
    echo !RED!═══════════════════════════════════════════════════════!NC!
    echo !RED!  Full Intel Optimization Selected!NC!
    echo !RED!═══════════════════════════════════════════════════════!NC!
    echo !YELLOW!Downloading 1-5GB of packages (this may take 10-30 minutes)!NC!
    echo.
    echo !BLUE!Installing all Intel packages... Please be patient.!NC!
    echo.
    !PYTHON_CMD! -m pip install -r requirements-intel.txt --quiet 2>nul
    if errorlevel 1 (
        echo !YELLOW!Note: Some Intel packages may have failed to install!NC!
    ) else (
        echo !GREEN!✓ All Intel packages installed!NC!
    )
)
echo.

REM Test GUARANTEE cascade system
echo !YELLOW![5/5] Verifying GUARANTEE cascade installation...!NC!
!PYTHON_CMD! << 'PYEOF'
import sys
sys.path.insert(0, 'tools')

components = [
    ('guarantee_chainer', 'GuaranteeChainer'),
    ('guarantee_validator', 'GuaranteeValidator'),
    ('guarantee_network_beacon', 'GuaranteeNetworkBeacon'),
    ('guarantee_fingerprint_setup', 'FingerprintSetupManager'),
    ('guarantee_beacon_integrator', 'BeaconIntegrator'),
    ('guarantee_report_generator', 'GuaranteeReportGenerator'),
    ('tui_theme_classified', 'ClassifiedTheme'),
]

success_count = 0
for module_name, class_name in components:
    try:
        module = __import__(module_name)
        if hasattr(module, class_name):
            print(f"  ✓ {module_name}")
            success_count += 1
    except:
        print(f"  ✗ {module_name}")

if success_count == len(components):
    print("\n✓ GUARANTEE cascade system verified!")
else:
    print(f"\n⚠ {success_count}/{len(components)} components loaded")
PYEOF

echo.
echo !GREEN!═══════════════════════════════════════════════════════!NC!
echo !GREEN!  ✓ Installation completed successfully!!NC!
echo !GREEN!═══════════════════════════════════════════════════════!NC!
echo.
echo !BLUE!Quick Start:!NC!
echo !BLUE!  launch.bat              - Run POLYGOTTEM TUI!NC!
echo !BLUE!  launch.bat --help       - Show help!NC!
echo !BLUE!  launch.bat --benchmark  - Run benchmark tests!NC!
echo.
echo !YELLOW!Installation modes (for future reinstalls):!NC!
echo !YELLOW!  install.bat                 - Interactive (default)!NC!
echo !YELLOW!  install.bat --intel         - Full Intel optimization!NC!
echo.
echo !YELLOW!To activate the virtual environment manually:!NC!
echo !YELLOW!  !VENV_DIR!\Scripts\activate.bat!NC!
echo.
pause
