#!/bin/bash
# POLYGOTTEM Installation Script
# Safely creates virtual environment and installs dependencies

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
VENV_DIR="venv"
PYTHON_CMD="python3"

# Print colored message
print_msg() {
    local color=$1
    shift
    echo -e "${color}$@${NC}"
}

print_msg "$BLUE" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
print_msg "$BLUE" "  POLYGOTTEM - Polyglot Exploit Generator Installer"
print_msg "$BLUE" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

# Check Python version
print_msg "$YELLOW" "[1/5] Checking Python installation..."
if ! command -v $PYTHON_CMD &> /dev/null; then
    print_msg "$RED" "ERROR: Python 3 not found. Please install Python 3.8 or higher."
    exit 1
fi

PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
print_msg "$GREEN" "✓ Found Python $PYTHON_VERSION"
echo

# Check for tkinter (for file dialog support)
print_msg "$YELLOW" "[1.5/5] Checking for tkinter (file dialog support)..."
if ! $PYTHON_CMD -c "import tkinter" 2>/dev/null; then
    print_msg "$YELLOW" "⚠ tkinter not found - file dialogs will be unavailable"
    print_msg "$BLUE" "  To enable graphical file browsing, install tkinter:"
    if [ -f /etc/debian_version ]; then
        print_msg "$BLUE" "  sudo apt install python3-tk"
    elif [ -f /etc/redhat-release ]; then
        print_msg "$BLUE" "  sudo dnf install python3-tkinter"
    else
        print_msg "$BLUE" "  Install python3-tk or python3-tkinter for your distribution"
    fi
    echo
    read -p "$(echo -e ${YELLOW}Install tkinter now? [y/N]: ${NC})" -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [ -f /etc/debian_version ]; then
            print_msg "$BLUE" "Installing tkinter..."
            sudo apt install -y python3-tk && print_msg "$GREEN" "✓ tkinter installed" || print_msg "$YELLOW" "⚠ tkinter installation failed (needs sudo)"
        elif [ -f /etc/redhat-release ]; then
            print_msg "$BLUE" "Installing tkinter..."
            sudo dnf install -y python3-tkinter && print_msg "$GREEN" "✓ tkinter installed" || print_msg "$YELLOW" "⚠ tkinter installation failed (needs sudo)"
        else
            print_msg "$YELLOW" "Manual installation required for your distribution"
        fi
    else
        print_msg "$BLUE" "Skipping tkinter (file dialogs disabled, manual path entry will work)"
    fi
else
    print_msg "$GREEN" "✓ tkinter available - file dialogs enabled"
fi
echo

# Auto-overwrite venv if it exists
if [ -d "$VENV_DIR" ]; then
    print_msg "$YELLOW" "[2/5] Removing existing virtual environment..."
    rm -rf "$VENV_DIR"
    print_msg "$GREEN" "✓ Existing venv removed"
fi
echo

# Create virtual environment
if [ ! -d "$VENV_DIR" ]; then
    print_msg "$YELLOW" "[2/5] Creating virtual environment..."
    $PYTHON_CMD -m venv "$VENV_DIR"
    if [ $? -ne 0 ]; then
        print_msg "$RED" "ERROR: Failed to create virtual environment."
        print_msg "$YELLOW" "Try: sudo apt install python3-venv (Debian/Ubuntu)"
        print_msg "$YELLOW" "  or: sudo yum install python3-venv (RHEL/CentOS)"
        exit 1
    fi
    # Verify venv was created
    if [ ! -f "$VENV_DIR/bin/python" ]; then
        print_msg "$RED" "ERROR: venv creation failed - python binary not found"
        exit 1
    fi
    print_msg "$GREEN" "✓ Virtual environment created successfully"
else
    print_msg "$YELLOW" "[2/5] Virtual environment already exists, skipping creation."
fi
echo

# Use absolute paths to venv python/pip instead of sourcing activation
VENV_PYTHON="$VENV_DIR/bin/python"
VENV_PIP="$VENV_DIR/bin/pip"

# Upgrade pip using absolute path
print_msg "$YELLOW" "[3/5] Upgrading pip..."
$VENV_PYTHON -m pip install --upgrade pip --quiet
if [ $? -ne 0 ]; then
    print_msg "$RED" "ERROR: Failed to upgrade pip"
    exit 1
fi
print_msg "$GREEN" "✓ pip upgraded"
echo

# Install requirements
print_msg "$YELLOW" "[5/5] Installing dependencies..."
echo

# Parse command line arguments
AUTO_MODE=false
INTERACTIVE_MODE=false
INTEL_ALL=false

for arg in "$@"; do
    case $arg in
        --auto)
            AUTO_MODE=true
            ;;
        --interactive)
            INTERACTIVE_MODE=true
            ;;
        --intel)
            INTEL_ALL=true
            ;;
    esac
done

# Install core dependencies first
print_msg "$BLUE" "Installing core dependencies (NumPy)..."
$VENV_PIP install -r requirements.txt --quiet
print_msg "$GREEN" "✓ Core dependencies installed"
echo

# If no flags, prompt for installation mode
if [ "$AUTO_MODE" = false ] && [ "$INTEL_ALL" = false ] && [ "$INTERACTIVE_MODE" = false ]; then
    print_msg "$YELLOW" "═══════════════════════════════════════════════════════"
    print_msg "$YELLOW" "  Hardware Acceleration Setup"
    print_msg "$YELLOW" "═══════════════════════════════════════════════════════"
    echo
    print_msg "$BLUE" "POLYGOTTEM works fine with just NumPy (already installed)."
    print_msg "$BLUE" "However, Intel hardware acceleration can provide 10-50x speedup."
    echo
    print_msg "$YELLOW" "Installation options:"
    print_msg "$GREEN" "  1) Minimal (CPU only - RECOMMENDED) - Already done!"
    print_msg "$YELLOW" "  2) Interactive (choose specific packages)"
    print_msg "$RED" "  3) Full Intel optimization (1-5GB download)"
    print_msg "$BLUE" "  4) Skip hardware acceleration"
    echo
    read -p "$(echo -e ${YELLOW}Choose option [1-4]: ${NC})" -n 1 -r CHOICE
    echo
    echo

    case $CHOICE in
        1)
            print_msg "$GREEN" "✓ Minimal installation complete!"
            ;;
        2)
            INTERACTIVE_MODE=true
            ;;
        3)
            INTEL_ALL=true
            ;;
        4)
            print_msg "$BLUE" "Skipping hardware acceleration."
            ;;
        *)
            print_msg "$YELLOW" "Invalid choice. Using minimal installation."
            ;;
    esac
fi

# Function to check if package is available (system or pip)
check_package() {
    $VENV_PYTHON -c "import $1" 2>/dev/null
    return $?
}

# Interactive mode - let user pick packages
if [ "$INTERACTIVE_MODE" = true ]; then
    print_msg "$YELLOW" "═══════════════════════════════════════════════════════"
    print_msg "$YELLOW" "  Interactive Package Selection"
    print_msg "$YELLOW" "═══════════════════════════════════════════════════════"
    echo

    # OpenVINO
    print_msg "$BLUE" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_msg "$BLUE" "Package: OpenVINO (Intel NPU acceleration)"
    if check_package "openvino"; then
        print_msg "$GREEN" "  ✓ Already available (system or venv installation)"
        print_msg "$YELLOW" "  Using existing installation."
    else
        print_msg "$YELLOW" "  Size: ~2GB | Speed boost: 10-50x for XOR operations"
        print_msg "$YELLOW" "  Requires: Intel Core Ultra (Meteor Lake) with NPU"
        read -p "$(echo -e ${YELLOW}Install OpenVINO? [y/N]: ${NC})" -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_msg "$BLUE" "Installing OpenVINO... (this may take 5-10 minutes)"
            $VENV_PIP install "openvino>=2024.0.0" --quiet && print_msg "$GREEN" "✓ OpenVINO installed" || print_msg "$RED" "✗ OpenVINO installation failed"
        fi
    fi
    echo

    # Intel Level Zero (SYSTEM PACKAGE - not on PyPI)
    print_msg "$BLUE" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_msg "$BLUE" "Package: Intel Level Zero (GPU acceleration)"
    print_msg "$YELLOW" "  NOTE: Level Zero is a SYSTEM package (not on PyPI)"
    print_msg "$YELLOW" "  Speed boost: 5-20x for parallel ops"
    print_msg "$YELLOW" "  Requires: Intel Arc GPU or Iris Xe Graphics"
    echo
    if [ -f /etc/debian_version ]; then
        print_msg "$BLUE" "  Install command: sudo apt install intel-level-zero-gpu level-zero"
    elif [ -f /etc/redhat-release ]; then
        print_msg "$BLUE" "  Install command: sudo dnf install level-zero"
    fi
    read -p "$(echo -e ${YELLOW}Install Level Zero system package now? [y/N]: ${NC})" -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [ -f /etc/debian_version ]; then
            print_msg "$BLUE" "Installing Level Zero..."
            sudo apt install -y intel-level-zero-gpu level-zero && print_msg "$GREEN" "✓ Level Zero installed" || print_msg "$YELLOW" "⚠ Level Zero installation failed (needs Intel GPU repo)"
        elif [ -f /etc/redhat-release ]; then
            print_msg "$BLUE" "Installing Level Zero..."
            sudo dnf install -y level-zero && print_msg "$GREEN" "✓ Level Zero installed" || print_msg "$YELLOW" "⚠ Level Zero installation failed (needs Intel GPU repo)"
        else
            print_msg "$YELLOW" "Manual installation required for your distribution"
        fi
    else
        print_msg "$BLUE" "Skipping Level Zero (PyOpenCL will work without it)"
    fi
    echo

    # PyOpenCL
    print_msg "$BLUE" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_msg "$BLUE" "Package: PyOpenCL (Generic GPU acceleration)"
    if check_package "pyopencl"; then
        print_msg "$GREEN" "  ✓ Already available (system or venv installation)"
        print_msg "$YELLOW" "  Using existing installation."
    else
        print_msg "$YELLOW" "  Size: ~50MB | Speed boost: 3-15x for operations"
        print_msg "$YELLOW" "  Requires: Any OpenCL-compatible GPU (Intel/NVIDIA/AMD)"
        read -p "$(echo -e ${YELLOW}Install PyOpenCL? [y/N]: ${NC})" -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_msg "$BLUE" "Installing PyOpenCL..."
            $VENV_PIP install "pyopencl>=2024.1" --quiet && print_msg "$GREEN" "✓ PyOpenCL installed" || print_msg "$RED" "✗ PyOpenCL installation failed"
        fi
    fi
    echo

    # Intel Extension for Scikit-learn
    print_msg "$BLUE" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_msg "$BLUE" "Package: Intel Extension for Scikit-learn"
    if check_package "sklearnex"; then
        print_msg "$GREEN" "  ✓ Already available (system or venv installation)"
        print_msg "$YELLOW" "  Using existing installation."
    else
        print_msg "$YELLOW" "  Size: ~200MB | Speed boost: 2-5x for NumPy/SciPy operations"
        print_msg "$YELLOW" "  Requires: Intel CPU (any generation)"
        read -p "$(echo -e ${YELLOW}Install Intel Extension for Scikit-learn? [y/N]: ${NC})" -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_msg "$BLUE" "Installing Intel Extension for Scikit-learn..."
            $VENV_PIP install "scikit-learn-intelex>=2024.0" --quiet && print_msg "$GREEN" "✓ Intel Extension for Scikit-learn installed" || print_msg "$RED" "✗ Installation failed"
        fi
    fi
    echo

    # Neural Compressor
    print_msg "$BLUE" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_msg "$BLUE" "Package: Intel Neural Compressor"
    if check_package "neural_compressor"; then
        print_msg "$GREEN" "  ✓ Already available (system or venv installation)"
        print_msg "$YELLOW" "  Using existing installation."
    else
        print_msg "$YELLOW" "  Size: ~1GB | Speed boost: Model optimization for NPU"
        print_msg "$YELLOW" "  Requires: Intel Core Ultra with NPU"
        read -p "$(echo -e ${YELLOW}Install Neural Compressor? [y/N]: ${NC})" -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_msg "$BLUE" "Installing Neural Compressor... (this may take 5-10 minutes)"
            $VENV_PIP install "neural-compressor>=2.5" --quiet && print_msg "$GREEN" "✓ Neural Compressor installed" || print_msg "$RED" "✗ Installation failed"
        fi
    fi
    echo
fi

# Full Intel installation
if [ "$INTEL_ALL" = true ]; then
    print_msg "$RED" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_msg "$RED" "  Full Intel Optimization Selected"
    print_msg "$RED" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_msg "$YELLOW" "Downloading 1-5GB of packages (this may take 10-30 minutes)"
    print_msg "$YELLOW" "Packages: OpenVINO, PyOpenCL, Intel Scikit-learn Extension, Neural Compressor"
    print_msg "$BLUE" "Note: Level Zero must be installed separately as a system package"
    echo
    print_msg "$BLUE" "Installing all Intel packages... Please be patient."
    $VENV_PIP install -r requirements-intel.txt && print_msg "$GREEN" "✓ All Intel packages installed" || print_msg "$RED" "✗ Some packages failed"
fi
echo

# Success message
print_msg "$GREEN" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
print_msg "$GREEN" "  ✓ Installation completed successfully!"
print_msg "$GREEN" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
print_msg "$BLUE" "Quick Start:"
print_msg "$BLUE" "  ./launch.sh              - Run POLYGOTTEM TUI"
print_msg "$BLUE" "  ./launch.sh --help       - Show help"
print_msg "$BLUE" "  ./launch.sh --benchmark  - Run benchmark tests"
echo
print_msg "$YELLOW" "Installation modes (for future reinstalls):"
print_msg "$YELLOW" "  ./install.sh                 - Interactive (default)"
print_msg "$YELLOW" "  ./install.sh --auto          - Minimal install (no prompts)"
print_msg "$YELLOW" "  ./install.sh --interactive   - Choose packages individually"
print_msg "$YELLOW" "  ./install.sh --intel         - Full Intel optimization"
echo
print_msg "$YELLOW" "To activate the virtual environment manually:"
print_msg "$YELLOW" "  source venv/bin/activate"
echo

# Test GUARANTEE cascade system
print_msg "$BLUE" "Testing GUARANTEE cascade system..."
$VENV_PYTHON << 'TESTEOF'
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
            success_count += 1
    except:
        pass

if success_count == len(components):
    print("✓ GUARANTEE cascade system verified!")
else:
    print(f"⚠ {success_count}/{len(components)} components loaded")
TESTEOF

echo
