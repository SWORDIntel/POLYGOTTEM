#!/bin/bash
# POLYGOTTEM Launch Script
# Activates virtual environment and runs the application

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
VENV_DIR="venv"
MAIN_SCRIPT="polygottem.py"

# Print colored message
print_msg() {
    local color=$1
    shift
    echo -e "${color}$@${NC}"
}

# Check if virtual environment exists
if [ ! -d "$VENV_DIR" ]; then
    print_msg "$RED" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_msg "$RED" "  ERROR: Virtual environment not found!"
    print_msg "$RED" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo
    print_msg "$YELLOW" "Please run the installer first:"
    print_msg "$YELLOW" "  ./install.sh"
    echo
    print_msg "$YELLOW" "Or for Intel Meteor Lake optimization:"
    print_msg "$YELLOW" "  ./install.sh --intel"
    echo
    exit 1
fi

# Check if main script exists
if [ ! -f "$MAIN_SCRIPT" ]; then
    print_msg "$RED" "ERROR: $MAIN_SCRIPT not found!"
    exit 1
fi

# Activate virtual environment
source "$VENV_DIR/bin/activate"

# Handle special flags
BENCHMARK=false
SHOW_HELP=false

for arg in "$@"; do
    case $arg in
        --benchmark)
            BENCHMARK=true
            shift
            ;;
        --help|-h)
            SHOW_HELP=true
            shift
            ;;
    esac
done

# Run benchmark tests
if [ "$BENCHMARK" = true ]; then
    print_msg "$BLUE" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_msg "$BLUE" "  Running POLYGOTTEM Benchmark Tests"
    print_msg "$BLUE" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo

    # Check if benchmark tools exist
    if [ -f "tools/intel_acceleration.py" ]; then
        print_msg "$YELLOW" "Checking hardware acceleration..."
        python3 tools/intel_acceleration.py || true
        echo
    fi

    if [ -f "tools/exploit_header_generator.py" ]; then
        print_msg "$YELLOW" "Benchmarking exploit header generator..."
        python3 tools/exploit_header_generator.py --benchmark || true
        echo
    fi

    if [ -f "tools/multi_cve_polyglot.py" ]; then
        print_msg "$YELLOW" "Benchmarking multi-CVE polyglot generator..."
        python3 tools/multi_cve_polyglot.py --benchmark || true
        echo
    fi

    print_msg "$GREEN" "Benchmark tests completed!"
    exit 0
fi

# Show help
if [ "$SHOW_HELP" = true ]; then
    print_msg "$BLUE" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_msg "$BLUE" "  POLYGOTTEM - Polyglot Exploit Generator"
    print_msg "$BLUE" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo
    print_msg "$GREEN" "Usage:"
    print_msg "$GREEN" "  ./launch.sh [options]"
    echo
    print_msg "$YELLOW" "Options:"
    print_msg "$YELLOW" "  --help, -h       Show this help message"
    print_msg "$YELLOW" "  --benchmark      Run benchmark tests"
    echo
    print_msg "$YELLOW" "Examples:"
    print_msg "$YELLOW" "  ./launch.sh                  # Launch POLYGOTTEM TUI"
    print_msg "$YELLOW" "  ./launch.sh --benchmark      # Run performance tests"
    print_msg "$YELLOW" "  ./launch.sh --help           # Show this help"
    echo
    print_msg "$BLUE" "Documentation:"
    print_msg "$BLUE" "  See docs/guides/ for detailed documentation"
    echo
    exit 0
fi

# Launch the main application
print_msg "$BLUE" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
print_msg "$BLUE" "  Launching POLYGOTTEM..."
print_msg "$BLUE" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

# Run the main script with all remaining arguments
python3 "$MAIN_SCRIPT" "$@"
