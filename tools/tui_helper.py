#!/usr/bin/env python3
"""
TUI Helper Module for POLYGOTTEM
=================================
Provides Terminal User Interface utilities including colors, progress bars,
status symbols, and formatted output.

Author: SWORDIntel
Date: 2025-11-10
"""

import sys
import time
import shutil
from typing import Optional


class Colors:
    """ANSI color codes for terminal output"""
    # Basic colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

    # Bright colors
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'

    # Styles
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'

    # Reset
    RESET = '\033[0m'

    # Background colors
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'

    # TEMPEST Level C colors
    TEMPEST_AMBER = '\033[38;5;214m'  # Amber for EMSEC warnings
    TEMPEST_ORANGE = '\033[38;5;208m'  # Orange for classification
    TEMPEST_RED = '\033[38;5;196m'  # Bright red for critical EMSEC


class Symbols:
    """Unicode symbols for status indicators"""
    SUCCESS = '✓'
    FAILURE = '✗'
    WARNING = '⚠'
    INFO = 'ℹ'
    ARROW = '→'
    BULLET = '•'
    STAR = '★'
    HOURGLASS = '⌛'
    GEAR = '⚙'
    LOCK = '🔒'
    UNLOCK = '🔓'
    FIRE = '🔥'
    TARGET = '🎯'
    BOMB = '💣'
    SKULL = '☠'
    SHIELD = '🛡'

    # TEMPEST Level C symbols
    RADIATION = '☢'  # Electromagnetic emission warning
    WAVE = '〰'  # Signal emanation
    CLASSIFIED = '🔐'  # Classification marking
    EMSEC = '📡'  # EMSEC/SIGINT warning
    ALERT = '🚨'  # Critical TEMPEST alert


class TUI:
    """Terminal User Interface helper class with TEMPEST Level C theming"""

    def __init__(self, use_colors: bool = True, tempest_mode: bool = True):
        """
        Initialize TUI helper

        Args:
            use_colors: Enable/disable ANSI colors (auto-detect if stdout is TTY)
            tempest_mode: Enable TEMPEST Level C security markings and warnings
        """
        self.use_colors = use_colors and sys.stdout.isatty()
        self.colors = Colors()
        self.symbols = Symbols()
        self.terminal_width = self._get_terminal_width()
        self.tempest_mode = tempest_mode
        self.tempest_level = "C"  # TEMPEST Level C (Uncontrolled but sensitive)
        self.classification = "CLASSIFIED"  # Security classification

    def _get_terminal_width(self) -> int:
        """Get terminal width, default to 80 if not detectable"""
        try:
            return shutil.get_terminal_size().columns
        except Exception:
            return 80

    def colorize(self, text: str, color: str, bold: bool = False) -> str:
        """
        Colorize text with ANSI codes

        Args:
            text: Text to colorize
            color: Color code from Colors class
            bold: Apply bold style

        Returns:
            Colorized text or plain text if colors disabled
        """
        if not self.use_colors:
            return text

        prefix = f"{self.colors.BOLD}{color}" if bold else color
        return f"{prefix}{text}{self.colors.RESET}"

    def success(self, message: str, prefix: str = ""):
        """Print success message in green with ✓ symbol"""
        symbol = self.colorize(self.symbols.SUCCESS, self.colors.GREEN)
        msg = self.colorize(message, self.colors.GREEN)
        print(f"{prefix}{symbol} {msg}")

    def error(self, message: str, prefix: str = ""):
        """Print error message in red with ✗ symbol"""
        symbol = self.colorize(self.symbols.FAILURE, self.colors.RED)
        msg = self.colorize(message, self.colors.RED, bold=True)
        print(f"{prefix}{symbol} {msg}")

    def warning(self, message: str, prefix: str = ""):
        """Print warning message in yellow with ⚠ symbol"""
        symbol = self.colorize(self.symbols.WARNING, self.colors.YELLOW)
        msg = self.colorize(message, self.colors.YELLOW)
        print(f"{prefix}{symbol} {msg}")

    def info(self, message: str, prefix: str = ""):
        """Print info message in blue with ℹ symbol"""
        symbol = self.colorize(self.symbols.INFO, self.colors.BLUE)
        msg = self.colorize(message, self.colors.CYAN)
        print(f"{prefix}{symbol} {msg}")

    def header(self, text: str, char: str = "="):
        """Print formatted header"""
        line = char * len(text)
        print()
        print(self.colorize(line, self.colors.CYAN, bold=True))
        print(self.colorize(text, self.colors.CYAN, bold=True))
        print(self.colorize(line, self.colors.CYAN, bold=True))
        print()

    def section(self, text: str, char: str = "-"):
        """Print section divider"""
        print()
        print(self.colorize(f"─── {text} " + "─" * (self.terminal_width - len(text) - 5),
                          self.colors.BLUE))

    def box(self, title: str, content: list, width: Optional[int] = None):
        """
        Print content in a box

        Args:
            title: Box title
            content: List of lines to display
            width: Box width (auto if None)
        """
        if width is None:
            width = min(self.terminal_width - 4, 80)

        # Top border
        print(self.colorize("┌" + "─" * (width - 2) + "┐", self.colors.CYAN))

        # Title
        title_pad = width - len(title) - 4
        print(self.colorize(f"│ {title}" + " " * title_pad + "│",
                          self.colors.CYAN, bold=True))
        print(self.colorize("├" + "─" * (width - 2) + "┤", self.colors.CYAN))

        # Content
        for line in content:
            # Strip ANSI codes for length calculation
            clean_line = self._strip_ansi(line)
            pad = width - len(clean_line) - 4
            print(self.colorize("│ ", self.colors.CYAN) + line + " " * pad +
                  self.colorize(" │", self.colors.CYAN))

        # Bottom border
        print(self.colorize("└" + "─" * (width - 2) + "┘", self.colors.CYAN))

    def _strip_ansi(self, text: str) -> str:
        """Strip ANSI codes from text for length calculation"""
        import re
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)

    def table(self, headers: list, rows: list, column_widths: Optional[list] = None):
        """
        Print formatted table

        Args:
            headers: List of column headers
            rows: List of row data (list of lists)
            column_widths: Optional list of column widths
        """
        if not column_widths:
            # Auto-calculate column widths
            column_widths = [len(h) for h in headers]
            for row in rows:
                for i, cell in enumerate(row):
                    column_widths[i] = max(column_widths[i], len(str(cell)))

        # Add padding
        column_widths = [w + 2 for w in column_widths]

        # Top border
        print(self.colorize("┌" + "┬".join("─" * w for w in column_widths) + "┐",
                          self.colors.CYAN))

        # Headers
        header_line = "│"
        for i, header in enumerate(headers):
            header_line += self.colorize(f" {header:<{column_widths[i]-1}}",
                                        self.colors.CYAN, bold=True) + "│"
        print(header_line)

        # Separator
        print(self.colorize("├" + "┼".join("─" * w for w in column_widths) + "┤",
                          self.colors.CYAN))

        # Rows
        for row in rows:
            row_line = self.colorize("│", self.colors.CYAN)
            for i, cell in enumerate(row):
                row_line += f" {str(cell):<{column_widths[i]-1}}" + \
                           self.colorize("│", self.colors.CYAN)
            print(row_line)

        # Bottom border
        print(self.colorize("└" + "┴".join("─" * w for w in column_widths) + "┘",
                          self.colors.CYAN))

    def progress_bar(self, current: int, total: int, prefix: str = "",
                    suffix: str = "", bar_length: int = 40):
        """
        Display progress bar

        Args:
            current: Current progress value
            total: Total value
            prefix: Text before progress bar
            suffix: Text after progress bar
            bar_length: Length of progress bar in characters
        """
        if total == 0:
            percent = 100
        else:
            percent = int(100 * current / total)

        filled = int(bar_length * current / total) if total > 0 else bar_length
        bar = '█' * filled + '░' * (bar_length - filled)

        # Color based on progress
        if percent < 33:
            color = self.colors.RED
        elif percent < 66:
            color = self.colors.YELLOW
        else:
            color = self.colors.GREEN

        bar_colored = self.colorize(bar, color)
        percent_str = self.colorize(f"{percent}%", color, bold=True)

        print(f"\r{prefix} {bar_colored} {percent_str} {suffix}", end='', flush=True)

        if current >= total:
            print()  # New line when complete

    def spinner(self, message: str = "Working", delay: float = 0.1):
        """
        Context manager for displaying spinner

        Usage:
            with tui.spinner("Processing"):
                # Do work here
                time.sleep(2)
        """
        return SpinnerContext(self, message, delay)

    def list_item(self, text: str, level: int = 0, symbol: str = None):
        """
        Print list item with optional indentation

        Args:
            text: Item text
            level: Indentation level
            symbol: Custom symbol (default: bullet)
        """
        indent = "  " * level
        sym = symbol if symbol else self.symbols.BULLET
        sym_colored = self.colorize(sym, self.colors.CYAN)
        print(f"{indent}{sym_colored} {text}")

    def key_value(self, key: str, value: str, key_width: int = 20):
        """
        Print key-value pair with alignment

        Args:
            key: Key name
            value: Value
            key_width: Width for key column
        """
        key_colored = self.colorize(f"{key}:", self.colors.CYAN, bold=True)
        print(f"  {key_colored:<{key_width}} {value}")

    def critical(self, message: str):
        """Print critical message with special formatting"""
        symbol = self.colorize(self.symbols.FIRE, self.colors.RED)
        msg = self.colorize(message, self.colors.RED, bold=True)
        bg = self.colorize("", self.colors.BG_RED)
        print(f"{symbol} {bg}{msg}{self.colors.RESET}")

    def banner(self, title: str, subtitle: str = "", width: Optional[int] = None):
        """
        Print banner with title and optional subtitle (TEMPEST Level C themed)

        Args:
            title: Main title
            subtitle: Optional subtitle
            width: Banner width (auto if None)
        """
        if width is None:
            width = min(self.terminal_width, 80)

        # TEMPEST Level C classification header
        if self.tempest_mode:
            tempest_header = f"{self.symbols.RADIATION} TEMPEST LEVEL {self.tempest_level} - {self.classification} {self.symbols.RADIATION}"
            tempest_pad = (width - len(tempest_header) - 2) // 2

            print()
            print(self.colorize("=" * width, self.colors.TEMPEST_ORANGE, bold=True))
            print(self.colorize(" " * tempest_pad + tempest_header +
                              " " * (width - len(tempest_header) - tempest_pad),
                              self.colors.TEMPEST_ORANGE, bold=True))
            print(self.colorize("=" * width, self.colors.TEMPEST_ORANGE, bold=True))

        print()
        print(self.colorize("╔" + "═" * (width - 2) + "╗", self.colors.CYAN, bold=True))

        # Center title
        title_pad = (width - len(title) - 2) // 2
        print(self.colorize("║" + " " * title_pad + title +
                          " " * (width - len(title) - title_pad - 2) + "║",
                          self.colors.CYAN, bold=True))

        if subtitle:
            sub_pad = (width - len(subtitle) - 2) // 2
            print(self.colorize("║" + " " * sub_pad + subtitle +
                              " " * (width - len(subtitle) - sub_pad - 2) + "║",
                              self.colors.BLUE))

        print(self.colorize("╚" + "═" * (width - 2) + "╝", self.colors.CYAN, bold=True))

        # TEMPEST EMSEC warning footer
        if self.tempest_mode:
            print()
            emsec_warning = f"{self.symbols.EMSEC} EMSEC: Monitor for electromagnetic emanations"
            print(self.colorize(emsec_warning, self.colors.TEMPEST_AMBER))

        print()

    def tempest_warning(self, message: str):
        """
        Display TEMPEST electromagnetic security warning

        Args:
            message: Warning message
        """
        if not self.tempest_mode:
            self.warning(message)
            return

        symbol = self.colorize(self.symbols.RADIATION, self.colors.TEMPEST_AMBER)
        msg = self.colorize(f"TEMPEST: {message}", self.colors.TEMPEST_AMBER, bold=True)
        print(f"{symbol} {msg}")

    def emsec_alert(self, message: str):
        """
        Display critical EMSEC (Electromagnetic Security) alert

        Args:
            message: Alert message
        """
        if not self.tempest_mode:
            self.critical(message)
            return

        symbol = self.colorize(self.symbols.ALERT, self.colors.TEMPEST_RED)
        msg = self.colorize(f"EMSEC ALERT: {message}", self.colors.TEMPEST_RED, bold=True)
        bg = self.colors.BG_RED
        print(f"{symbol} {bg}{msg}{self.colors.RESET}")

    def classification_banner(self, width: Optional[int] = None):
        """
        Display TEMPEST Level C classification banner

        Args:
            width: Banner width (auto if None)
        """
        if not self.tempest_mode:
            return

        if width is None:
            width = min(self.terminal_width, 80)

        classification_text = f"{self.symbols.CLASSIFIED} {self.classification} - TEMPEST LEVEL {self.tempest_level} {self.symbols.CLASSIFIED}"
        pad = (width - len(classification_text)) // 2

        print()
        print(self.colorize("━" * width, self.colors.TEMPEST_ORANGE, bold=True))
        print(self.colorize(" " * pad + classification_text +
                          " " * (width - len(classification_text) - pad),
                          self.colors.TEMPEST_ORANGE, bold=True))
        print(self.colorize("━" * width, self.colors.TEMPEST_ORANGE, bold=True))
        print()

    def tempest_box(self, title: str, content: list, level: str = "C"):
        """
        Display TEMPEST-classified information box

        Args:
            title: Box title
            content: List of lines to display
            level: TEMPEST level (A, B, or C)
        """
        # Color based on TEMPEST level
        if level == "A":
            color = self.colors.TEMPEST_RED
            level_text = "LEVEL A - CLASSIFIED"
        elif level == "B":
            color = self.colors.TEMPEST_ORANGE
            level_text = "LEVEL B - RESTRICTED"
        else:  # Level C
            color = self.colors.TEMPEST_AMBER
            level_text = "LEVEL C - CONTROLLED"

        width = min(self.terminal_width - 4, 80)

        # Top classification marking
        print()
        class_mark = f"{self.symbols.RADIATION} TEMPEST {level_text} {self.symbols.RADIATION}"
        class_pad = (width - len(class_mark)) // 2
        print(self.colorize(" " * class_pad + class_mark, color, bold=True))
        print()

        # Box top border
        print(self.colorize("┏" + "━" * (width - 2) + "┓", color, bold=True))

        # Title
        title_pad = width - len(title) - 4
        print(self.colorize(f"┃ {title}" + " " * title_pad + "┃", color, bold=True))
        print(self.colorize("┣" + "━" * (width - 2) + "┫", color))

        # Content
        for line in content:
            clean_line = self._strip_ansi(line)
            pad = width - len(clean_line) - 4
            print(self.colorize("┃ ", color) + line + " " * pad +
                  self.colorize(" ┃", color))

        # Bottom border
        print(self.colorize("┗" + "━" * (width - 2) + "┛", color, bold=True))

        # Bottom classification marking
        print()
        print(self.colorize(" " * class_pad + class_mark, color, bold=True))
        print()

    def opsec_reminder(self, message: str):
        """
        Display operational security reminder

        Args:
            message: OPSEC message
        """
        symbol = self.colorize(self.symbols.SHIELD, self.colors.TEMPEST_AMBER)
        msg = self.colorize(f"OPSEC: {message}", self.colors.TEMPEST_AMBER)
        print(f"{symbol} {msg}")

    def session_footer(self, width: Optional[int] = None):
        """
        Display TEMPEST session classification footer

        Args:
            width: Footer width (auto if None)
        """
        if not self.tempest_mode:
            return

        if width is None:
            width = min(self.terminal_width, 80)

        print()
        print(self.colorize("=" * width, self.colors.TEMPEST_ORANGE, bold=True))

        footer_text = f"{self.symbols.RADIATION} END TEMPEST LEVEL {self.tempest_level} SESSION - {self.classification} {self.symbols.RADIATION}"
        footer_pad = (width - len(footer_text)) // 2

        print(self.colorize(" " * footer_pad + footer_text +
                          " " * (width - len(footer_text) - footer_pad),
                          self.colors.TEMPEST_ORANGE, bold=True))

        # EMSEC reminder
        emsec_text = f"{self.symbols.EMSEC} Verify electromagnetic shielding active | Secure all emanations"
        emsec_pad = (width - len(emsec_text)) // 2
        print(self.colorize(" " * emsec_pad + emsec_text, self.colors.TEMPEST_AMBER))

        print(self.colorize("=" * width, self.colors.TEMPEST_ORANGE, bold=True))
        print()


class SpinnerContext:
    """Context manager for spinner animation"""

    def __init__(self, tui: TUI, message: str, delay: float):
        self.tui = tui
        self.message = message
        self.delay = delay
        self.frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.running = False
        self._thread = None

    def __enter__(self):
        """Start spinner"""
        import threading
        self.running = True
        self._thread = threading.Thread(target=self._spin)
        self._thread.daemon = True
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Stop spinner"""
        self.running = False
        if self._thread:
            self._thread.join()
        print("\r" + " " * (len(self.message) + 10), end='\r')  # Clear line

    def _spin(self):
        """Spinner animation loop"""
        i = 0
        while self.running:
            frame = self.frames[i % len(self.frames)]
            frame_colored = self.tui.colorize(frame, self.tui.colors.CYAN)
            print(f"\r{frame_colored} {self.message}...", end='', flush=True)
            time.sleep(self.delay)
            i += 1


# Convenience functions for quick use
_default_tui = None

def get_tui() -> TUI:
    """Get default TUI instance"""
    global _default_tui
    if _default_tui is None:
        _default_tui = TUI()
    return _default_tui


def success(message: str, prefix: str = ""):
    """Quick success message"""
    get_tui().success(message, prefix)


def error(message: str, prefix: str = ""):
    """Quick error message"""
    get_tui().error(message, prefix)


def warning(message: str, prefix: str = ""):
    """Quick warning message"""
    get_tui().warning(message, prefix)


def info(message: str, prefix: str = ""):
    """Quick info message"""
    get_tui().info(message, prefix)


if __name__ == '__main__':
    # Demo of TEMPEST Level C themed TUI features
    tui = TUI(tempest_mode=True)

    tui.banner("POLYGOTTEM TEMPEST Interface", "CLASSIFIED - Electromagnetic Security Demo")

    # TEMPEST-specific warnings
    tui.section("TEMPEST Level C Security Warnings")
    tui.tempest_warning("Electromagnetic emanations detected - Activate shielding")
    tui.emsec_alert("Unshielded CRT display in secure area")
    tui.opsec_reminder("Verify Faraday cage integrity before operation")

    # Classification banner
    tui.classification_banner()

    # Standard status messages
    tui.header("Status Messages")
    tui.success("Operation completed successfully")
    tui.error("An error occurred")
    tui.warning("This is a warning message")
    tui.info("Informational message")
    tui.critical("CRITICAL: This is urgent!")

    # TEMPEST classified box
    tui.section("TEMPEST Classified Information")
    tui.tempest_box("OPERATION CHIMERA", [
        "Exploit Chain: CVE-2025-XXXX → Kernel RCE",
        "Target Platform: Linux 6.x",
        "Persistence: systemd service + immutable flag",
        "C2 Protocol: DNS tunneling over TLS",
        "EMSEC: Faraday cage required"
    ], level="C")

    tui.section("Lists and Key-Values")
    tui.list_item("TEMPEST Level C deployment")
    tui.list_item("Electromagnetic countermeasures:", level=0)
    tui.list_item("Shielded cables installed", level=1)
    tui.list_item("RF dampening active", level=1)

    print()
    tui.key_value("CVE ID", "CVE-2025-XXXXX")
    tui.key_value("Classification", "TEMPEST Level C")
    tui.key_value("EMSEC Status", "ACTIVE")

    tui.section("Tables")
    headers = ["CVE", "Type", "TEMPEST Level"]
    rows = [
        ["CVE-2023-4863", "Heap Overflow", "Level C"],
        ["CVE-2024-10573", "Buffer Overflow", "Level B"],
        ["CVE-2023-52356", "Heap Overflow", "Level A"],
    ]
    tui.table(headers, rows)

    tui.section("Progress Bar")
    for i in range(101):
        tui.progress_bar(i, 100, prefix="Processing:", suffix=f"{i}/100")
        time.sleep(0.02)

    print()
    tui.success("Demo complete!")

    # Session footer with TEMPEST markings
    tui.session_footer()
