#!/usr/bin/env python3
"""
Interactive Multi-Choice Menu System for POLYGOTTEM
===================================================
Provides interactive menus with multi-selection, navigation, and confirmation.

Features:
- Multi-select checkbox menus
- Single-select radio button menus
- Arrow key navigation (with fallback to numbered input)
- Visual feedback and TUI integration
- Cascading menu chains

Author: SWORDIntel
Date: 2025-11-11
"""

import sys
from typing import List, Dict, Any, Optional, Tuple
from tui_helper import TUI, Colors, Symbols


class InteractiveMenu:
    """Interactive menu with multi-choice selection support"""

    def __init__(self, tui: Optional[TUI] = None):
        """
        Initialize interactive menu

        Args:
            tui: TUI instance (creates new if None)
        """
        self.tui = tui if tui else TUI()
        self.colors = Colors()
        self.symbols = Symbols()

    def multi_select(self,
                     title: str,
                     options: List[Dict[str, Any]],
                     min_selections: int = 0,
                     max_selections: Optional[int] = None,
                     allow_empty: bool = False) -> List[int]:
        """
        Multi-select checkbox menu

        Args:
            title: Menu title
            options: List of option dicts with keys:
                     - 'label': Display text (required)
                     - 'value': Option value (optional)
                     - 'description': Additional info (optional)
                     - 'selected': Pre-selected (default False)
                     - 'disabled': Cannot be selected (default False)
                     - 'color': Custom color (optional)
            min_selections: Minimum number of selections required
            max_selections: Maximum selections allowed (None = unlimited)
            allow_empty: Allow confirming with no selections

        Returns:
            List of selected option indices
        """
        self.tui.header(title)
        self.tui.info("Use numbers to toggle selection, 'A' for all, 'N' for none, 'Enter' to confirm")
        print()

        # Initialize selection state
        selected = set()
        for i, opt in enumerate(options):
            if opt.get('selected', False) and not opt.get('disabled', False):
                selected.add(i)

        # Check for terminal capabilities
        has_curses = self._check_curses()

        if has_curses:
            return self._multi_select_curses(options, selected, min_selections,
                                            max_selections, allow_empty)
        else:
            return self._multi_select_simple(options, selected, min_selections,
                                            max_selections, allow_empty)

    def _multi_select_simple(self, options, selected, min_sel, max_sel, allow_empty):
        """Simple numbered multi-select (fallback when curses unavailable)"""

        while True:
            # Display options
            print(self.tui.colorize("\nCurrent Selection:", self.colors.CYAN, bold=True))
            for i, opt in enumerate(options):
                disabled = opt.get('disabled', False)
                is_selected = i in selected

                # Checkbox symbol
                if is_selected:
                    checkbox = self.tui.colorize("[✓]", self.colors.GREEN, bold=True)
                else:
                    checkbox = self.tui.colorize("[ ]", self.colors.BRIGHT_BLACK)

                # Option label
                label = opt['label']
                if disabled:
                    label = self.tui.colorize(label, self.colors.BRIGHT_BLACK)
                elif is_selected:
                    label = self.tui.colorize(label, opt.get('color', self.colors.GREEN))
                else:
                    label = self.tui.colorize(label, opt.get('color', self.colors.WHITE))

                # Number
                num = self.tui.colorize(f"{i+1}.", self.colors.CYAN)

                print(f"  {num} {checkbox} {label}")

                # Description
                if 'description' in opt:
                    desc = self.tui.colorize(f"      {opt['description']}",
                                            self.colors.BRIGHT_BLACK)
                    print(desc)

            print()
            print(self.tui.colorize(f"Selected: {len(selected)}", self.colors.CYAN))
            if min_sel > 0:
                print(self.tui.colorize(f"Minimum required: {min_sel}", self.colors.YELLOW))
            if max_sel:
                print(self.tui.colorize(f"Maximum allowed: {max_sel}", self.colors.YELLOW))

            # Get input
            print()
            prompt = self.tui.colorize("Enter number (1-{}), 'A' (all), 'N' (none), or 'Enter' (confirm): "
                                      .format(len(options)), self.colors.CYAN)
            choice = input(prompt).strip().upper()

            if choice == '':
                # Confirm selection
                if len(selected) < min_sel:
                    self.tui.error(f"Must select at least {min_sel} option(s)")
                    continue
                if not allow_empty and len(selected) == 0:
                    self.tui.error("Must select at least one option")
                    continue
                break
            elif choice == 'A':
                # Select all non-disabled
                selected = {i for i, opt in enumerate(options) if not opt.get('disabled', False)}
                if max_sel and len(selected) > max_sel:
                    self.tui.warning(f"Limited to {max_sel} selections")
                    selected = set(list(selected)[:max_sel])
                self.tui.success("All options selected")
            elif choice == 'N':
                # Deselect all
                selected.clear()
                self.tui.info("All options deselected")
            else:
                # Toggle specific option
                try:
                    idx = int(choice) - 1
                    if idx < 0 or idx >= len(options):
                        self.tui.error("Invalid option number")
                        continue

                    opt = options[idx]
                    if opt.get('disabled', False):
                        self.tui.error("This option is disabled")
                        continue

                    if idx in selected:
                        selected.remove(idx)
                        self.tui.info(f"Deselected: {opt['label']}")
                    else:
                        if max_sel and len(selected) >= max_sel:
                            self.tui.warning(f"Maximum {max_sel} selections allowed")
                            continue
                        selected.add(idx)
                        self.tui.success(f"Selected: {opt['label']}")
                except ValueError:
                    self.tui.error("Invalid input")

        return sorted(list(selected))

    def _multi_select_curses(self, options, selected, min_sel, max_sel, allow_empty):
        """Curses-based multi-select with arrow key navigation"""
        import curses

        def _menu(stdscr):
            curses.curs_set(0)  # Hide cursor
            current_pos = 0

            while True:
                stdscr.clear()
                h, w = stdscr.getmaxyx()

                # Title
                stdscr.addstr(0, 0, "Use ↑↓ to navigate, SPACE to toggle, ENTER to confirm, A/N for all/none",
                             curses.A_BOLD)
                stdscr.addstr(1, 0, f"Selected: {len(selected)}", curses.A_DIM)

                # Options
                for i, opt in enumerate(options):
                    y = i + 3
                    if y >= h - 2:
                        break

                    disabled = opt.get('disabled', False)
                    is_selected = i in selected
                    is_current = i == current_pos

                    # Checkbox
                    checkbox = "[✓]" if is_selected else "[ ]"

                    # Formatting
                    attr = curses.A_NORMAL
                    if is_current:
                        attr |= curses.A_REVERSE
                    if is_selected:
                        attr |= curses.A_BOLD
                    if disabled:
                        attr |= curses.A_DIM

                    line = f"  {checkbox} {opt['label']}"
                    stdscr.addstr(y, 0, line[:w-1], attr)

                # Status
                stdscr.addstr(h-1, 0, "Press 'q' to quit without selecting", curses.A_DIM)

                stdscr.refresh()

                # Handle input
                key = stdscr.getch()

                if key == curses.KEY_UP and current_pos > 0:
                    current_pos -= 1
                elif key == curses.KEY_DOWN and current_pos < len(options) - 1:
                    current_pos += 1
                elif key == ord(' '):  # Space to toggle
                    if not options[current_pos].get('disabled', False):
                        if current_pos in selected:
                            selected.remove(current_pos)
                        else:
                            if not max_sel or len(selected) < max_sel:
                                selected.add(current_pos)
                elif key == ord('a') or key == ord('A'):  # Select all
                    selected = {i for i, opt in enumerate(options) if not opt.get('disabled', False)}
                    if max_sel and len(selected) > max_sel:
                        selected = set(list(selected)[:max_sel])
                elif key == ord('n') or key == ord('N'):  # Select none
                    selected.clear()
                elif key == ord('\n'):  # Enter to confirm
                    if len(selected) >= min_sel or (allow_empty and len(selected) == 0):
                        return sorted(list(selected))
                elif key == ord('q') or key == ord('Q'):
                    return []

        try:
            result = curses.wrapper(_menu)
            return result
        except Exception as e:
            self.tui.warning(f"Curses menu failed, falling back to simple menu: {e}")
            return self._multi_select_simple(options, selected, min_sel, max_sel, allow_empty)

    def single_select(self,
                     title: str,
                     options: List[Dict[str, Any]],
                     default: Optional[int] = None,
                     allow_cancel: bool = True) -> Optional[int]:
        """
        Single-select radio button menu

        Args:
            title: Menu title
            options: List of option dicts (same format as multi_select)
            default: Default selected index
            allow_cancel: Allow canceling without selection

        Returns:
            Selected option index, or None if canceled
        """
        self.tui.header(title)
        self.tui.info("Enter option number or 'Enter' for default")
        print()

        selected = default if default is not None else 0

        while True:
            # Display options
            for i, opt in enumerate(options):
                disabled = opt.get('disabled', False)
                is_selected = i == selected

                # Radio button symbol
                if is_selected:
                    radio = self.tui.colorize("(•)", self.colors.GREEN, bold=True)
                else:
                    radio = self.tui.colorize("( )", self.colors.BRIGHT_BLACK)

                # Option label
                label = opt['label']
                if disabled:
                    label = self.tui.colorize(label, self.colors.BRIGHT_BLACK)
                elif is_selected:
                    label = self.tui.colorize(label, opt.get('color', self.colors.GREEN))
                else:
                    label = self.tui.colorize(label, opt.get('color', self.colors.WHITE))

                # Number
                num = self.tui.colorize(f"{i+1}.", self.colors.CYAN)

                print(f"  {num} {radio} {label}")

                # Description
                if 'description' in opt:
                    desc = self.tui.colorize(f"      {opt['description']}",
                                            self.colors.BRIGHT_BLACK)
                    print(desc)

            print()
            cancel_text = " or 'C' to cancel" if allow_cancel else ""
            prompt = self.tui.colorize(f"Enter option (1-{len(options)}){cancel_text}, or 'Enter' for [{selected+1}]: ",
                                      self.colors.CYAN)
            choice = input(prompt).strip().upper()

            if choice == '':
                return selected
            elif choice == 'C' and allow_cancel:
                return None
            else:
                try:
                    idx = int(choice) - 1
                    if idx < 0 or idx >= len(options):
                        self.tui.error("Invalid option number")
                        continue
                    if options[idx].get('disabled', False):
                        self.tui.error("This option is disabled")
                        continue
                    return idx
                except ValueError:
                    self.tui.error("Invalid input")

    def confirm(self, message: str, default: bool = False) -> bool:
        """
        Yes/No confirmation prompt

        Args:
            message: Confirmation message
            default: Default choice (True=Yes, False=No)

        Returns:
            True if confirmed, False otherwise
        """
        default_text = "Y/n" if default else "y/N"
        prompt = self.tui.colorize(f"{message} [{default_text}]: ", self.colors.YELLOW)

        choice = input(prompt).strip().upper()

        if choice == '':
            return default

        return choice in ('Y', 'YES')

    def prompt_input(self,
                    message: str,
                    default: Optional[str] = None,
                    validator: Optional[callable] = None) -> str:
        """
        Text input prompt with validation

        Args:
            message: Prompt message
            default: Default value
            validator: Optional validation function that returns (bool, error_msg)

        Returns:
            User input string
        """
        default_text = f" [{default}]" if default else ""

        while True:
            prompt = self.tui.colorize(f"{message}{default_text}: ", self.colors.CYAN)
            value = input(prompt).strip()

            if value == '' and default:
                value = default

            if validator:
                is_valid, error_msg = validator(value)
                if not is_valid:
                    self.tui.error(error_msg)
                    continue

            return value

    def _check_curses(self) -> bool:
        """Check if curses is available and terminal supports it"""
        try:
            import curses
            # Test if we can initialize
            return sys.stdout.isatty() and sys.stdin.isatty()
        except ImportError:
            return False


class MenuBuilder:
    """Fluent interface for building complex menu chains"""

    def __init__(self, tui: Optional[TUI] = None):
        """Initialize menu builder"""
        self.menu = InteractiveMenu(tui)
        self.results = {}

    def add_multi_select(self,
                        key: str,
                        title: str,
                        options: List[Dict[str, Any]],
                        **kwargs) -> 'MenuBuilder':
        """
        Add multi-select menu to chain

        Args:
            key: Result key
            title: Menu title
            options: Menu options
            **kwargs: Additional arguments for multi_select()

        Returns:
            Self for chaining
        """
        selected = self.menu.multi_select(title, options, **kwargs)
        self.results[key] = selected
        return self

    def add_single_select(self,
                         key: str,
                         title: str,
                         options: List[Dict[str, Any]],
                         **kwargs) -> 'MenuBuilder':
        """
        Add single-select menu to chain

        Args:
            key: Result key
            title: Menu title
            options: Menu options
            **kwargs: Additional arguments for single_select()

        Returns:
            Self for chaining
        """
        selected = self.menu.single_select(title, options, **kwargs)
        self.results[key] = selected
        return self

    def add_confirm(self, key: str, message: str, **kwargs) -> 'MenuBuilder':
        """
        Add confirmation prompt to chain

        Args:
            key: Result key
            message: Confirmation message
            **kwargs: Additional arguments for confirm()

        Returns:
            Self for chaining
        """
        result = self.menu.confirm(message, **kwargs)
        self.results[key] = result
        return self

    def add_input(self, key: str, message: str, **kwargs) -> 'MenuBuilder':
        """
        Add text input prompt to chain

        Args:
            key: Result key
            message: Prompt message
            **kwargs: Additional arguments for prompt_input()

        Returns:
            Self for chaining
        """
        result = self.menu.prompt_input(message, **kwargs)
        self.results[key] = result
        return self

    def get_results(self) -> Dict[str, Any]:
        """Get all menu results"""
        return self.results


if __name__ == '__main__':
    # Demo of interactive menu features
    menu = InteractiveMenu()
    tui = menu.tui

    tui.banner("Interactive Menu Demo", "Multi-Choice Selection System")

    # Demo 1: Multi-select
    cve_options = [
        {
            'label': 'CVE-2023-4863 (WebP)',
            'description': 'Critical heap overflow - Chrome, Edge, Firefox',
            'color': Colors.BRIGHT_RED,
            'selected': True
        },
        {
            'label': 'CVE-2024-10573 (MP3)',
            'description': 'Buffer overflow in MP3 decoder',
            'color': Colors.RED
        },
        {
            'label': 'CVE-2023-52356 (TIFF)',
            'description': 'Heap overflow in TIFF parsing',
            'color': Colors.YELLOW
        },
        {
            'label': 'CVE-2019-15133 (GIF)',
            'description': 'Integer overflow in GIF loader',
            'color': Colors.YELLOW
        },
    ]

    selected_cves = menu.multi_select(
        "Select CVE Exploits to Include",
        cve_options,
        min_selections=1
    )

    tui.success(f"Selected {len(selected_cves)} CVE(s)")
    for idx in selected_cves:
        tui.list_item(cve_options[idx]['label'])

    # Demo 2: Single-select
    payload_options = [
        {'label': 'NOP Sled', 'description': 'Classic buffer overflow payload'},
        {'label': 'Shellcode', 'description': 'Direct execution payload'},
        {'label': 'ROP Chain', 'description': 'Return-oriented programming'},
        {'label': 'Custom', 'description': 'User-provided payload'},
    ]

    payload = menu.single_select(
        "Select Payload Type",
        payload_options,
        default=0
    )

    if payload is not None:
        tui.success(f"Selected payload: {payload_options[payload]['label']}")

    # Demo 3: Confirmation
    if menu.confirm("Generate polyglot file?", default=True):
        tui.success("Generating polyglot...")
    else:
        tui.info("Canceled")

    # Demo 4: Menu builder chain
    builder = MenuBuilder()
    results = builder \
        .add_single_select('format', 'Select Format', [
            {'label': 'Image Polyglot'},
            {'label': 'Audio Polyglot'},
            {'label': 'MEGA Polyglot'},
        ]) \
        .add_input('filename', 'Output filename', default='output.bin') \
        .add_confirm('encrypt', 'Apply XOR encryption?', default=True) \
        .get_results()

    tui.section("Menu Chain Results")
    for key, value in results.items():
        tui.key_value(key, str(value))
