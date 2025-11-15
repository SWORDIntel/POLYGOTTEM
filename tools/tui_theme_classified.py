#!/usr/bin/env python3
"""
TEMPEST Class C Classified Theme - Military/Covert Aesthetic
============================================================
Implements classified document styling for POLYGOTTEM with:
- Military header/footer formatting
- Classification levels (U, C, S, TS, SCI)
- Operation ID and timestamp on every section
- Monochrome with green/amber highlights
- Declassification notice templates
- Minimal, stark aesthetic

Author: SWORDIntel
Date: 2025-11-15
"""

import os
import sys
from typing import Optional, List
from datetime import datetime

# Add tools to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tui_helper import TUI, Colors


class ClassifiedTheme(TUI):
    """Extends TUI with classified document styling"""

    # Classification levels
    UNCLASSIFIED = "U"
    CONFIDENTIAL = "C"
    SECRET = "S"
    TOP_SECRET = "TS"
    TOP_SECRET_SCI = "TS//SCI"

    # Color scheme for classified aesthetic
    CLASSIFICATION_COLOR = Colors.YELLOW
    HEADER_COLOR = Colors.BRIGHT_WHITE
    TIMESTAMP_COLOR = Colors.BRIGHT_BLACK
    OPERATION_COLOR = Colors.BRIGHT_CYAN

    def __init__(self, classification_level: str = "C", operation_id: Optional[str] = None):
        """
        Initialize classified theme

        Args:
            classification_level: Classification level (U, C, S, TS, TS//SCI)
            operation_id: Operation ID to display on all sections
        """
        super().__init__()
        self.classification_level = classification_level
        self.operation_id = operation_id or self._generate_operation_id()
        self.timestamp = datetime.now()

    def _generate_operation_id(self) -> str:
        """
        Generate operation ID in military style

        Returns:
            Operation ID (e.g., CHIMERA_20251115_091313)
        """
        import random
        import string
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"CHIMERA_{timestamp}"

    def _get_classification_label(self) -> str:
        """
        Get classification label with color

        Returns:
            Colored classification label
        """
        labels = {
            "U": "(U) UNCLASSIFIED",
            "C": "(C) CONFIDENTIAL",
            "S": "(S) SECRET",
            "TS": "(TS) TOP SECRET",
            "TS//SCI": "(TS//SCI) TOP SECRET // SCI"
        }
        label = labels.get(self.classification_level, "(U) UNCLASSIFIED")
        return self.colorize(label, self.CLASSIFICATION_COLOR)

    def _get_header_line(self) -> str:
        """
        Get classified header line

        Returns:
            Header line with classification marking
        """
        return self.colorize("=" * 80, Colors.BRIGHT_BLACK)

    def classified_banner(self, title: str, subtitle: Optional[str] = None):
        """
        Display classified document banner

        Args:
            title: Document title
            subtitle: Optional subtitle
        """
        self.raw("")
        self.raw(self._get_header_line())
        self.raw(self._get_classification_label())
        self.raw("")

        # Title
        self.raw(self.colorize(f"  {title}", self.HEADER_COLOR))

        # Subtitle
        if subtitle:
            self.raw(self.colorize(f"  {subtitle}", Colors.BRIGHT_BLACK))

        self.raw("")

        # Operation ID and timestamp
        op_line = f"  OPERATION: {self.colorize(self.operation_id, self.OPERATION_COLOR)} | "
        op_line += f"TIME: {self.colorize(self.timestamp.strftime('%Y-%m-%d %H:%M:%S'), self.TIMESTAMP_COLOR)}"
        self.raw(op_line)

        self.raw("")
        self.raw(self._get_header_line())
        print()

    def classified_section(self, title: str, classification: Optional[str] = None):
        """
        Display classified section header

        Args:
            title: Section title
            classification: Optional classification level override
        """
        classification = classification or self.classification_level
        class_label = {
            "U": "(U)",
            "C": "(C)",
            "S": "(S)",
            "TS": "(TS)",
            "TS//SCI": "(TS//SCI)"
        }.get(classification, "(U)")

        header = f"{self.colorize(class_label, self.CLASSIFICATION_COLOR)} {title}"
        self.raw("")
        self.raw(self.colorize("─" * 80, Colors.BRIGHT_BLACK))
        self.raw(header)
        self.raw(self.colorize("─" * 80, Colors.BRIGHT_BLACK))
        print()

    def classified_box(self, title: str, content: List[str], classification: Optional[str] = None):
        """
        Display classified information box

        Args:
            title: Box title
            content: List of content lines
            classification: Optional classification level override
        """
        classification = classification or self.classification_level
        class_label = {
            "U": "(U)",
            "C": "(C)",
            "S": "(S)",
            "TS": "(TS)"
        }.get(classification, "(U)")

        self.raw("")
        self.raw(self.colorize("╔" + "═" * 78 + "╗", Colors.BRIGHT_BLACK))
        self.raw(self.colorize(f"║ {class_label} {title:<70} ║", self.HEADER_COLOR))
        self.raw(self.colorize("║" + "─" * 78 + "║", Colors.BRIGHT_BLACK))

        for line in content:
            self.raw(self.colorize(f"║ {line:<78} ║", Colors.BRIGHT_GREEN))

        self.raw(self.colorize("╚" + "═" * 78 + "╝", Colors.BRIGHT_BLACK))
        print()

    def classified_warning(self, message: str):
        """
        Display classified warning message

        Args:
            message: Warning message
        """
        warning = f"[!] {message}"
        self.raw(self.colorize(warning, Colors.YELLOW))

    def classified_success(self, message: str):
        """
        Display classified success message with timestamp

        Args:
            message: Success message
        """
        timestamp = datetime.now().strftime('%H:%M:%S')
        msg = f"[✓] [{timestamp}] {message}"
        self.raw(self.colorize(msg, Colors.BRIGHT_GREEN))

    def classified_error(self, message: str):
        """
        Display classified error message

        Args:
            message: Error message
        """
        timestamp = datetime.now().strftime('%H:%M:%S')
        msg = f"[✗] [{timestamp}] {message}"
        self.raw(self.colorize(msg, Colors.RED))

    def classified_info(self, message: str):
        """
        Display classified info message

        Args:
            message: Info message
        """
        timestamp = datetime.now().strftime('%H:%M:%S')
        msg = f"[•] [{timestamp}] {message}"
        self.raw(self.colorize(msg, Colors.BRIGHT_CYAN))

    def declassification_notice(self):
        """Display standard declassification notice"""
        self.raw("")
        self.raw(self.colorize("─" * 80, Colors.BRIGHT_BLACK))
        self.raw(self.colorize("DECLASSIFICATION AUTHORITY: Not Releasable to Foreign Nationals (NOFORN)", Colors.BRIGHT_BLACK))
        self.raw(self.colorize("DECLASSIFY ON: 2050-01-01 or OADR", Colors.BRIGHT_BLACK))
        self.raw(self.colorize("─" * 80, Colors.BRIGHT_BLACK))
        print()

    def footer(self, classification: Optional[str] = None):
        """
        Display classified document footer

        Args:
            classification: Optional classification level override
        """
        classification = classification or self.classification_level
        class_label = {
            "U": "(U) UNCLASSIFIED",
            "C": "(C) CONFIDENTIAL",
            "S": "(S) SECRET",
            "TS": "(TS) TOP SECRET"
        }.get(classification, "(U) UNCLASSIFIED")

        self.raw("")
        self.raw(self._get_header_line())
        self.raw(self.colorize(class_label, self.CLASSIFICATION_COLOR))
        self.raw(self.colorize(f"Operation: {self.operation_id}", self.OPERATION_COLOR))
        self.raw(self.colorize(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", self.TIMESTAMP_COLOR))
        self.raw(self._get_header_line())
        print()

    def intelligence_report_header(self, report_title: str, classification: Optional[str] = None):
        """
        Display intelligence report header (formatted for classified docs)

        Args:
            report_title: Report title
            classification: Optional classification level override
        """
        classification = classification or self.classification_level

        self.classified_banner(
            f"INTELLIGENCE OPERATIONS REPORT",
            f"{report_title}"
        )

        self.classified_section("CLASSIFICATION MARKINGS")
        self.raw(self.colorize(f"Document Classification: {classification}", self.CLASSIFICATION_COLOR))
        self.raw(self.colorize(f"Distribution: SWORDIntel Security Personnel Only", Colors.BRIGHT_BLACK))
        self.raw(self.colorize(f"Operation ID: {self.operation_id}", self.OPERATION_COLOR))
        print()

    def operational_timeline(self, events: List[tuple]):
        """
        Display operational timeline

        Args:
            events: List of (timestamp, event) tuples
        """
        self.classified_section("OPERATIONAL TIMELINE")

        for timestamp, event in events:
            time_str = self.colorize(f"[{timestamp}]", self.TIMESTAMP_COLOR)
            self.raw(f"  {time_str} {event}")

        print()

    def security_clearance_notice(self):
        """Display security clearance notice"""
        self.raw("")
        self.raw(self.colorize("╔" + "═" * 78 + "╗", Colors.RED))
        self.raw(self.colorize("║" + " " * 78 + "║", Colors.RED))
        self.raw(self.colorize("║  AUTHORIZED PERSONNEL ONLY - SECURITY CLEARANCE REQUIRED               ║", Colors.RED))
        self.raw(self.colorize("║  Unauthorized Access is a Federal Crime (18 U.S.C. § 641, 1030)       ║", Colors.RED))
        self.raw(self.colorize("║" + " " * 78 + "║", Colors.RED))
        self.raw(self.colorize("╚" + "═" * 78 + "╝", Colors.RED))
        print()

    def set_classification_level(self, level: str):
        """
        Change classification level

        Args:
            level: Classification level (U, C, S, TS, TS//SCI)
        """
        valid_levels = ["U", "C", "S", "TS", "TS//SCI"]
        if level in valid_levels:
            self.classification_level = level
            self.classified_info(f"Classification changed to {level}")

    def audit_log_entry(self, action: str, details: str, result: str = "SUCCESS"):
        """
        Log entry in classified audit format

        Args:
            action: Action taken
            details: Action details
            result: Result (SUCCESS, FAILED, PENDING)
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        result_color = Colors.BRIGHT_GREEN if result == "SUCCESS" else Colors.RED

        log_line = f"[{timestamp}] {action}: {details} ... {self.colorize(f'[{result}]', result_color)}"
        self.raw(log_line)
