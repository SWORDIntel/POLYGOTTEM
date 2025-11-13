#!/usr/bin/env python3
"""
Interactive File Browser for POLYGOTTEM
========================================
Provides polished file selection interface with directory browsing,
filtering, preview, and multi-select support.

Features:
- Browse directories without typing paths
- Filter by file type (images, documents, executables, etc.)
- Multi-select files with visual feedback
- File metadata and preview
- Recent files list
- Favorites/bookmarks
- Quick navigation

Author: SWORDIntel
Date: 2025-11-11
"""

import os
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import mimetypes

from tui_helper import TUI, Colors, Symbols


class FileBrowser:
    """Interactive file browser with TUI"""

    def __init__(self, tui: Optional[TUI] = None, root_dir: Optional[str] = None):
        """
        Initialize file browser

        Args:
            tui: TUI instance
            root_dir: Root directory for browsing (default: payloads/)
        """
        self.tui = tui if tui else TUI()

        # Set default root to payloads/ in project root
        if root_dir is None:
            project_root = Path(__file__).parent.parent
            root_dir = project_root / "payloads"

        self.root_dir = Path(root_dir)
        self.current_dir = self.root_dir
        self.selected_files = []
        self.favorites = []
        self.recent_files = []

        # File type filters
        self.file_types = {
            'images': ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.tiff', '.ico'],
            'documents': ['.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt'],
            'executables': ['.exe', '.dll', '.so', '.dylib', '.app', '.sh', '.bat', '.ps1'],
            'scripts': ['.py', '.js', '.sh', '.bash', '.ps1', '.vbs', '.rb', '.pl'],
            'audio': ['.mp3', '.wav', '.flac', '.ogg', '.m4a', '.aac'],
            'video': ['.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv'],
            'archives': ['.zip', '.tar', '.gz', '.bz2', '.7z', '.rar'],
            'all': None  # No filter
        }

        # Ensure root directory exists
        self.root_dir.mkdir(parents=True, exist_ok=True)

    def browse(self,
              title: str = "Select File",
              multi_select: bool = False,
              file_type_filter: Optional[str] = None,
              show_hidden: bool = False) -> Optional[List[Path]]:
        """
        Launch interactive file browser

        Args:
            title: Browser window title
            multi_select: Allow selecting multiple files
            file_type_filter: Filter by file type (e.g., 'images', 'documents')
            show_hidden: Show hidden files

        Returns:
            List of selected file paths, or None if canceled
        """
        self.tui.header(title)

        # Show current directory
        self.tui.info(f"Browsing: {self._get_display_path()}")

        if file_type_filter and file_type_filter in self.file_types:
            extensions = self.file_types[file_type_filter]
            if extensions:
                self.tui.info(f"Filter: {file_type_filter} ({', '.join(extensions)})")

        print()

        while True:
            # Get entries in current directory
            entries = self._get_entries(show_hidden, file_type_filter)

            if not entries and self.current_dir == self.root_dir:
                self.tui.warning("No files found in payloads directory")
                self.tui.info("Add files to: " + str(self.root_dir))
                if self.tui.menu.confirm("Create sample files?", default=True):
                    self._create_sample_files()
                    entries = self._get_entries(show_hidden, file_type_filter)

            # Build menu options
            options = self._build_options(entries, multi_select)

            if not options:
                self.tui.error("No files available")
                return None

            # Show navigation help
            self._show_navigation_help(multi_select)

            # Display menu
            from tools.interactive_menu import InteractiveMenu
            menu = InteractiveMenu(self.tui)

            if multi_select:
                selected_indices = menu.multi_select(
                    f"Select Files from {self._get_display_path()}",
                    options,
                    allow_empty=True
                )

                if selected_indices is None or len(selected_indices) == 0:
                    # Check for special actions
                    continue

                # Process selections
                results = self._process_selections(selected_indices, entries, multi_select)
                if results is not None:
                    return results

            else:
                choice = menu.single_select(
                    f"Select File from {self._get_display_path()}",
                    options,
                    allow_cancel=True
                )

                if choice is None:
                    return None

                # Process selection
                results = self._process_selections([choice], entries, multi_select)
                if results is not None:
                    return results

    def browse_for_carrier(self,
                          carrier_type: str = "image") -> Optional[Path]:
        """
        Browse for carrier file (e.g., PNG, PDF)

        Args:
            carrier_type: Type of carrier ('image', 'document', etc.)

        Returns:
            Selected carrier file path or None
        """
        self.tui.section("Select Carrier File")
        self.tui.info(f"Choose a {carrier_type} file to use as the polyglot carrier")
        print()

        result = self.browse(
            title=f"Select {carrier_type.capitalize()} Carrier",
            multi_select=False,
            file_type_filter=carrier_type + 's'  # 'images', 'documents'
        )

        return result[0] if result else None

    def browse_for_payloads(self) -> List[Path]:
        """
        Browse for payload files to embed

        Returns:
            List of selected payload files
        """
        self.tui.section("Select Payload Files")
        self.tui.info("Choose payload files to embed (or skip to use command)")
        print()

        result = self.browse(
            title="Select Payload Files (optional)",
            multi_select=True,
            file_type_filter='all'
        )

        return result if result else []

    def _get_entries(self,
                    show_hidden: bool,
                    file_type_filter: Optional[str]) -> List[Dict[str, Any]]:
        """Get directory entries with metadata"""
        entries = []

        try:
            # Add parent directory option if not at root
            if self.current_dir != self.root_dir:
                entries.append({
                    'type': 'parent',
                    'name': '..',
                    'path': self.current_dir.parent,
                    'is_dir': True,
                    'size': 0,
                    'modified': datetime.now()
                })

            # Get directory contents
            for item in sorted(self.current_dir.iterdir()):
                # Skip hidden files if not showing
                if not show_hidden and item.name.startswith('.'):
                    continue

                # Apply file type filter
                if file_type_filter and file_type_filter != 'all':
                    if item.is_file():
                        extensions = self.file_types.get(file_type_filter)
                        if extensions and item.suffix.lower() not in extensions:
                            continue

                entry = {
                    'type': 'directory' if item.is_dir() else 'file',
                    'name': item.name,
                    'path': item,
                    'is_dir': item.is_dir(),
                    'size': item.stat().st_size if item.is_file() else 0,
                    'modified': datetime.fromtimestamp(item.stat().st_mtime)
                }

                entries.append(entry)

        except PermissionError:
            self.tui.error("Permission denied accessing directory")

        return entries

    def _build_options(self,
                      entries: List[Dict[str, Any]],
                      multi_select: bool) -> List[Dict[str, Any]]:
        """Build menu options from entries"""
        options = []

        for entry in entries:
            # Icon based on type
            if entry['type'] == 'parent':
                icon = '📁'
                label = f"{icon} {entry['name']} (Parent Directory)"
                color = Colors.CYAN
            elif entry['is_dir']:
                icon = '📁'
                label = f"{icon} {entry['name']}/"
                color = Colors.CYAN
            else:
                icon = self._get_file_icon(entry['path'])
                size_str = self._format_size(entry['size'])
                label = f"{icon} {entry['name']} ({size_str})"
                color = Colors.WHITE

            # Add to recent files indicator
            if entry['path'] in self.recent_files:
                label += " [Recent]"

            # Add to favorites indicator
            if entry['path'] in self.favorites:
                label += " ⭐"

            options.append({
                'label': label,
                'description': f"Modified: {entry['modified'].strftime('%Y-%m-%d %H:%M')}",
                'color': color,
                'value': entry,
                'disabled': False
            })

        return options

    def _process_selections(self,
                          selected_indices: List[int],
                          entries: List[Dict[str, Any]],
                          multi_select: bool) -> Optional[List[Path]]:
        """Process user selections"""
        if not selected_indices:
            return []

        selected_entries = [entries[i] for i in selected_indices]

        # If single selection and it's a directory, navigate into it
        if len(selected_entries) == 1 and selected_entries[0]['is_dir']:
            self.current_dir = selected_entries[0]['path']
            return None  # Continue browsing

        # Collect files
        files = []
        for entry in selected_entries:
            if not entry['is_dir']:
                files.append(entry['path'])
                # Add to recent files
                if entry['path'] not in self.recent_files:
                    self.recent_files.insert(0, entry['path'])
                    if len(self.recent_files) > 10:
                        self.recent_files.pop()

        return files if files else None

    def _get_file_icon(self, file_path: Path) -> str:
        """Get emoji icon for file type"""
        suffix = file_path.suffix.lower()

        # Images
        if suffix in self.file_types['images']:
            return '🖼️'
        # Documents
        elif suffix in self.file_types['documents']:
            return '📄'
        # Executables
        elif suffix in self.file_types['executables']:
            return '⚙️'
        # Scripts
        elif suffix in self.file_types['scripts']:
            return '📝'
        # Audio
        elif suffix in self.file_types['audio']:
            return '🎵'
        # Video
        elif suffix in self.file_types['video']:
            return '🎬'
        # Archives
        elif suffix in self.file_types['archives']:
            return '📦'
        else:
            return '📄'

    def _format_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f}{unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f}TB"

    def _get_display_path(self) -> str:
        """Get display path relative to root"""
        try:
            rel_path = self.current_dir.relative_to(self.root_dir)
            return f"payloads/{rel_path}" if str(rel_path) != '.' else "payloads/"
        except ValueError:
            return str(self.current_dir)

    def _show_navigation_help(self, multi_select: bool):
        """Show navigation help"""
        help_items = []

        if multi_select:
            help_items.append("Space/Number = Toggle selection")
            help_items.append("A = Select all")
            help_items.append("N = Clear selection")
        else:
            help_items.append("Number = Select file/folder")

        help_items.append("Enter = Confirm")
        help_items.append("Folders = Navigate into directory")

        print()
        self.tui.info("Navigation: " + " | ".join(help_items))
        print()

    def _create_sample_files(self):
        """Create sample files for demonstration"""
        self.tui.info("Creating sample files...")

        samples_dir = self.root_dir / "samples"
        samples_dir.mkdir(exist_ok=True)

        # Create sample carrier files
        carriers_dir = samples_dir / "carriers"
        carriers_dir.mkdir(exist_ok=True)

        # Sample PNG
        sample_png = carriers_dir / "sample_image.png"
        if not sample_png.exists():
            # PNG header + minimal data
            png_data = (
                b'\x89PNG\r\n\x1a\n'  # PNG signature
                b'\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
                b'\x08\x02\x00\x00\x00\x90wS\xde'  # 1x1 image
                b'\x00\x00\x00\x0cIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4'
                b'\x00\x00\x00\x00IEND\xaeB`\x82'
            )
            sample_png.write_bytes(png_data)

        # Sample PDF
        sample_pdf = carriers_dir / "sample_document.pdf"
        if not sample_pdf.exists():
            pdf_content = b"""%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj
3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj
xref
0 4
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
trailer<</Size 4/Root 1 0 R>>
startxref
203
%%EOF
"""
            sample_pdf.write_bytes(pdf_content)

        # Create sample payload files
        payloads_dir = samples_dir / "payloads"
        payloads_dir.mkdir(exist_ok=True)

        # Sample shellcode
        sample_shellcode = payloads_dir / "sample_shellcode.bin"
        if not sample_shellcode.exists():
            sample_shellcode.write_bytes(b'\x90' * 100 + b'\xcc')  # NOPs + INT3

        # Sample script
        sample_script = payloads_dir / "sample_payload.sh"
        if not sample_script.exists():
            sample_script.write_text('#!/bin/bash\necho "Sample payload executed"\n')

        self.tui.success(f"Sample files created in {samples_dir}")

    def show_file_info(self, file_path: Path):
        """Show detailed file information"""
        self.tui.section("File Information")

        stat = file_path.stat()

        info_items = [
            f"Name: {file_path.name}",
            f"Path: {file_path}",
            f"Size: {self._format_size(stat.st_size)}",
            f"Type: {mimetypes.guess_type(file_path)[0] or 'Unknown'}",
            f"Modified: {datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')}",
            f"Permissions: {oct(stat.st_mode)[-3:]}",
        ]

        self.tui.box("File Details", info_items)

    def get_recent_files(self, limit: int = 5) -> List[Path]:
        """Get recently selected files"""
        return self.recent_files[:limit]

    def add_favorite(self, file_path: Path):
        """Add file to favorites"""
        if file_path not in self.favorites:
            self.favorites.append(file_path)
            self.tui.success(f"Added to favorites: {file_path.name}")

    def remove_favorite(self, file_path: Path):
        """Remove file from favorites"""
        if file_path in self.favorites:
            self.favorites.remove(file_path)
            self.tui.info(f"Removed from favorites: {file_path.name}")


if __name__ == '__main__':
    # Demo file browser
    tui = TUI()
    browser = FileBrowser(tui)

    tui.banner("POLYGOTTEM File Browser", "Interactive File Selection")

    # Demo: Browse for carrier
    carrier = browser.browse_for_carrier('image')
    if carrier:
        tui.success(f"Selected carrier: {carrier}")
        browser.show_file_info(carrier)

    # Demo: Browse for payloads
    payloads = browser.browse_for_payloads()
    if payloads:
        tui.success(f"Selected {len(payloads)} payload(s):")
        for p in payloads:
            tui.list_item(str(p), level=1)

    # Show recent files
    print()
    recent = browser.get_recent_files()
    if recent:
        tui.info("Recent files:")
        for f in recent:
            tui.list_item(str(f), level=1)
