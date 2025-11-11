#!/usr/bin/env python3
"""
Validation Utilities for POLYGOTTEM
====================================
Provides comprehensive input validation, error handling, and safe file operations.

Author: SWORDIntel
Date: 2025-11-11
"""

import os
import sys
import tempfile
import shutil
import logging
import time
from pathlib import Path
from typing import Optional, List, Union, Tuple, Callable


class ValidationError(Exception):
    """Custom exception for validation errors"""
    pass


class FileOperationError(Exception):
    """Custom exception for file operation errors"""
    pass


def validate_file_exists(file_path: Union[str, Path], file_description: str = "File") -> Path:
    """
    Validate that a file exists and is readable

    Args:
        file_path: Path to file
        file_description: Description of file for error messages

    Returns:
        Path object of validated file

    Raises:
        ValidationError: If file doesn't exist or isn't readable
    """
    path = Path(file_path)

    if not path.exists():
        raise ValidationError(f"{file_description} not found: {file_path}")

    if not path.is_file():
        raise ValidationError(f"{file_description} is not a file: {file_path}")

    if not os.access(path, os.R_OK):
        raise ValidationError(f"{file_description} is not readable: {file_path}")

    return path


def validate_directory_exists(dir_path: Union[str, Path], create: bool = False) -> Path:
    """
    Validate that a directory exists

    Args:
        dir_path: Path to directory
        create: If True, create directory if it doesn't exist

    Returns:
        Path object of validated directory

    Raises:
        ValidationError: If directory doesn't exist and create=False
    """
    path = Path(dir_path)

    if not path.exists():
        if create:
            try:
                path.mkdir(parents=True, exist_ok=True)
                return path
            except (OSError, PermissionError) as e:
                raise ValidationError(f"Cannot create directory {dir_path}: {e}")
        else:
            raise ValidationError(f"Directory not found: {dir_path}")

    if not path.is_dir():
        raise ValidationError(f"Path is not a directory: {dir_path}")

    return path


def validate_output_path(output_path: Union[str, Path],
                        allow_overwrite: bool = False,
                        create_parents: bool = True) -> Path:
    """
    Validate output file path

    Args:
        output_path: Path for output file
        allow_overwrite: If True, allow overwriting existing files
        create_parents: If True, create parent directories

    Returns:
        Path object of validated output path

    Raises:
        ValidationError: If path exists and overwrite not allowed
        FileOperationError: If parent directory cannot be created
    """
    path = Path(output_path)

    # Check if file exists
    if path.exists() and not allow_overwrite:
        raise ValidationError(
            f"Output file already exists: {output_path}\n"
            f"Use --force to overwrite or choose a different path"
        )

    # Check parent directory
    parent = path.parent
    if not parent.exists():
        if create_parents:
            try:
                parent.mkdir(parents=True, exist_ok=True)
            except (OSError, PermissionError) as e:
                raise FileOperationError(f"Cannot create parent directory {parent}: {e}")
        else:
            raise ValidationError(f"Parent directory does not exist: {parent}")

    # Check if parent is writable
    if not os.access(parent, os.W_OK):
        raise ValidationError(f"Parent directory is not writable: {parent}")

    return path


def validate_xor_key(key: str) -> bytes:
    """
    Validate and convert XOR key

    Args:
        key: XOR key as hex string or regular string

    Returns:
        Key as bytes

    Raises:
        ValidationError: If key format is invalid
    """
    if not key:
        raise ValidationError("XOR key cannot be empty")

    # Try to parse as hex
    if all(c in '0123456789abcdefABCDEF' for c in key):
        try:
            return bytes.fromhex(key)
        except ValueError as e:
            raise ValidationError(f"Invalid hex key '{key}': {e}")
    else:
        # Treat as string
        return key.encode('utf-8')


def validate_xor_keys(keys: Optional[List[str]]) -> List[str]:
    """
    Validate list of XOR keys

    Args:
        keys: List of XOR keys

    Returns:
        Validated list of keys

    Raises:
        ValidationError: If any key is invalid
    """
    if not keys:
        return ['9e', '0a61200d']  # Default KEYPLUG keys

    validated = []
    for i, key in enumerate(keys, 1):
        try:
            validate_xor_key(key)
            validated.append(key)
        except ValidationError as e:
            raise ValidationError(f"Invalid XOR key #{i}: {e}")

    return validated


def validate_image_format(file_path: Union[str, Path]) -> str:
    """
    Validate image file format by reading header

    Args:
        file_path: Path to image file

    Returns:
        Image format (gif, jpg, png)

    Raises:
        ValidationError: If format is not supported
    """
    path = validate_file_exists(file_path, "Image file")

    try:
        with open(path, 'rb') as f:
            header = f.read(16)
    except (OSError, IOError) as e:
        raise ValidationError(f"Cannot read image file {file_path}: {e}")

    if header.startswith(b'GIF8'):
        return 'gif'
    elif header.startswith(b'\xff\xd8\xff'):
        return 'jpg'
    elif header.startswith(b'\x89PNG'):
        return 'png'
    elif header.startswith(b'RIFF') and b'WEBP' in header:
        return 'webp'
    elif header.startswith(b'BM'):
        return 'bmp'
    else:
        raise ValidationError(
            f"Unsupported or invalid image format: {file_path}\n"
            f"Supported formats: GIF, JPEG, PNG, WebP, BMP"
        )


def atomic_write(file_path: Union[str, Path],
                content: Union[bytes, str],
                mode: str = 'wb') -> Path:
    """
    Atomically write file content using temp file + move

    Args:
        file_path: Destination file path
        content: Content to write
        mode: File mode ('wb' for binary, 'w' for text)

    Returns:
        Path to written file

    Raises:
        FileOperationError: If write fails
    """
    path = Path(file_path)

    # Create temp file in same directory for atomic move
    try:
        temp_fd, temp_path = tempfile.mkstemp(
            dir=path.parent,
            prefix=f".tmp_{path.name}_",
            suffix='.tmp'
        )

        # Write content
        with os.fdopen(temp_fd, mode) as f:
            f.write(content)

        # Atomic move
        shutil.move(temp_path, path)

        return path

    except (OSError, IOError, PermissionError) as e:
        # Clean up temp file if it exists
        try:
            if 'temp_path' in locals():
                os.unlink(temp_path)
        except:
            pass
        raise FileOperationError(f"Failed to write file {file_path}: {e}")


def safe_file_read(file_path: Union[str, Path],
                   mode: str = 'rb',
                   max_size: Optional[int] = None) -> Union[bytes, str]:
    """
    Safely read file with size limits

    Args:
        file_path: Path to file
        mode: Read mode ('rb' for binary, 'r' for text)
        max_size: Maximum file size in bytes (None = no limit)

    Returns:
        File content

    Raises:
        ValidationError: If file too large
        FileOperationError: If read fails
    """
    path = validate_file_exists(file_path)

    # Check size
    if max_size is not None:
        size = path.stat().st_size
        if size > max_size:
            raise ValidationError(
                f"File too large: {size:,} bytes (max: {max_size:,} bytes)"
            )

    try:
        with open(path, mode) as f:
            return f.read()
    except (OSError, IOError) as e:
        raise FileOperationError(f"Failed to read file {file_path}: {e}")


def get_safe_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal

    Args:
        filename: Original filename

    Returns:
        Safe filename
    """
    # Remove path separators and dangerous characters
    safe = filename.replace('/', '_').replace('\\', '_').replace('..', '_')
    safe = ''.join(c for c in safe if c.isalnum() or c in '._- ')

    # Ensure not empty
    if not safe or safe.strip() in ('', '.', '..'):
        safe = 'output'

    return safe.strip()


def setup_logging(verbose: bool = False,
                 log_file: Optional[str] = None,
                 name: Optional[str] = None) -> logging.Logger:
    """
    Setup logging with consistent format

    Args:
        verbose: Enable verbose/debug logging
        log_file: Optional file to log to
        name: Logger name (default: root logger)

    Returns:
        Configured logger
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Clear existing handlers
    logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Format
    if verbose:
        fmt = logging.Formatter(
            '[%(asctime)s] %(levelname)s [%(name)s:%(lineno)d] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    else:
        fmt = logging.Formatter('[%(levelname)s] %(message)s')

    console_handler.setFormatter(fmt)
    logger.addHandler(console_handler)

    # File handler
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(fmt)
            logger.addHandler(file_handler)
        except (OSError, IOError) as e:
            logger.warning(f"Cannot create log file {log_file}: {e}")

    return logger


def check_dependencies(required: List[str],
                      optional: List[str] = None) -> Tuple[bool, List[str]]:
    """
    Check if required dependencies are available

    Args:
        required: List of required module names
        optional: List of optional module names

    Returns:
        Tuple of (all_required_available, list_of_missing_modules)
    """
    import importlib

    missing = []

    # Check required
    for module in required:
        try:
            importlib.import_module(module)
        except ImportError:
            missing.append(module)

    # Check optional (just warn, don't add to missing)
    if optional:
        for module in optional:
            try:
                importlib.import_module(module)
            except ImportError:
                logging.debug(f"Optional dependency not available: {module}")

    all_available = len(missing) == 0
    return all_available, missing


class ProgressIndicator:
    """Simple progress indicator for long operations"""

    def __init__(self, total: int, description: str = "Progress", width: int = 50):
        """
        Initialize progress indicator

        Args:
            total: Total number of items/bytes
            description: Description to display
            width: Width of progress bar in characters
        """
        self.total = total
        self.description = description
        self.width = width
        self.current = 0
        self.start_time = time.time()
        self.last_update = 0

    def update(self, increment: int = 1, force: bool = False):
        """
        Update progress

        Args:
            increment: Amount to increment
            force: Force update even if update interval not reached
        """
        self.current += increment

        # Only update every 0.1 seconds to avoid overhead
        now = time.time()
        if not force and (now - self.last_update) < 0.1:
            return

        self.last_update = now
        self._display()

    def _display(self):
        """Display progress bar"""
        if self.total == 0:
            percent = 100
        else:
            percent = min(100, int(100 * self.current / self.total))

        filled = int(self.width * percent / 100)
        bar = '█' * filled + '░' * (self.width - filled)

        # Calculate speed
        elapsed = time.time() - self.start_time
        if elapsed > 0 and self.current > 0:
            speed = self.current / elapsed
            if self.current < self.total:
                eta = (self.total - self.current) / speed
                eta_str = f"ETA: {eta:.1f}s"
            else:
                eta_str = "Done"
        else:
            eta_str = ""

        # Format current/total
        if self.total > 1024 * 1024:
            # Show in MB
            current_mb = self.current / (1024 * 1024)
            total_mb = self.total / (1024 * 1024)
            size_str = f"{current_mb:.1f}/{total_mb:.1f} MB"
        elif self.total > 1024:
            # Show in KB
            current_kb = self.current / 1024
            total_kb = self.total / 1024
            size_str = f"{current_kb:.1f}/{total_kb:.1f} KB"
        else:
            size_str = f"{self.current}/{self.total} bytes"

        # Print progress bar
        sys.stderr.write(f"\r{self.description}: [{bar}] {percent}% {size_str} {eta_str}   ")
        sys.stderr.flush()

    def finish(self):
        """Mark progress as complete"""
        self.current = self.total
        self._display()
        sys.stderr.write("\n")
        sys.stderr.flush()


def with_progress(operation: Callable, total_size: int, description: str = "Processing",
                 chunk_size: int = 8192) -> any:
    """
    Wrap an operation with a progress indicator

    Args:
        operation: Function to execute
        total_size: Total size for progress tracking
        description: Description for progress bar
        chunk_size: Size of chunks to process

    Returns:
        Result of operation
    """
    progress = ProgressIndicator(total_size, description)

    try:
        result = operation(progress)
        progress.finish()
        return result
    except Exception as e:
        progress.finish()
        raise
