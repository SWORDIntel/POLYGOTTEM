#!/usr/bin/env python3
"""
Polyglot Image Payload Extractor
=================================
Extracts and decrypts payloads from polyglot images.

EDUCATIONAL/RESEARCH USE ONLY
This tool demonstrates payload extraction for security research.

Author: SWORDIntel
Date: 2025-11-08
"""

import sys
import os
import argparse
import subprocess
import logging
from pathlib import Path

# Import validation utilities
try:
    from validation_utils import (
        validate_file_exists, validate_output_path, validate_xor_keys,
        atomic_write, setup_logging, ValidationError, FileOperationError
    )
except ImportError:
    # Fallback if run standalone
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from validation_utils import (
        validate_file_exists, validate_output_path, validate_xor_keys,
        atomic_write, setup_logging, ValidationError, FileOperationError
    )


class PolyglotExtractor:
    """Extracts and decrypts payloads from polyglot images"""

    # Image format EOF markers
    EOF_MARKERS = {
        'gif': b'\x3b',
        'jpg': b'\xff\xd9',
        'jpeg': b'\xff\xd9',
        'png': b'\x49\x45\x4e\x44\xae\x42\x60\x82',
    }

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.logger = setup_logging(verbose=verbose, name='polyglot_extract')

    def log(self, message):
        """Print if verbose mode enabled"""
        if self.verbose:
            self.logger.debug(message)
        else:
            self.logger.info(message)

    def xor_decrypt(self, data, key):
        """XOR decryption (same as encryption)"""
        if isinstance(key, str):
            key = bytes.fromhex(key) if all(c in '0123456789abcdefABCDEF' for c in key) else key.encode()

        decrypted = bytearray(len(data))
        key_len = len(key)

        for i in range(len(data)):
            decrypted[i] = data[i] ^ key[i % key_len]

        return bytes(decrypted)

    def multi_layer_decrypt(self, data, keys):
        """Apply multiple XOR layers in reverse order"""
        result = data
        # Reverse order for decryption
        for key in reversed(keys):
            self.log(f"Removing XOR layer with key: {key if isinstance(key, str) else key.hex()}")
            result = self.xor_decrypt(result, key)
        return result

    def detect_format(self, file_path):
        """Detect image format from header"""
        with open(file_path, 'rb') as f:
            header = f.read(16)

        if header.startswith(b'GIF8'):
            return 'gif'
        elif header.startswith(b'\xff\xd8\xff'):
            return 'jpg'
        elif header.startswith(b'\x89PNG'):
            return 'png'
        else:
            # Try by extension
            ext = Path(file_path).suffix.lower().lstrip('.')
            if ext in self.EOF_MARKERS:
                return ext
            return None

    def find_eof(self, data, img_format):
        """Find EOF marker position"""
        eof_marker = self.EOF_MARKERS.get(img_format)
        if not eof_marker:
            return None

        eof_pos = data.rfind(eof_marker)
        if eof_pos == -1:
            return None

        return eof_pos + len(eof_marker)

    def extract_payload(self, image_path, output_path=None, xor_keys=None, force=False):
        """
        Extract encrypted payload from polyglot image

        Args:
            image_path: Path to polyglot image
            output_path: Where to save extracted payload (default: auto-generate)
            xor_keys: List of XOR keys for decryption
            force: Allow overwriting existing output files

        Returns:
            Tuple of (path_to_extracted_payload, payload_type)

        Raises:
            ValidationError: If inputs are invalid
            FileOperationError: If file operations fail
        """
        # Validate inputs
        try:
            image_path = validate_file_exists(image_path, "Polyglot image")
            xor_keys = validate_xor_keys(xor_keys)
        except ValidationError as e:
            self.logger.error(f"Validation failed: {e}")
            raise

        self.log(f"Reading polyglot file: {image_path}")
        try:
            with open(image_path, 'rb') as f:
                data = f.read()
        except (OSError, IOError) as e:
            raise FileOperationError(f"Failed to read polyglot file: {e}")

        # Detect format
        img_format = self.detect_format(image_path)
        if not img_format:
            raise ValueError("Cannot detect image format")

        self.log(f"Detected format: {img_format.upper()}")

        # Find EOF
        eof_pos = self.find_eof(data, img_format)
        if eof_pos is None:
            raise ValueError(f"Cannot find EOF marker for {img_format}")

        # Check for appended data
        if eof_pos >= len(data):
            raise ValueError("No appended data found (file ends at EOF marker)")

        encrypted_payload = data[eof_pos:]
        self.log(f"Found {len(encrypted_payload):,} bytes after EOF at offset {eof_pos:,}")

        if len(encrypted_payload) == 0:
            raise ValueError("No payload data found")

        # Decrypt
        self.log(f"Decrypting with {len(xor_keys)} layer(s)")
        decrypted = self.multi_layer_decrypt(encrypted_payload, xor_keys)

        # Validate decrypted payload
        if not self._validate_decrypted_payload(decrypted):
            self.logger.warning(
                "Decrypted payload validation failed. "
                "It may be corrupted or encrypted with different keys."
            )

        # Auto-generate output path
        if output_path is None:
            base = Path(image_path).stem
            output_path = f"{base}_extracted_payload.bin"

        # Validate output path
        try:
            output_path = validate_output_path(output_path, allow_overwrite=force)
        except ValidationError as e:
            self.logger.error(f"Invalid output path: {e}")
            raise

        self.log(f"Writing decrypted payload: {output_path}")
        try:
            atomic_write(output_path, decrypted, mode='wb')
        except FileOperationError as e:
            self.logger.error(f"Failed to write payload: {e}")
            raise

        # Detect payload type
        payload_type = self.detect_payload_type(decrypted)

        print(f"\n[+] Payload extracted successfully!")
        print(f"    Image: {image_path}")
        print(f"    EOF position: {eof_pos:,} bytes")
        print(f"    Encrypted size: {len(encrypted_payload):,} bytes")
        print(f"    Decrypted size: {len(decrypted):,} bytes")
        print(f"    Output: {output_path}")
        print(f"    Detected type: {payload_type}")

        return output_path, payload_type

    def _validate_decrypted_payload(self, data: bytes) -> bool:
        """
        Validate that decrypted payload appears legitimate

        Args:
            data: Decrypted payload bytes

        Returns:
            True if payload appears valid
        """
        if len(data) == 0:
            return False

        # Check for known file signatures
        signatures = [
            b'\x7fELF',           # ELF binary
            b'MZ',                # PE/EXE binary
            b'#!/',               # Shebang script
            b'PK\x03\x04',        # ZIP archive
            b'\x89PNG',           # PNG image
            b'GIF8',              # GIF image
            b'\xff\xd8\xff',      # JPEG image
            b'<?xml',             # XML file
            b'<html',             # HTML file
            b'{',                 # JSON/JavaScript (maybe)
        ]

        # Check if starts with known signature
        for sig in signatures:
            if data.startswith(sig):
                return True

        # Check if mostly printable (likely text/script)
        sample_size = min(len(data), 1024)
        printable_count = sum(1 for b in data[:sample_size] if 32 <= b <= 126 or b in (9, 10, 13))
        if printable_count / sample_size > 0.7:
            return True

        # Check for high entropy (might be compressed/encrypted)
        # Very low entropy suggests decryption failed (all zeros, repeated bytes)
        if len(set(data[:1024])) < 10:
            return False

        # If we get here, it's probably valid but unknown format
        return True

    def detect_payload_type(self, data):
        """Detect what kind of payload this is"""
        if data.startswith(b'\x7fELF'):
            return "ELF binary (Linux executable)"
        elif data.startswith(b'MZ'):
            return "PE binary (Windows executable)"
        elif data.startswith(b'#!/'):
            return "Shell script"
        elif data.startswith(b'#!') or b'\n' in data[:100]:
            return "Script file"
        elif data.startswith(b'PK\x03\x04'):
            return "ZIP archive"
        else:
            # Check if mostly printable
            printable = sum(32 <= b <= 126 for b in data[:1024])
            if printable / min(len(data), 1024) > 0.8:
                return "Text/script file"
            return "Binary data (unknown)"


def main():
    parser = argparse.ArgumentParser(
        description='Extract payloads from polyglot images',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Extract with default KEYPLUG keys
  %(prog)s suspicious.gif

  # Extract with custom keys
  %(prog)s image.jpg -k d3 -k 410d200d

  # Extract and execute (DANGEROUS!)
  %(prog)s payload.gif --execute

  # Auto-detect and try common keys
  %(prog)s unknown.png --brute-force

WARNING: For educational and authorized security research only!
Never execute payloads from untrusted sources!
        """
    )

    parser.add_argument('image', help='Polyglot image file')
    parser.add_argument('-o', '--output', help='Output file for extracted payload')
    parser.add_argument('-k', '--key', dest='keys', action='append',
                       help='XOR key (hex or string, can be used multiple times)')
    parser.add_argument('-x', '--execute', action='store_true',
                       help='Execute payload after extraction (DANGEROUS!)')
    parser.add_argument('--brute-force', action='store_true',
                       help='Try common KEYPLUG keys automatically')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--force', action='store_true',
                       help='Overwrite output file if it exists')

    args = parser.parse_args()

    extractor = PolyglotExtractor(verbose=args.verbose)

    # Brute force mode
    if args.brute_force:
        common_keys = [
            ['9e'],
            ['d3'],
            ['a5'],
            ['9e', '0a61200d'],
            ['d3', '410d200d'],
            ['9e', '0a61200d', '41414141'],
        ]

        print("[*] Trying common KEYPLUG key combinations...")
        for i, keys in enumerate(common_keys, 1):
            try:
                print(f"\n[*] Attempt {i}/{len(common_keys)}: Keys = {keys}")
                output_path, payload_type = extractor.extract_payload(
                    args.image,
                    args.output or f"payload_attempt_{i}.bin",
                    xor_keys=keys
                )

                # Check if it's a valid payload
                if 'ELF' in payload_type or 'PE' in payload_type or 'script' in payload_type.lower():
                    print(f"\n[+] SUCCESS! Valid payload found with keys: {keys}")
                    break
            except Exception as e:
                print(f"    Failed: {e}")
                continue
        else:
            print("\n[!] No valid payload found with common keys")
            return 1
    else:
        # Normal extraction
        try:
            output_path, payload_type = extractor.extract_payload(
                args.image,
                args.output,
                xor_keys=args.keys,
                force=args.force
            )
        except (ValidationError, FileOperationError) as e:
            print(f"[!] Error: {e}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"[!] Unexpected error: {e}", file=sys.stderr)
            if args.verbose:
                import traceback
                traceback.print_exc()
            return 1

    # Execute if requested
    if args.execute:
        print(f"\n[!] WARNING: About to execute extracted payload!")
        print(f"[!] Type: {payload_type}")
        response = input("[?] Are you sure? (type 'YES' to confirm): ")

        if response == 'YES':
            print(f"[*] Executing: {output_path}")
            try:
                # Make executable
                os.chmod(output_path, 0o755)
                # Execute
                subprocess.run([output_path], check=True)
            except Exception as e:
                print(f"[!] Execution failed: {e}", file=sys.stderr)
                return 1
        else:
            print("[*] Execution cancelled")

    return 0


if __name__ == '__main__':
    sys.exit(main())
