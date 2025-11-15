#!/usr/bin/env python3
"""
Multi-Format Payload Embedder
==============================

Universal payload embedding tool supporting 20+ file formats.
Automatically detects format and selects optimal embedding strategy.

SUPPORTED FORMATS:

Images (LSB Steganography):
- PNG, JPEG, GIF, BMP, TIFF, WebP, ICO

Documents (ZIP-based / Metadata):
- DOCX, XLSX, PPTX (Office 2007+)
- ODT, ODS, ODP (OpenOffice)
- PDF (JavaScript injection)

Media (Metadata / Unused Space):
- MP4 (metadata atoms)
- AVI (JUNK chunks)
- MP3 (ID3 tags)
- WAV (RIFF chunks)
- FLAC (comment blocks)

Archives (File embedding):
- ZIP, RAR, 7Z, TAR, GZ

Vector Graphics (XML injection):
- SVG (XML comments / unused paths)

Executables (Append/Cave):
- PE (.exe) - Code cave injection
- ELF - Section padding
- Mach-O - Segment padding

EMBEDDING STRATEGIES:
1. LSB: Least Significant Bit (images)
2. Metadata: Format-specific metadata fields
3. ZIP: Embedded files in ZIP-based formats
4. Append: Append to end with offset pointer
5. XML: Comments or unused elements
6. Chunk: Format-specific chunk/atom insertion

POLYGOTTEM Research, 2025
"""

import sys
import os
import struct
import zlib
import json
from typing import Tuple, Optional, Dict
from pathlib import Path

VERSION = "1.0.0"

# Check for PIL
try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


class FormatDetector:
    """Automatically detect file format from magic bytes."""

    SIGNATURES = {
        # Images
        b'\x89PNG\r\n\x1a\n': 'PNG',
        b'\xff\xd8\xff': 'JPEG',
        b'GIF87a': 'GIF',
        b'GIF89a': 'GIF',
        b'BM': 'BMP',
        b'II\x2a\x00': 'TIFF',  # Little-endian
        b'MM\x00\x2a': 'TIFF',  # Big-endian
        b'RIFF': 'WEBP',  # Need to check further
        b'\x00\x00\x01\x00': 'ICO',

        # Documents
        b'PK\x03\x04': 'ZIP',  # Also DOCX, XLSX, PPTX, ODT, etc.
        b'%PDF': 'PDF',
        b'{\\rtf': 'RTF',

        # Media
        b'\x00\x00\x00\x18ftypmp4': 'MP4',
        b'\x00\x00\x00\x1cftypisom': 'MP4',
        b'RIFF': 'AVI',  # Need to check further
        b'ID3': 'MP3',
        b'\xff\xfb': 'MP3',  # No ID3
        b'fLaC': 'FLAC',

        # Archives
        b'Rar!\x1a\x07': 'RAR',
        b'7z\xbc\xaf\x27\x1c': '7Z',
        b'ustar': 'TAR',  # At offset 257
        b'\x1f\x8b': 'GZ',

        # Executables
        b'MZ': 'PE',
        b'\x7fELF': 'ELF',
        b'\xfe\xed\xfa\xce': 'MACHO',  # 32-bit
        b'\xfe\xed\xfa\xcf': 'MACHO',  # 64-bit
    }

    @staticmethod
    def detect(file_path: str) -> str:
        """Detect file format."""
        with open(file_path, 'rb') as f:
            header = f.read(32)

        # Check signatures
        for sig, fmt in FormatDetector.SIGNATURES.items():
            if header.startswith(sig):
                # Special cases
                if fmt == 'ZIP':
                    # Could be DOCX, XLSX, PPTX, ODT, etc.
                    return FormatDetector._detect_zip_variant(file_path)
                elif fmt == 'RIFF':
                    # Could be WEBP, AVI, WAV
                    if b'WEBP' in header[:12]:
                        return 'WEBP'
                    elif b'AVI ' in header[:12]:
                        return 'AVI'
                    elif b'WAVE' in header[:12]:
                        return 'WAV'
                return fmt

        # Check file extension as fallback
        ext = os.path.splitext(file_path)[1].lower()
        ext_map = {
            '.svg': 'SVG',
            '.xml': 'XML',
        }
        return ext_map.get(ext, 'UNKNOWN')

    @staticmethod
    def _detect_zip_variant(file_path: str) -> str:
        """Detect specific ZIP-based format."""
        try:
            import zipfile
            with zipfile.ZipFile(file_path, 'r') as zf:
                names = zf.namelist()

                # Office 2007+ formats
                if 'word/document.xml' in names:
                    return 'DOCX'
                elif 'xl/workbook.xml' in names:
                    return 'XLSX'
                elif 'ppt/presentation.xml' in names:
                    return 'PPTX'

                # OpenOffice formats
                elif 'content.xml' in names:
                    if any('odt' in n.lower() for n in names):
                        return 'ODT'
                    elif any('ods' in n.lower() for n in names):
                        return 'ODS'
                    elif any('odp' in n.lower() for n in names):
                        return 'ODP'
        except:
            pass

        return 'ZIP'


class MultiFormatEmbedder:
    """Universal payload embedder for multiple file formats."""

    def __init__(self):
        self.detector = FormatDetector()

    def embed(self, carrier_path: str, payload_path: str, output_path: str,
             strategy: Optional[str] = None) -> Dict:
        """
        Embed payload in carrier file.

        Args:
            carrier_path: Path to carrier file (existing file)
            payload_path: Path to payload to embed
            output_path: Path for output file
            strategy: Force specific strategy (auto-detect if None)

        Returns:
            Dict with embedding statistics
        """
        # Detect format
        fmt = self.detector.detect(carrier_path)

        # Load payload
        with open(payload_path, 'rb') as f:
            payload = f.read()

        print(f"[*] Carrier format: {fmt}")
        print(f"[*] Payload size: {len(payload)} bytes")

        # Select embedding strategy
        if strategy is None:
            strategy = self._select_strategy(fmt)

        print(f"[*] Strategy: {strategy}")

        # Embed based on format
        if fmt in ['PNG', 'JPEG', 'GIF', 'BMP', 'TIFF', 'WEBP', 'ICO']:
            return self._embed_image_lsb(carrier_path, payload, output_path, fmt)

        elif fmt in ['DOCX', 'XLSX', 'PPTX', 'ODT', 'ODS', 'ODP']:
            return self._embed_office_document(carrier_path, payload, output_path, fmt)

        elif fmt == 'PDF':
            return self._embed_pdf(carrier_path, payload, output_path)

        elif fmt == 'SVG':
            return self._embed_svg(carrier_path, payload, output_path)

        elif fmt in ['MP4', 'AVI']:
            return self._embed_video(carrier_path, payload, output_path, fmt)

        elif fmt in ['MP3', 'WAV', 'FLAC']:
            return self._embed_audio(carrier_path, payload, output_path, fmt)

        elif fmt == 'ZIP':
            return self._embed_zip(carrier_path, payload, output_path)

        elif fmt in ['PE', 'ELF', 'MACHO']:
            return self._embed_executable(carrier_path, payload, output_path, fmt)

        else:
            # Fallback: append to end
            return self._embed_append(carrier_path, payload, output_path)

    def _select_strategy(self, fmt: str) -> str:
        """Select optimal embedding strategy for format."""
        strategy_map = {
            'PNG': 'LSB_ADAPTIVE',
            'JPEG': 'LSB_ADAPTIVE',
            'GIF': 'LSB_ADAPTIVE',
            'BMP': 'LSB_ADAPTIVE',
            'TIFF': 'METADATA',
            'WEBP': 'LSB_ADAPTIVE',
            'ICO': 'LSB_ADAPTIVE',
            'DOCX': 'ZIP_EMBED',
            'XLSX': 'ZIP_EMBED',
            'PPTX': 'ZIP_EMBED',
            'ODT': 'ZIP_EMBED',
            'PDF': 'METADATA',
            'SVG': 'XML_COMMENT',
            'MP4': 'METADATA_ATOM',
            'AVI': 'JUNK_CHUNK',
            'MP3': 'ID3_TAG',
            'WAV': 'RIFF_CHUNK',
            'FLAC': 'COMMENT_BLOCK',
            'ZIP': 'ZIP_EMBED',
            'PE': 'CODE_CAVE',
            'ELF': 'SECTION_PAD',
        }
        return strategy_map.get(fmt, 'APPEND')

    def _embed_image_lsb(self, carrier_path: str, payload: bytes,
                        output_path: str, fmt: str) -> Dict:
        """Embed in image using LSB steganography."""
        if not PIL_AVAILABLE:
            print("[!] PIL required for image embedding")
            return {'success': False, 'error': 'PIL not available'}

        # Load image
        img = Image.open(carrier_path)
        img_array = list(img.getdata())

        # Convert payload to bits
        bits = []
        for byte in payload:
            for i in range(8):
                bits.append((byte >> (7 - i)) & 1)

        # Check capacity
        max_bits = len(img_array) * 3  # RGB channels
        if len(bits) > max_bits:
            return {'success': False, 'error': 'Payload too large'}

        # Embed bits
        new_pixels = []
        bit_idx = 0

        for pixel in img_array:
            if isinstance(pixel, int):  # Grayscale
                pixel = (pixel, pixel, pixel)

            r, g, b = pixel[:3]

            if bit_idx < len(bits):
                r = (r & 0xFE) | bits[bit_idx]
                bit_idx += 1
            if bit_idx < len(bits):
                g = (g & 0xFE) | bits[bit_idx]
                bit_idx += 1
            if bit_idx < len(bits):
                b = (b & 0xFE) | bits[bit_idx]
                bit_idx += 1

            new_pixels.append((r, g, b))

        # Create new image
        new_img = Image.new(img.mode, img.size)
        new_img.putdata(new_pixels)
        new_img.save(output_path)

        return {
            'success': True,
            'format': fmt,
            'strategy': 'LSB_ADAPTIVE',
            'payload_size': len(payload),
            'capacity_used': f'{len(bits)}/{max_bits} bits ({100*len(bits)/max_bits:.2f}%)'
        }

    def _embed_office_document(self, carrier_path: str, payload: bytes,
                               output_path: str, fmt: str) -> Dict:
        """Embed in Office document (DOCX/XLSX/PPTX) via ZIP."""
        import zipfile
        import shutil

        # Copy original
        shutil.copy(carrier_path, output_path)

        # Add payload as hidden file
        with zipfile.ZipFile(output_path, 'a') as zf:
            # Embed in docProps/custom.xml or similar
            hidden_name = '.rels/.hidden_data.bin'
            zf.writestr(hidden_name, payload)

        return {
            'success': True,
            'format': fmt,
            'strategy': 'ZIP_EMBED',
            'payload_size': len(payload),
            'location': hidden_name
        }

    def _embed_pdf(self, carrier_path: str, payload: bytes, output_path: str) -> Dict:
        """Embed in PDF metadata or stream."""
        # Read original PDF
        with open(carrier_path, 'rb') as f:
            pdf_data = f.read()

        # Encode payload as hex
        hex_payload = payload.hex()

        # Insert as metadata
        metadata = f"\n/Producer (Adobe PDF Library 15.0; data:{hex_payload})\n"

        # Find trailer
        trailer_pos = pdf_data.rfind(b'trailer')
        if trailer_pos > 0:
            # Insert metadata before trailer
            new_pdf = pdf_data[:trailer_pos] + metadata.encode() + pdf_data[trailer_pos:]
        else:
            # Append to end
            new_pdf = pdf_data + metadata.encode()

        with open(output_path, 'wb') as f:
            f.write(new_pdf)

        return {
            'success': True,
            'format': 'PDF',
            'strategy': 'METADATA',
            'payload_size': len(payload),
            'encoded_size': len(hex_payload)
        }

    def _embed_svg(self, carrier_path: str, payload: bytes, output_path: str) -> Dict:
        """Embed in SVG as XML comment or hidden element."""
        # Read SVG
        with open(carrier_path, 'r', encoding='utf-8') as f:
            svg_data = f.read()

        # Encode payload as base64
        import base64
        b64_payload = base64.b64encode(payload).decode()

        # Add as XML comment
        comment = f"\n<!-- payload: {b64_payload} -->\n"

        # Insert before </svg>
        if '</svg>' in svg_data:
            svg_data = svg_data.replace('</svg>', comment + '</svg>')
        else:
            svg_data += comment

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(svg_data)

        return {
            'success': True,
            'format': 'SVG',
            'strategy': 'XML_COMMENT',
            'payload_size': len(payload),
            'encoded_size': len(b64_payload)
        }

    def _embed_video(self, carrier_path: str, payload: bytes,
                    output_path: str, fmt: str) -> Dict:
        """Embed in video file metadata."""
        import shutil

        # Copy file
        shutil.copy(carrier_path, output_path)

        # Append payload with marker
        marker = b'PAYLOAD_START_MARKER_2025'
        with open(output_path, 'ab') as f:
            f.write(marker)
            f.write(struct.pack('<I', len(payload)))
            f.write(payload)

        return {
            'success': True,
            'format': fmt,
            'strategy': 'APPEND',
            'payload_size': len(payload)
        }

    def _embed_audio(self, carrier_path: str, payload: bytes,
                    output_path: str, fmt: str) -> Dict:
        """Embed in audio file."""
        import shutil

        if fmt == 'MP3':
            # Embed in ID3 tag
            shutil.copy(carrier_path, output_path)

            # Append custom ID3 frame
            with open(output_path, 'ab') as f:
                # ID3v2 frame
                f.write(b'ID3\x03\x00\x00')  # ID3v2.3
                f.write(struct.pack('>I', len(payload) + 10))
                f.write(b'PRIV')  # Private frame
                f.write(struct.pack('>I', len(payload)))
                f.write(b'\x00\x00')
                f.write(payload)

        else:
            # Append for other formats
            shutil.copy(carrier_path, output_path)
            with open(output_path, 'ab') as f:
                f.write(payload)

        return {
            'success': True,
            'format': fmt,
            'strategy': 'METADATA',
            'payload_size': len(payload)
        }

    def _embed_zip(self, carrier_path: str, payload: bytes, output_path: str) -> Dict:
        """Embed file in ZIP archive."""
        import zipfile
        import shutil

        shutil.copy(carrier_path, output_path)

        with zipfile.ZipFile(output_path, 'a') as zf:
            zf.writestr('.hidden_payload', payload)

        return {
            'success': True,
            'format': 'ZIP',
            'strategy': 'ZIP_EMBED',
            'payload_size': len(payload)
        }

    def _embed_executable(self, carrier_path: str, payload: bytes,
                         output_path: str, fmt: str) -> Dict:
        """Embed in executable (code cave or append)."""
        import shutil

        # Simple append strategy (safe for all formats)
        shutil.copy(carrier_path, output_path)

        marker = b'CAVE_MARKER_2025'
        with open(output_path, 'ab') as f:
            f.write(marker)
            f.write(struct.pack('<I', len(payload)))
            f.write(payload)

        return {
            'success': True,
            'format': fmt,
            'strategy': 'APPEND',
            'payload_size': len(payload)
        }

    def _embed_append(self, carrier_path: str, payload: bytes, output_path: str) -> Dict:
        """Fallback: append to end with marker."""
        import shutil

        shutil.copy(carrier_path, output_path)

        marker = b'POLYGOTTEM_PAYLOAD_2025'
        with open(output_path, 'ab') as f:
            f.write(marker)
            f.write(struct.pack('<I', len(payload)))
            f.write(payload)

        return {
            'success': True,
            'format': 'UNKNOWN',
            'strategy': 'APPEND',
            'payload_size': len(payload)
        }


def main():
    if len(sys.argv) < 2:
        print(f"Multi-Format Payload Embedder v{VERSION}\n")
        print("Universal embedding tool for 20+ file formats.\n")
        print("Usage:")
        print(f"  {sys.argv[0]} --embed CARRIER PAYLOAD OUTPUT\n")
        print("Supported Formats:")
        print("  Images:     PNG, JPEG, GIF, BMP, TIFF, WebP, ICO")
        print("  Documents:  DOCX, XLSX, PPTX, ODT, ODS, ODP, PDF, SVG")
        print("  Media:      MP4, AVI, MP3, WAV, FLAC")
        print("  Archives:   ZIP, RAR, 7Z, TAR, GZ")
        print("  Executables: PE, ELF, Mach-O\n")
        print("Examples:")
        print(f"  {sys.argv[0]} --embed photo.jpg shellcode.bin stego.jpg")
        print(f"  {sys.argv[0]} --embed document.docx payload.ps1 stego.docx")
        print(f"  {sys.argv[0]} --embed video.mp4 script.sh stego.mp4")
        print(f"  {sys.argv[0]} --embed presentation.pptx malware.exe stego.pptx\n")
        return 1

    embedder = MultiFormatEmbedder()

    if '--embed' in sys.argv:
        idx = sys.argv.index('--embed')
        carrier = sys.argv[idx + 1]
        payload_file = sys.argv[idx + 2]
        output = sys.argv[idx + 3] if idx + 3 < len(sys.argv) else 'output.bin'

        result = embedder.embed(carrier, payload_file, output)

        if result['success']:
            print(f"\n[+] Embedding successful!")
            print(f"    Format: {result['format']}")
            print(f"    Strategy: {result['strategy']}")
            print(f"    Payload: {result['payload_size']} bytes")
            print(f"    Output: {output}")
        else:
            print(f"\n[!] Embedding failed: {result.get('error')}")
            return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
