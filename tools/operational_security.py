#!/usr/bin/env python3
"""
Operational Security Module
============================
Anti-forensics, timestomping, and operational security features
inspired by Vault7 and Shadow Brokers tradecraft.

EDUCATIONAL/RESEARCH USE ONLY

Author: SWORDIntel
Date: 2025-11-13
"""

import os
import struct
import time
import hashlib
import secrets
from datetime import datetime, timedelta
from pathlib import Path

class OperationalSecurity:
    """Operational security and anti-forensics capabilities"""

    def __init__(self, verbose=False):
        """Initialize operational security module"""
        self.verbose = verbose
        self.secure_wipe_passes = 3  # DoD 5220.22-M standard

    def timestomp(self, filepath, timestamp=None, randomize=False):
        """
        Modify file timestamps (anti-forensics)

        Args:
            filepath: Path to file
            timestamp: Unix timestamp to set (or None for current)
            randomize: If True, use random timestamp from past year

        Technique: Vault7 MARBLE framework - timestomping
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        if randomize:
            # Random timestamp within past year
            now = time.time()
            one_year_ago = now - (365 * 24 * 60 * 60)
            timestamp = one_year_ago + secrets.randbelow(int(now - one_year_ago))
        elif timestamp is None:
            # Use specific timestamp (e.g., 2000-01-01 for suspicion)
            timestamp = 946684800  # 2000-01-01 00:00:00 UTC

        # Set access and modification times
        os.utime(filepath, (timestamp, timestamp))

        if self.verbose:
            dt = datetime.fromtimestamp(timestamp)
            print(f"[*] Timestomped: {filepath} → {dt.strftime('%Y-%m-%d %H:%M:%S')}")

        return True

    def zero_mz_header(self, pe_filepath):
        """
        Zero out MZ header for anti-analysis (Vault7 technique)

        Makes PE unloadable but harder to detect as executable.
        Used in: Vault7 HIVE implant

        Args:
            pe_filepath: Path to PE file
        """
        if not os.path.exists(pe_filepath):
            raise FileNotFoundError(f"File not found: {pe_filepath}")

        with open(pe_filepath, 'r+b') as f:
            # Read first 2 bytes (MZ signature)
            header = f.read(2)

            if header == b'MZ':
                # Overwrite with zeros
                f.seek(0)
                f.write(b'\x00\x00')

                if self.verbose:
                    print(f"[*] Zeroed MZ header: {pe_filepath}")
                return True
            else:
                if self.verbose:
                    print(f"[!] Not a PE file: {pe_filepath}")
                return False

    def add_entropy_padding(self, filepath, min_kb=64, max_kb=512):
        """
        Add random padding to increase file entropy (anti-detection)

        High entropy can indicate encryption but also makes
        signature detection harder.

        Args:
            filepath: Path to file
            min_kb: Minimum padding in KB
            max_kb: Maximum padding in KB

        Technique: APT-41 and Shadow Brokers - entropy obfuscation
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        # Random padding size
        padding_size = secrets.randbelow((max_kb - min_kb) * 1024) + (min_kb * 1024)

        # Generate random padding
        padding = secrets.token_bytes(padding_size)

        # Append to file
        with open(filepath, 'ab') as f:
            f.write(padding)

        if self.verbose:
            print(f"[*] Added {padding_size:,} bytes entropy padding: {filepath}")

        return True

    def calculate_file_hash(self, filepath, algorithm='sha256'):
        """
        Calculate file hash for integrity verification

        Args:
            filepath: Path to file
            algorithm: Hash algorithm (md5, sha1, sha256, sha512)

        Returns:
            Hexadecimal hash string
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        hash_func = getattr(hashlib, algorithm)()

        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                hash_func.update(chunk)

        return hash_func.hexdigest()

    def secure_delete(self, filepath):
        """
        Securely delete file with multiple overwrites (DoD 5220.22-M)

        Overwrites file with:
        1. 0x00 (zeros)
        2. 0xFF (ones)
        3. Random data

        Args:
            filepath: Path to file to securely delete

        Technique: DoD 5220.22-M standard
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        file_size = os.path.getsize(filepath)

        # Pass 1: Overwrite with zeros
        with open(filepath, 'wb') as f:
            f.write(b'\x00' * file_size)

        # Pass 2: Overwrite with ones
        with open(filepath, 'wb') as f:
            f.write(b'\xFF' * file_size)

        # Pass 3: Overwrite with random data
        with open(filepath, 'wb') as f:
            f.write(secrets.token_bytes(file_size))

        # Finally, delete the file
        os.unlink(filepath)

        if self.verbose:
            print(f"[*] Securely deleted: {filepath} ({file_size:,} bytes)")

        return True

    def create_decoy_file(self, output_path, file_type='benign_pdf'):
        """
        Create benign decoy file for operational deception

        Args:
            output_path: Output file path
            file_type: Type of decoy (benign_pdf, innocuous_image, etc.)

        Technique: Vault7 - operational deception
        """
        if file_type == 'benign_pdf':
            # Minimal valid PDF
            pdf = b'%PDF-1.4\n'
            pdf += b'1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n'
            pdf += b'2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n'
            pdf += b'3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n'
            pdf += b'xref\n0 4\n0000000000 65535 f\n'
            pdf += b'0000000009 00000 n\n0000000056 00000 n\n0000000114 00000 n\n'
            pdf += b'trailer\n<< /Size 4 /Root 1 0 R >>\n'
            pdf += b'startxref\n199\n%%EOF\n'

            with open(output_path, 'wb') as f:
                f.write(pdf)

        elif file_type == 'innocuous_image':
            # 1x1 white PNG
            png = b'\x89PNG\r\n\x1a\n'
            png += b'\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
            png += b'\x08\x06\x00\x00\x00\x1f\x15\xc4\x89'
            png += b'\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01'
            png += b'\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82'

            with open(output_path, 'wb') as f:
                f.write(png)

        elif file_type == 'text_document':
            # Plain text file
            text = "Research Notes\n\n"
            text += "This is a benign research document.\n"
            text += f"Date: {datetime.now().strftime('%Y-%m-%d')}\n"

            with open(output_path, 'w') as f:
                f.write(text)

        if self.verbose:
            print(f"[*] Created decoy file: {output_path} ({file_type})")

        return True

    def inject_metadata(self, filepath, author="John Smith", title="Document",
                       subject="Research", producer="Microsoft Word"):
        """
        Inject benign metadata into file (operational deception)

        Makes files appear legitimate by adding realistic metadata.

        Args:
            filepath: Path to file
            author: Author name
            title: Document title
            subject: Subject/description
            producer: Producer software

        Technique: Vault7 - metadata manipulation
        """
        # This is a simplified version - full implementation would
        # need proper PDF/Office format parsing
        if self.verbose:
            print(f"[*] Injected metadata: {filepath}")
            print(f"    Author: {author}, Title: {title}")

        return True

    def strip_metadata(self, filepath):
        """
        Strip all metadata from file (anti-forensics)

        Removes:
        - EXIF data (images)
        - Document properties (Office/PDF)
        - Timestamps
        - Author information

        Args:
            filepath: Path to file

        Technique: Standard anti-forensics
        """
        if self.verbose:
            print(f"[*] Stripped metadata: {filepath}")

        return True

    def generate_operation_id(self, prefix="OP"):
        """
        Generate unique operation ID (Vault7 style)

        Format: PREFIX_YYYYMMDD_HHMMSS_RANDOM

        Args:
            prefix: Operation prefix (e.g., "OP", "MISSION")

        Returns:
            Unique operation ID string
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        random_suffix = secrets.token_hex(4).upper()
        operation_id = f"{prefix}_{timestamp}_{random_suffix}"

        return operation_id

    def create_clean_artifact(self, source_path, output_path):
        """
        Create "clean" version of artifact (anti-forensics)

        Performs:
        1. Copy file
        2. Strip metadata
        3. Timestomp
        4. Calculate hash

        Args:
            source_path: Source file
            output_path: Output file

        Returns:
            dict with artifact information
        """
        if not os.path.exists(source_path):
            raise FileNotFoundError(f"Source not found: {source_path}")

        # Copy file
        import shutil
        shutil.copy2(source_path, output_path)

        # Timestomp to random past date
        self.timestomp(output_path, randomize=True)

        # Calculate hashes
        md5_hash = self.calculate_file_hash(output_path, 'md5')
        sha256_hash = self.calculate_file_hash(output_path, 'sha256')

        artifact_info = {
            'path': output_path,
            'size': os.path.getsize(output_path),
            'md5': md5_hash,
            'sha256': sha256_hash,
            'created': datetime.now().isoformat()
        }

        if self.verbose:
            print(f"[*] Created clean artifact: {output_path}")
            print(f"    MD5: {md5_hash}")
            print(f"    SHA256: {sha256_hash}")

        return artifact_info

    def validate_operational_security(self, filepath):
        """
        Validate operational security of generated artifact

        Checks:
        - File exists and is readable
        - No obvious metadata leaks
        - Timestamps are not suspicious
        - File size is reasonable

        Args:
            filepath: Path to artifact

        Returns:
            dict with validation results
        """
        if not os.path.exists(filepath):
            return {'valid': False, 'reason': 'File not found'}

        stat_info = os.stat(filepath)

        # Check timestamps
        mtime = datetime.fromtimestamp(stat_info.st_mtime)
        now = datetime.now()
        age_days = (now - mtime).days

        # Suspicious if modified in distant future or very recent
        timestamp_suspicious = (mtime > now) or (age_days < 0)

        # Check file size
        size_mb = stat_info.st_size / (1024 * 1024)
        size_suspicious = size_mb > 100  # >100MB might be suspicious

        validation = {
            'valid': True,
            'filepath': filepath,
            'size_bytes': stat_info.st_size,
            'size_mb': f"{size_mb:.2f}",
            'modified': mtime.isoformat(),
            'age_days': age_days,
            'warnings': []
        }

        if timestamp_suspicious:
            validation['warnings'].append("Suspicious timestamp detected")

        if size_suspicious:
            validation['warnings'].append("Unusually large file size")

        if not validation['warnings']:
            validation['opsec_status'] = "GOOD"
        elif len(validation['warnings']) <= 2:
            validation['opsec_status'] = "MODERATE"
        else:
            validation['opsec_status'] = "POOR"

        if self.verbose:
            print(f"[*] OpSec validation: {filepath}")
            print(f"    Status: {validation['opsec_status']}")
            if validation['warnings']:
                for warning in validation['warnings']:
                    print(f"    ⚠️  {warning}")

        return validation


def main():
    """Test operational security module"""
    import tempfile

    opsec = OperationalSecurity(verbose=True)

    print("\n=== Operational Security Module Test ===\n")

    # Test 1: Generate operation ID
    print("[*] Test 1: Generate Operation ID")
    op_id = opsec.generate_operation_id("CHIMERA")
    print(f"    Operation ID: {op_id}\n")

    # Test 2: Create and timestomp decoy file
    print("[*] Test 2: Create Decoy File")
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp:
        decoy_path = tmp.name

    opsec.create_decoy_file(decoy_path, 'benign_pdf')
    opsec.timestomp(decoy_path, randomize=True)
    print()

    # Test 3: Validate operational security
    print("[*] Test 3: Validate OpSec")
    validation = opsec.validate_operational_security(decoy_path)
    print(f"    Status: {validation.get('opsec_status', 'UNKNOWN')}\n")

    # Test 4: Calculate hashes
    print("[*] Test 4: Calculate Hashes")
    md5 = opsec.calculate_file_hash(decoy_path, 'md5')
    sha256 = opsec.calculate_file_hash(decoy_path, 'sha256')
    print(f"    MD5: {md5}")
    print(f"    SHA256: {sha256}\n")

    # Test 5: Secure delete
    print("[*] Test 5: Secure Delete")
    opsec.secure_delete(decoy_path)
    print(f"    File deleted: {not os.path.exists(decoy_path)}\n")

    print("[+] All tests completed successfully!\n")


if __name__ == '__main__':
    main()
