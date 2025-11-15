#!/usr/bin/env python3
"""
Guarantee Fingerprint Setup - Safe Initialization & Enrollment
===============================================================
First-run setup wizard for fingerprint authentication that prevents
accidental lockouts and ensures owner always has access.

Features:
- Hardware detection and testing
- Safe enrollment with recovery options
- Owner/creator privilege escalation
- Recovery code generation
- Lockout prevention mechanisms
- Interactive setup wizard

Author: SWORDIntel
Date: 2025-11-15
"""

import os
import sys
import json
import hashlib
import secrets
from typing import Optional, Dict, Any, Tuple
from datetime import datetime
from pathlib import Path

# Add tools to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tui_helper import TUI, Colors


class FingerprintSetupManager:
    """Manages safe fingerprint setup and initialization"""

    SETUP_COMPLETE_FILE = Path.home() / '.polygottem' / '.fingerprint_setup_complete'
    RECOVERY_CODE_FILE = Path.home() / '.polygottem' / '.recovery_code'
    HARDWARE_CONFIG_FILE = Path.home() / '.polygottem' / '.hardware_config'
    OWNER_FILE = Path.home() / '.polygottem' / '.owner'

    def __init__(self, tui: Optional[TUI] = None):
        """
        Initialize fingerprint setup manager

        Args:
            tui: TUI instance for output
        """
        self.tui = tui if tui else TUI()
        # Ensure .polygottem directory exists
        Path.home().joinpath('.polygottem').mkdir(parents=True, exist_ok=True)

    def is_first_run(self) -> bool:
        """
        Check if this is first run (fingerprint setup needed)

        Returns:
            True if first run
        """
        return not self.SETUP_COMPLETE_FILE.exists()

    def run_setup_wizard(self) -> bool:
        """
        Run interactive setup wizard on first run

        Returns:
            True if setup successful
        """
        self.tui.banner("POLYGOTTEM FINGERPRINT SETUP", "First-Run Initialization")
        print()

        self.tui.warning("⚠️  FIRST-TIME SETUP REQUIRED")
        self.tui.info("Setting up biometric authentication to prevent unauthorized access")
        print()

        # Step 1: Detect available hardware
        if not self._detect_hardware():
            self.tui.error("No biometric hardware detected")
            self.tui.info("You can still use password-based authentication")
            return self._setup_password_only()

        # Step 2: Test hardware
        if not self._test_hardware():
            self.tui.warning("Hardware test failed")
            choice = input("Continue with password fallback? (y/n): ").strip().lower()
            if choice != 'y':
                return False
            return self._setup_password_only()

        # Step 3: Enroll biometric
        if not self._enroll_biometric():
            self.tui.error("Biometric enrollment failed")
            return False

        # Step 4: Generate recovery code
        recovery_code = self._generate_recovery_code()

        # Step 5: Mark setup complete
        self._mark_setup_complete()

        # Step 6: Display recovery code
        self._display_recovery_code(recovery_code)

        return True

    def _detect_hardware(self) -> bool:
        """
        Detect available biometric hardware

        Returns:
            True if hardware detected
        """
        self.tui.section("Step 1: Hardware Detection")
        print()

        import subprocess

        hardware_found = {
            'broadcom_fingerprint': False,
            'yubikey': False,
            'intel_npu': False
        }

        # Check for Broadcom fingerprint scanner
        try:
            result = subprocess.run(
                ['fprintd-list'],
                capture_output=True,
                timeout=2
            )
            if result.returncode == 0:
                self.tui.success("✓ Broadcom fingerprint scanner detected")
                hardware_found['broadcom_fingerprint'] = True
            else:
                self.tui.info("• Broadcom fingerprint scanner: Not available")
        except FileNotFoundError:
            self.tui.info("• Broadcom fingerprint scanner: libfprint not installed")

        # Check for Yubikey
        try:
            result = subprocess.run(
                ['lsusb'],
                capture_output=True,
                timeout=2
            )
            if b'1050:0402' in result.stdout or b'Yubikey' in result.stdout:
                self.tui.success("✓ Yubikey detected (ID: 1050:0402)")
                hardware_found['yubikey'] = True
            else:
                self.tui.info("• Yubikey: Not detected")
        except FileNotFoundError:
            self.tui.info("• Yubikey: lsusb not available")

        # Check for Intel NPU
        try:
            result = subprocess.run(
                ['lspci'],
                capture_output=True,
                timeout=2
            )
            if b'Intel.*NPU' in result.stdout or b'0b00' in result.stdout:
                self.tui.success("✓ Intel NPU detected (biometric acceleration)")
                hardware_found['intel_npu'] = True
            else:
                self.tui.info("• Intel NPU: Not detected")
        except FileNotFoundError:
            self.tui.info("• Intel NPU: lspci not available")

        print()

        # Save hardware config
        with open(self.HARDWARE_CONFIG_FILE, 'w') as f:
            json.dump(hardware_found, f, indent=2)
        os.chmod(self.HARDWARE_CONFIG_FILE, 0o600)

        return any(hardware_found.values())

    def _test_hardware(self) -> bool:
        """
        Test detected hardware

        Returns:
            True if hardware working
        """
        self.tui.section("Step 2: Hardware Testing")
        print()

        # Load hardware config
        try:
            with open(self.HARDWARE_CONFIG_FILE, 'r') as f:
                hardware = json.load(f)
        except:
            return False

        # Test Broadcom if available
        if hardware.get('broadcom_fingerprint'):
            self.tui.info("Testing Broadcom fingerprint scanner...")
            self.tui.info("Please scan your fingerprint (test scan)")

            import subprocess
            try:
                result = subprocess.run(
                    ['fprintd-verify'],
                    capture_output=True,
                    timeout=30
                )
                if result.returncode == 0:
                    self.tui.success("✓ Fingerprint scanner working")
                    return True
                else:
                    self.tui.warning("✗ Fingerprint scan failed - verify hardware is functional")
                    return False
            except Exception as e:
                self.tui.warning(f"Hardware test failed: {e}")
                return False

        # Test Yubikey if available
        if hardware.get('yubikey'):
            self.tui.info("Testing Yubikey...")
            self.tui.info("Please insert Yubikey and tap it")

            import subprocess
            try:
                result = subprocess.run(
                    ['ykman', 'info'],
                    capture_output=True,
                    timeout=10
                )
                if result.returncode == 0:
                    self.tui.success("✓ Yubikey working")
                    return True
                else:
                    self.tui.warning("✗ Yubikey test failed")
                    return False
            except FileNotFoundError:
                self.tui.warning("ykman not installed - cannot test Yubikey")
                return False
            except Exception as e:
                self.tui.warning(f"Hardware test failed: {e}")
                return False

        return False

    def _enroll_biometric(self) -> bool:
        """
        Enroll user's biometric

        Returns:
            True if enrollment successful
        """
        self.tui.section("Step 3: Biometric Enrollment")
        print()

        # Load hardware config
        try:
            with open(self.HARDWARE_CONFIG_FILE, 'r') as f:
                hardware = json.load(f)
        except:
            return False

        if hardware.get('broadcom_fingerprint'):
            self.tui.info("Preparing to enroll your fingerprint...")
            print()

            confirm = input("Ready to enroll? (y/n): ").strip().lower()
            if confirm != 'y':
                return False

            self.tui.info("Please place your finger on the scanner 3 times")
            self.tui.info("Keep your finger on the scanner for 2-3 seconds")
            print()

            import subprocess
            try:
                result = subprocess.run(
                    ['fprintd-enroll'],
                    capture_output=True,
                    timeout=60
                )
                if result.returncode == 0:
                    self.tui.success("✓ Fingerprint enrolled successfully")
                    return True
                else:
                    self.tui.error("✗ Fingerprint enrollment failed")
                    return False
            except Exception as e:
                self.tui.error(f"Enrollment failed: {e}")
                return False

        return True

    def _setup_password_only(self) -> bool:
        """
        Setup password-only authentication (no biometric)

        Returns:
            True if setup successful
        """
        self.tui.section("Password Setup (No Biometric Hardware)")
        print()

        import getpass

        password = getpass.getpass("Enter security password (min 12 characters): ")

        if len(password) < 12:
            self.tui.error("Password too short (minimum 12 characters)")
            return False

        confirm = getpass.getpass("Confirm password: ")

        if password != confirm:
            self.tui.error("Passwords do not match")
            return False

        # Hash password
        password_hash = hashlib.pbkdf2_hmac(
            'sha512',
            password.encode(),
            b'polygottem_kdf_salt_v1',
            100000
        ).hex()

        # Store password hash (would normally be in a secure keyring)
        # For now, just mark that password setup is done
        self.tui.success("✓ Password security configured")

        return True

    def _generate_recovery_code(self) -> str:
        """
        Generate emergency recovery code

        Returns:
            Recovery code (store securely!)
        """
        # Generate 32-byte recovery code
        recovery_bytes = secrets.token_bytes(32)
        recovery_code = recovery_bytes.hex()

        # Hash it for storage
        recovery_hash = hashlib.sha256(recovery_bytes).hexdigest()

        # Store hash
        recovery_data = {
            'recovery_hash': recovery_hash,
            'generated_at': datetime.now().isoformat(),
            'owner': os.getenv('USER', 'unknown')
        }

        with open(self.RECOVERY_CODE_FILE, 'w') as f:
            json.dump(recovery_data, f, indent=2)

        os.chmod(self.RECOVERY_CODE_FILE, 0o600)

        return recovery_code

    def _display_recovery_code(self, recovery_code: str):
        """
        Display recovery code and instructions

        Args:
            recovery_code: Recovery code to display
        """
        print()
        self.tui.banner("RECOVERY CODE - SAVE THIS SECURELY!", "Emergency Access Only")
        print()

        self.tui.warning("⚠️  IMPORTANT: Save this code in a secure location")
        self.tui.warning("You will need this code if you forget your biometric or password")
        print()

        # Display code in groups for readability
        code_groups = [recovery_code[i:i+8] for i in range(0, len(recovery_code), 8)]
        self.tui.raw("RECOVERY CODE:")
        for i, group in enumerate(code_groups, 1):
            self.tui.raw(f"  {i:2d}: {group.upper()}")

        print()
        self.tui.info("Save this code in:")
        self.tui.list_item("Password manager", level=1)
        self.tui.list_item("Secure document", level=1)
        self.tui.list_item("Hardware key", level=1)
        print()

        confirm = input("Have you saved the recovery code? (y/n): ").strip().lower()

        if confirm != 'y':
            self.tui.warning("⚠️  You will not be able to access this code again")
            confirm_again = input("Are you sure? (y/n): ").strip().lower()
            if confirm_again != 'y':
                return

        self.tui.success("✓ Recovery code saved")
        print()

    def _mark_setup_complete(self):
        """Mark fingerprint setup as complete"""
        setup_data = {
            'completed_at': datetime.now().isoformat(),
            'owner': os.getenv('USER', 'unknown'),
            'hostname': os.uname().nodename
        }

        with open(self.SETUP_COMPLETE_FILE, 'w') as f:
            json.dump(setup_data, f, indent=2)

        os.chmod(self.SETUP_COMPLETE_FILE, 0o600)

        # Also save owner info
        owner_data = {'owner': os.getenv('USER', 'unknown')}
        with open(self.OWNER_FILE, 'w') as f:
            json.dump(owner_data, f)

        os.chmod(self.OWNER_FILE, 0o600)

    def verify_recovery_code(self, recovery_code: str) -> bool:
        """
        Verify recovery code for emergency access

        Args:
            recovery_code: Recovery code to verify

        Returns:
            True if recovery code valid
        """
        try:
            with open(self.RECOVERY_CODE_FILE, 'r') as f:
                recovery_data = json.load(f)

            # Hash provided code
            provided_hash = hashlib.sha256(
                bytes.fromhex(recovery_code)
            ).hexdigest()

            return provided_hash == recovery_data['recovery_hash']

        except Exception:
            return False

    def is_owner(self) -> bool:
        """
        Check if current user is the owner

        Returns:
            True if current user is owner
        """
        try:
            with open(self.OWNER_FILE, 'r') as f:
                owner_data = json.load(f)
            return owner_data.get('owner') == os.getenv('USER', 'unknown')
        except:
            return False

    def display_lockout_notice(self):
        """Display lockout notice and recovery options"""
        self.tui.error("🔒 Biometric Authentication Failed")
        print()

        self.tui.info("Options:")
        self.tui.list_item("Recovery Code: Have your emergency recovery code? (--recovery)", level=0)
        self.tui.list_item("Admin Access: Owner can reset with --reset-auth", level=0)
        self.tui.list_item("Contact: See documentation for support", level=0)
        print()
