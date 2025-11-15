#!/usr/bin/env python3
"""
DuckDNS Integration for POLYGOTTEM
===================================
Provides dynamic DNS updates and SSH tunnel setup for remote access.

EDUCATIONAL/RESEARCH USE ONLY

Author: SWORDIntel
Date: 2025-11-15
"""

import os
import sys
import socket
import subprocess
import requests
from typing import Optional, Dict
from datetime import datetime


class DuckDNSIntegration:
    """Manages DuckDNS registration and SSH tunnel setup"""

    def __init__(self, domain: str = "polygottem.duckdns.org",
                 api_token: str = "62414348-fa36-4a8c-8fc2-8b96ef48b3ea"):
        """
        Initialize DuckDNS integration

        Args:
            domain: DuckDNS subdomain (e.g., "polygottem.duckdns.org")
            api_token: DuckDNS API token
        """
        self.domain = domain.replace('.duckdns.org', '')  # Extract subdomain
        self.full_domain = f"{self.domain}.duckdns.org"
        self.api_token = api_token
        self.update_url = f"https://www.duckdns.org/update"

    def get_public_ip(self) -> Optional[str]:
        """
        Get current public IP address

        Returns:
            Public IP address or None if failed
        """
        try:
            # Try multiple IP detection services
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

        except Exception as e:
            print(f"Error getting public IP: {e}")
            return None

    def update_duckdns(self, ip: Optional[str] = None) -> bool:
        """
        Update DuckDNS with current IP

        Args:
            ip: IP address to register (auto-detect if None)

        Returns:
            True if update successful, False otherwise
        """
        try:
            # Get IP if not provided
            if ip is None:
                ip = self.get_public_ip()
                if ip is None:
                    print("Failed to detect public IP")
                    return False

            # Update DuckDNS
            params = {
                'domains': self.domain,
                'token': self.api_token,
                'ip': ip
            }

            response = requests.get(self.update_url, params=params, timeout=10)

            if response.status_code == 200 and response.text.strip() == 'OK':
                print(f"✓ DuckDNS updated: {self.full_domain} → {ip}")
                return True
            else:
                print(f"✗ DuckDNS update failed: {response.text}")
                return False

        except Exception as e:
            print(f"Error updating DuckDNS: {e}")
            return False

    def setup_ssh_server(self, port: int = 22) -> bool:
        """
        Ensure SSH server is running

        Args:
            port: SSH port (default: 22)

        Returns:
            True if SSH is running, False otherwise
        """
        try:
            # Check if SSH server is running
            result = subprocess.run(
                ['systemctl', 'is-active', 'ssh'],
                capture_output=True,
                text=True
            )

            if result.returncode == 0 and result.stdout.strip() == 'active':
                print(f"✓ SSH server is running on port {port}")
                return True

            # Try alternative service names
            for service in ['ssh', 'sshd']:
                try:
                    subprocess.run(
                        ['sudo', 'systemctl', 'start', service],
                        check=True,
                        capture_output=True
                    )
                    print(f"✓ SSH server started ({service})")
                    return True
                except:
                    continue

            print("⚠ Could not start SSH server (may need manual start)")
            return False

        except Exception as e:
            print(f"Error checking SSH server: {e}")
            return False

    def get_ssh_connection_info(self) -> Dict[str, str]:
        """
        Get SSH connection information

        Returns:
            Dictionary with connection details
        """
        try:
            # Get current username
            username = os.getenv('USER', 'unknown')

            # Get public IP
            public_ip = self.get_public_ip()

            info = {
                'domain': self.full_domain,
                'ip': public_ip or 'Unknown',
                'username': username,
                'port': '22',
                'connection_string': f"ssh {username}@{self.full_domain}",
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

            return info

        except Exception as e:
            print(f"Error getting SSH info: {e}")
            return {}

    def setup_autossh_tunnel(self, remote_host: str, remote_port: int = 2222,
                            local_port: int = 22) -> bool:
        """
        Setup persistent SSH reverse tunnel using autossh

        Args:
            remote_host: Remote server to tunnel through
            remote_port: Remote port for reverse tunnel
            local_port: Local SSH port

        Returns:
            True if tunnel setup successful
        """
        try:
            # Check if autossh is installed
            result = subprocess.run(
                ['which', 'autossh'],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                print("⚠ autossh not installed - install with: sudo apt install autossh")
                return False

            # Create autossh reverse tunnel
            tunnel_cmd = [
                'autossh',
                '-M', '0',
                '-f',
                '-N',
                '-R', f'{remote_port}:localhost:{local_port}',
                '-o', 'ServerAliveInterval=30',
                '-o', 'ServerAliveCountMax=3',
                remote_host
            ]

            subprocess.Popen(tunnel_cmd)
            print(f"✓ Reverse SSH tunnel established: {remote_host}:{remote_port} → localhost:{local_port}")
            return True

        except Exception as e:
            print(f"Error setting up autossh tunnel: {e}")
            return False

    def register_and_connect(self) -> bool:
        """
        Complete workflow: Update DuckDNS, start SSH, show connection info

        Returns:
            True if all steps successful
        """
        print("\n" + "="*70)
        print("DuckDNS Registration & SSH Setup")
        print("="*70 + "\n")

        # Step 1: Update DuckDNS
        print("[1/3] Updating DuckDNS...")
        if not self.update_duckdns():
            print("⚠ DuckDNS update failed, continuing anyway...")

        print()

        # Step 2: Setup SSH
        print("[2/3] Setting up SSH server...")
        self.setup_ssh_server()

        print()

        # Step 3: Show connection info
        print("[3/3] SSH Connection Information:")
        print("-" * 70)

        info = self.get_ssh_connection_info()
        if info:
            print(f"  Domain:     {info['domain']}")
            print(f"  Public IP:  {info['ip']}")
            print(f"  Username:   {info['username']}")
            print(f"  Port:       {info['port']}")
            print()
            print(f"  Connection: {info['connection_string']}")
            print(f"  Updated:    {info['timestamp']}")

        print("-" * 70)
        print()

        print("✓ Setup complete!")
        print()
        print("To connect remotely:")
        print(f"  {info.get('connection_string', 'ssh <user>@' + self.full_domain)}")
        print()
        print("⚠ Make sure your firewall allows SSH connections (port 22)")
        print()

        return True


def main():
    """CLI interface for DuckDNS integration"""
    import argparse

    parser = argparse.ArgumentParser(
        description="DuckDNS Integration for POLYGOTTEM"
    )
    parser.add_argument(
        '--update',
        action='store_true',
        help='Update DuckDNS with current IP'
    )
    parser.add_argument(
        '--setup-ssh',
        action='store_true',
        help='Setup SSH server'
    )
    parser.add_argument(
        '--full',
        action='store_true',
        help='Complete setup (update + SSH)'
    )
    parser.add_argument(
        '--ip',
        type=str,
        help='Manually specify IP address'
    )

    args = parser.parse_args()

    # Initialize integration
    duckdns = DuckDNSIntegration()

    if args.update:
        duckdns.update_duckdns(args.ip)
    elif args.setup_ssh:
        duckdns.setup_ssh_server()
    elif args.full:
        duckdns.register_and_connect()
    else:
        # Default: show current info
        print("\nCurrent SSH Connection Info:")
        print("="*70)
        info = duckdns.get_ssh_connection_info()
        for key, value in info.items():
            print(f"  {key:20}: {value}")
        print("="*70)
        print("\nUse --help for more options")


if __name__ == '__main__':
    main()
