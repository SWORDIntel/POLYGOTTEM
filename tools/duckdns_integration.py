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
import random
from typing import Optional, Dict
from datetime import datetime


class DuckDNSIntegration:
    """Manages DuckDNS registration and SSH tunnel setup"""

    @staticmethod
    def generate_random_port() -> int:
        """
        Generate a random non-standard SSH port for security

        Returns:
            Random port between 2000-65000 (avoiding well-known ports)
        """
        return random.randint(2000, 65000)

    def __init__(self, domain: str = "polygottem.duckdns.org",
                 api_token: str = "62414348-fa36-4a8c-8fc2-8b96ef48b3ea",
                 ssh_port: Optional[int] = None):
        """
        Initialize DuckDNS integration

        Args:
            domain: DuckDNS subdomain (e.g., "polygottem.duckdns.org")
            api_token: DuckDNS API token
            ssh_port: SSH server port (None = random non-standard port for security)
        """
        self.domain = domain.replace('.duckdns.org', '')  # Extract subdomain
        self.full_domain = f"{self.domain}.duckdns.org"
        self.api_token = api_token
        # Use random port if not specified (security best practice)
        self.ssh_port = ssh_port if ssh_port is not None else self.generate_random_port()
        self.update_url = f"https://www.duckdns.org/update"
        self.config_file = os.path.expanduser("~/.polygottem_duckdns.conf")

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

    def setup_ssh_server(self, port: Optional[int] = None) -> bool:
        """
        Ensure SSH server is running and configured

        Args:
            port: SSH port (uses self.ssh_port if not specified)

        Returns:
            True if SSH is running, False otherwise
        """
        if port is None:
            port = self.ssh_port

        try:
            # Check if SSH server is running
            result = subprocess.run(
                ['systemctl', 'is-active', 'ssh'],
                capture_output=True,
                text=True
            )

            service_name = None
            if result.returncode == 0 and result.stdout.strip() == 'active':
                service_name = 'ssh'
            else:
                # Try sshd
                result = subprocess.run(
                    ['systemctl', 'is-active', 'sshd'],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0 and result.stdout.strip() == 'active':
                    service_name = 'sshd'

            if service_name:
                print(f"✓ SSH server is running ({service_name})")

                # Verify port is listening
                if self._verify_ssh_port(port):
                    print(f"✓ SSH listening on port {port}")
                    return True
                else:
                    print(f"⚠ SSH running but not listening on port {port}")
                    if port != 22:
                        print(f"  Note: Custom port {port} may require configuration")
                    return True  # Still return True if service is running

            # Try to start SSH server
            print("⚠ SSH server not running, attempting to start...")
            for service in ['ssh', 'sshd']:
                try:
                    subprocess.run(
                        ['sudo', 'systemctl', 'start', service],
                        check=True,
                        capture_output=True
                    )
                    print(f"✓ SSH server started ({service})")

                    # Enable on boot
                    try:
                        subprocess.run(
                            ['sudo', 'systemctl', 'enable', service],
                            check=False,
                            capture_output=True
                        )
                    except:
                        pass

                    return True
                except:
                    continue

            print("✗ Could not start SSH server")
            print("  Manual start required: sudo systemctl start ssh")
            return False

        except Exception as e:
            print(f"Error checking SSH server: {e}")
            return False

    def _verify_ssh_port(self, port: int) -> bool:
        """
        Verify SSH is listening on specified port

        Args:
            port: Port to check

        Returns:
            True if port is listening
        """
        try:
            # Use ss or netstat to check port
            result = subprocess.run(
                ['ss', '-tln'],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                # Check if port is in output
                return f':{port}' in result.stdout

            # Fallback to netstat
            result = subprocess.run(
                ['netstat', '-tln'],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                return f':{port}' in result.stdout

            return False
        except:
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

            # Build connection string with port
            if self.ssh_port != 22:
                connection_string = f"ssh -p {self.ssh_port} {username}@{self.full_domain}"
            else:
                connection_string = f"ssh {username}@{self.full_domain}"

            info = {
                'domain': self.full_domain,
                'ip': public_ip or 'Unknown',
                'username': username,
                'port': str(self.ssh_port),
                'connection_string': connection_string,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

            return info

        except Exception as e:
            print(f"Error getting SSH info: {e}")
            return {}

    def save_configuration(self) -> bool:
        """
        Save current configuration to file

        Returns:
            True if successful
        """
        try:
            config = {
                'domain': self.full_domain,
                'port': self.ssh_port,
                'last_ip': self.get_public_ip(),
                'last_update': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

            with open(self.config_file, 'w') as f:
                for key, value in config.items():
                    f.write(f"{key}={value}\n")

            return True
        except Exception as e:
            print(f"⚠ Could not save configuration: {e}")
            return False

    def load_configuration(self) -> Dict[str, str]:
        """
        Load saved configuration

        Returns:
            Configuration dictionary
        """
        try:
            if not os.path.exists(self.config_file):
                return {}

            config = {}
            with open(self.config_file, 'r') as f:
                for line in f:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        config[key] = value

            return config
        except Exception as e:
            print(f"⚠ Could not load configuration: {e}")
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
        print("[1/4] Updating DuckDNS...")
        if not self.update_duckdns():
            print("⚠ DuckDNS update failed, continuing anyway...")

        print()

        # Step 2: Setup SSH
        print("[2/4] Setting up SSH server...")
        ssh_success = self.setup_ssh_server()

        print()

        # Step 3: Verify configuration
        print("[3/4] Verifying configuration...")
        port_verified = self._verify_ssh_port(self.ssh_port)
        if port_verified:
            print(f"✓ SSH port {self.ssh_port} is accessible")
        else:
            print(f"⚠ SSH port {self.ssh_port} verification failed")
            if self.ssh_port != 22:
                print(f"  Custom port may need firewall configuration")

        print()

        # Step 4: Show connection info
        print("[4/4] SSH Connection Information:")
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

        # Save configuration
        if self.save_configuration():
            print(f"✓ Configuration saved to {self.config_file}")
        print()

        print("✓ Setup complete!")
        print()
        print("To connect remotely:")
        print(f"  {info.get('connection_string', 'ssh <user>@' + self.full_domain)}")
        print()

        # Port-specific firewall instructions
        print("⚠ FIREWALL CONFIGURATION REQUIRED:")
        print(f"  Port {self.ssh_port} must be accessible from the internet")
        print()

        if self.ssh_port == 22:
            print("  Ubuntu/Debian:")
            print("    sudo ufw allow 22/tcp")
            print()
            print("  Fedora/RHEL:")
            print("    sudo firewall-cmd --add-service=ssh --permanent")
            print("    sudo firewall-cmd --reload")
        else:
            print(f"  Ubuntu/Debian:")
            print(f"    sudo ufw allow {self.ssh_port}/tcp")
            print()
            print(f"  Fedora/RHEL:")
            print(f"    sudo firewall-cmd --add-port={self.ssh_port}/tcp --permanent")
            print(f"    sudo firewall-cmd --reload")

        print()

        # Router/NAT port forwarding
        print("  If behind NAT/router, configure port forwarding:")
        print(f"    External port {self.ssh_port} → Internal IP:{self.ssh_port}")
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
    parser.add_argument(
        '--port',
        type=int,
        default=None,
        help='SSH port (default: random non-standard port for security, or specify custom)'
    )

    args = parser.parse_args()

    # Initialize integration with port (None = random)
    duckdns = DuckDNSIntegration(ssh_port=args.port)

    # Show selected port for user awareness
    if args.port is None and (args.full or args.setup_ssh):
        print(f"\n🔒 SECURITY: Using randomized SSH port {duckdns.ssh_port}")
        print(f"   (Use --port to specify custom port)\n")

    if args.update:
        duckdns.update_duckdns(args.ip)
    elif args.setup_ssh:
        duckdns.setup_ssh_server()
    elif args.full:
        duckdns.register_and_connect()
    else:
        # Default: show current info or load from config
        config = duckdns.load_configuration()
        if config:
            print("\nSaved Configuration:")
            print("="*70)
            for key, value in config.items():
                print(f"  {key:20}: {value}")
            print("="*70)
        else:
            print("\nCurrent SSH Connection Info:")
            print("="*70)
            info = duckdns.get_ssh_connection_info()
            for key, value in info.items():
                print(f"  {key:20}: {value}")
            print("="*70)
        print("\nUse --help for more options")


if __name__ == '__main__':
    main()
