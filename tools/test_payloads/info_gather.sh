#!/bin/bash
#
# Harmless PoC Payload - System Information Gatherer
# This demonstrates what a payload could do without being actually malicious
#

echo "================================"
echo "PoC Payload Executed Successfully!"
echo "================================"
echo ""
echo "[+] Extraction timestamp: $(date)"
echo "[+] Hostname: $(hostname)"
echo "[+] User: $(whoami)"
echo "[+] Working directory: $(pwd)"
echo "[+] Shell: $SHELL"
echo "[+] OS: $(uname -a)"
echo ""
echo "This is a HARMLESS test payload for demonstration purposes."
echo "In a real attack, this would be cryptd rootkit + XMRig miner!"
echo ""
echo "[*] Payload could now:"
echo "    - Install backdoor SSH keys"
echo "    - Download additional stages"
echo "    - Start cryptocurrency miner"
echo "    - Establish C2 connection"
echo "    - Create persistent cron jobs"
echo ""
echo "================================"
echo "PoC Complete - No harm done!"
echo "================================"

# Save execution proof
echo "[$(date)] PoC payload executed on $(hostname) by $(whoami)" >> /tmp/poc_execution.log
