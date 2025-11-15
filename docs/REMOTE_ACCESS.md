# Remote Access via DuckDNS

## Overview

POLYGOTTEM now includes **DuckDNS integration** for remote SSH access after exploit generation. This feature automatically registers your public IP with `polygottem.duckdns.org` and sets up SSH access.

## Features

✅ **Automatic IP Registration** - Updates DuckDNS with your current public IP
✅ **SSH Server Setup** - Ensures SSH server is running
✅ **Connection Information** - Provides easy-to-use SSH connection string
✅ **Integrated Workflow** - Offered at the end of all workflows
✅ **Zero Configuration** - Works out-of-the-box

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
```bash
# Ubuntu/Debian
sudo apt install openssh-server
sudo systemctl start ssh
sudo systemctl enable ssh

# Fedora/RHEL
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
    api_token="62414348-fa36-4a8c-8fc2-8b96ef48b3ea"
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

# Reverse tunnel
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

**Last Updated:** 2025-11-15
**Version:** 2.0.2
