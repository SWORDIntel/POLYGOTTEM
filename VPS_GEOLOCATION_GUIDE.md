# VPS Geolocation Manager - Complete Guide

## Overview

The VPS Geolocation Manager automates worldwide VPS server configuration with accurate IP geolocation through WHOIS database manipulation, WireGuard/WARP setup, and BGP configuration.

Based on techniques from: https://blog.lyc8503.net/en/post/asn-5-worldwide-servers/

## Features

✅ **WireGuard/WARP Configuration**
- Automated config generation for Cloudflare WARP
- Geolocation-preserving routing rules
- Installation scripts for all major Linux distros

✅ **IP Geolocation Management**
- RIPE WHOIS database object generation
- Geofeed CSV for bulk database updates
- Multi-provider database support (Maxmind, IPInfo, DB-IP)

✅ **BGP Configuration**
- BIRD daemon configuration generation
- ASN routing setup
- Peer management

✅ **Verification Tools**
- Multi-database geolocation checking
- Automated verification scripts
- Cloudflare trace integration

✅ **Multi-Provider Support**
- AWS, DigitalOcean, Vultr, Linode
- Hetzner, OVH, custom providers
- Provider-specific optimizations

## Quick Start

### Interactive Mode

```bash
# Launch interactive manager
python3 -m tools.vps_geo_manager --interactive

# Follow prompts to:
# 1. Add VPS servers
# 2. Configure geolocation
# 3. Export all configs
# 4. Generate verification scripts
```

### Single Server Setup

```bash
# Generate WARP config for a server
python3 -m tools.vps_geo_manager --generate-warp \
    --ip 1.2.3.4 \
    --country US \
    --region California \
    --output ./server-configs/
```

## Workflow Overview

### 1. **Server Configuration**

Add your VPS servers with location details:

```python
from tools.vps_geo_manager import VPSServer, VPSProvider

server = VPSServer(
    hostname="vps-us-west-01",
    ip_address="1.2.3.4",
    ipv6_address="2001:db8::1/48",
    country_code="US",
    region="California",
    provider=VPSProvider.DIGITALOCEAN,
    asn="AS64512"
)
```

### 2. **Generate Configurations**

The manager generates:
- **WireGuard/WARP config** (`warp.conf`)
- **Installation script** (`install_warp_*.sh`)
- **RIPE WHOIS object** (`ripe_inet6num.txt`)
- **BIRD BGP config** (for ASN holders)
- **Geofeed CSV** (bulk updates)

### 3. **Deploy to Server**

```bash
# Copy configs to server
scp vps_configs/vps-us-west-01/* root@1.2.3.4:/tmp/

# SSH to server
ssh root@1.2.3.4

# Run installation
cd /tmp
chmod +x install_warp_vps-us-west-01.sh
./install_warp_vps-us-west-01.sh

# Generate WireGuard keys
wg genkey | tee privatekey | wg pubkey > publickey

# Edit config with your keys
vim /etc/wireguard/wg0.conf

# Start WARP
wg-quick up wg0
systemctl enable wg-quick@wg0
```

### 4. **Update WHOIS Database**

**For RIPE Members:**

```bash
# Submit inet6num object
# 1. Login to RIPE Database: https://apps.db.ripe.net/db-web-ui/
# 2. Create new inet6num object
# 3. Copy content from ripe_inet6num.txt
# 4. Submit for approval

# Updates take 3 days to 2 weeks to propagate
```

**For Non-RIPE Members:**

Use Geofeed for automated updates:

```bash
# 1. Host geofeed.csv on your web server
wget https://example.com/geofeed.csv

# 2. Add to WHOIS remarks:
remarks: geofeed https://example.com/geofeed.csv

# 3. Databases will crawl and update automatically
```

### 5. **Verify Geolocation**

```bash
# Run verification script
./vps_configs/verify_geo.sh

# Check individual IPs
curl -s https://1.1.1.1/cdn-cgi/trace | grep -E "(ip|loc)"
curl -s https://ipinfo.io/1.2.3.4/json | jq .

# Use IPLark for batch queries
# https://iplark.com/
```

## WireGuard/WARP Configuration

### How It Works

Cloudflare's WARP assigns public IPs with **geolocation matching your source IP**. By connecting from a VPS in a specific country, you get an IP geolocated to that country.

### Configuration Template

```ini
[Interface]
PrivateKey = YOUR_PRIVATE_KEY
Address = 1.2.3.4/32
Address = 2001:db8::1/128
DNS = 1.1.1.1, 1.0.0.1
MTU = 1280

# Critical: Route from assigned IP through main table
PostUp = ip -4 rule add from 1.2.3.4 lookup main
PostDown = ip -4 rule delete from 1.2.3.4 lookup main
PostUp = ip -6 rule add from 2001:db8::1 lookup main
PostDown = ip -6 rule delete from 2001:db8::1 lookup main

[Peer]
PublicKey = CLOUDFLARE_PUBLIC_KEY
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = [2001:db8::1]:2408
PersistentKeepalive = 25
```

### Key Points

- **PostUp rules** ensure traffic from WARP IP uses main routing table
- This preserves geolocation association
- IPv6 endpoint recommended for better connectivity
- MTU 1280 prevents fragmentation issues

## WHOIS Database Configuration

### RIPE inet6num Object

Required fields:
- `inet6num`: Your IPv6 subnet (minimum /48 recommended)
- `netname`: Network name
- `country`: 2-letter country code (THIS SETS GEOLOCATION)
- `admin-c`, `tech-c`: Contact handles
- `mnt-by`: Maintainer object
- `remarks`: Additional location info

### Database Update Timeline

| Database | Update Time | Notes |
|----------|-------------|-------|
| RIPE/WHOIS | 1-3 days | Direct submission |
| Maxmind | 3-14 days | Crawls WHOIS |
| IPInfo | 3-14 days | Crawls WHOIS |
| DB-IP | 3-14 days | Crawls WHOIS |
| Cloudflare | +1-2 weeks | Lags Maxmind |

**Total wait time: ~1 month for full propagation**

## BGP Configuration (Advanced)

For ASN holders, configure BGP announcements:

### BIRD Configuration

```bash
# Generated automatically by vps_geo_manager
router id 1.2.3.4;

protocol bgp peer_AS64496 {
    local as 64512;
    neighbor 203.0.113.1 as 64496;

    ipv6 {
        import none;
        export where proto = "static";
    };
}

# Announce your subnet
protocol static {
    ipv6;
    route 2001:db8::/48 reject;
}
```

### Verification

```bash
# Check BGP status
birdc show protocols all

# Verify route announcement
birdc show route all

# Check on external tools
# https://bgp.he.net/
# https://bgpview.io/
```

## Geofeed Format

CSV format for bulk geolocation updates:

```csv
# subnet,country,region,city,postal_code
2001:db8::/48,US,California,San Francisco,94102
2001:db8:1::/48,UK,England,London,
2001:db8:2::/48,JP,Tokyo,Tokyo,100-0001
```

### Hosting Geofeed

```bash
# 1. Generate geofeed
python3 -m tools.vps_geo_manager --export-configs

# 2. Host on web server
cp vps_configs/geofeed.csv /var/www/html/

# 3. Make it accessible
chmod 644 /var/www/html/geofeed.csv

# 4. Verify accessibility
curl https://example.com/geofeed.csv

# 5. Add to WHOIS
remarks: geofeed https://example.com/geofeed.csv
```

## Verification Methods

### 1. Cloudflare Trace

```bash
# Direct check
curl -s https://1.1.1.1/cdn-cgi/trace | grep -E "(ip|loc|colo)"

# Example output:
# ip=1.2.3.4
# loc=US
# colo=SJC
```

### 2. IPInfo.io

```bash
curl -s https://ipinfo.io/1.2.3.4/json | jq .

# Output includes:
# - country
# - region
# - city
# - org (ASN info)
```

### 3. IP-API

```bash
curl -s "http://ip-api.com/json/1.2.3.4" | jq .

# Free tier: 45 requests/minute
```

### 4. IPLark (Batch Queries)

Visit https://iplark.com/ to check multiple IPs across databases:
- Maxmind
- IPInfo
- DB-IP
- IP2Location
- And more

## Multi-Server Deployment

### Scenario: 5 Worldwide VPS Servers

```bash
# 1. Configure all servers interactively
python3 -m tools.vps_geo_manager --interactive

# Add servers:
# - vps-us-west (US, California)
# - vps-eu-central (DE, Frankfurt)
# - vps-asia-east (JP, Tokyo)
# - vps-oceania (AU, Sydney)
# - vps-south-america (BR, São Paulo)

# 2. Export all configs
# Choose: Export Configs
# Output: vps_configs/

# 3. Deploy to each server
for server in vps-*; do
    scp -r vps_configs/$server/* root@$server:/tmp/
    ssh root@$server "cd /tmp && ./install_warp_*.sh"
done

# 4. Configure keys on each server
# (Manual step - generate and configure WireGuard keys)

# 5. Submit WHOIS updates
# - Upload geofeed.csv to web server
# - Add geofeed URL to WHOIS remarks
# - Or submit individual inet6num objects to RIPE

# 6. Wait for propagation (1 month)

# 7. Verify all servers
./vps_configs/verify_geo.sh
```

## Troubleshooting

### Issue: Geolocation Not Updating

**Symptoms:**
- WHOIS shows correct country
- Geolocation databases show wrong location

**Solutions:**
1. Check WHOIS submission was accepted
2. Wait longer (can take 2 weeks)
3. Submit correction directly to databases:
   - Maxmind: https://www.maxmind.com/en/geoip-data-correction
   - IPInfo: https://ipinfo.io/corrections
   - DB-IP: https://db-ip.com/db/ip-location-api.html

### Issue: WARP Not Assigning Correct IP

**Symptoms:**
- WARP connects but IP geolocation is wrong
- Assigned IP doesn't match VPS location

**Solutions:**
1. Verify source IP (VPS IP) is correctly geolocated first
2. Check PostUp routing rules are working:
   ```bash
   ip rule list
   # Should show rule for WARP IP
   ```
3. Restart WARP:
   ```bash
   wg-quick down wg0
   wg-quick up wg0
   ```

### Issue: BGP Routes Not Announced

**Symptoms:**
- BIRD shows peer established
- Routes not visible on BGP looking glasses

**Solutions:**
1. Check BIRD export filters:
   ```bash
   birdc show route export peer_ASxxxx
   ```
2. Verify static route exists:
   ```bash
   birdc show route protocol static
   ```
3. Check peer configuration accepts your announcements
4. Verify prefix is within your allocated space

## Integration with POLYGOTTEM

### Use Cases

**1. Distributed C2 Infrastructure**
- Deploy C2 servers worldwide
- Accurate geolocation for evasion
- Region-specific targeting

**2. Payload Delivery Network**
- Geo-distribute polyglot files
- Location-based payload selection
- Regional execution methods

**3. Testing Environment**
- Simulate attacks from different countries
- Test geo-blocking bypasses
- Verify region-specific vulnerabilities

### Workflow Integration

```bash
# 1. Setup VPS infrastructure
python3 -m tools.vps_geo_manager --interactive

# 2. Generate polyglot payloads for each region
python3 -m tools.polyglot_orchestrator_enhanced

# 3. Deploy payloads to regional servers
# 4. Configure execution methods per region
# 5. Monitor and adjust based on results
```

## Advanced Techniques

### Multi-Homed Configuration

For servers with multiple IP addresses:

```bash
# Configure multiple WARP interfaces
wg-quick up wg0  # US IP
wg-quick up wg1  # UK IP
wg-quick up wg2  # JP IP

# Route based on destination
ip rule add to 203.0.113.0/24 lookup wg0_table
ip rule add to 198.51.100.0/24 lookup wg1_table
```

### Automated Monitoring

```bash
# Cron job to verify geolocation daily
0 2 * * * /opt/polygottem/vps_configs/verify_geo.sh | mail -s "Geo Verification" admin@example.com
```

### Dynamic Geolocation Updates

```python
# Update geofeed programmatically
from tools.vps_geo_manager import VPSGeoManager, GeolocationConfig

manager = VPSGeoManager()

# Add new location
new_geo = GeolocationConfig(
    subnet="2001:db8:3::/48",
    country_code="SG",
    region="Singapore",
    city="Singapore"
)

# Regenerate geofeed
manager.generate_geofeed([new_geo], "geofeed.csv")

# Upload to web server
# (implement your deployment method)
```

## Best Practices

### Security

✅ **Do:**
- Use strong WireGuard keys
- Rotate keys regularly
- Limit BGP peer access
- Monitor geolocation changes
- Keep configs in version control

❌ **Don't:**
- Share WHOIS credentials
- Use default passwords
- Expose WARP configs publicly
- Announce routes you don't own
- Forget to update geofeed

### Performance

✅ **Optimize:**
- Use IPv6 when possible
- Set MTU correctly (1280 for WARP)
- Monitor latency to peers
- Use persistent keepalive
- Enable hardware acceleration

### Maintenance

✅ **Regular Tasks:**
- Check geolocation monthly
- Update WHOIS annually
- Review BGP announcements
- Test failover scenarios
- Document configuration changes

## Resources

### Official Documentation
- RIPE Database: https://www.ripe.net/manage-ips-and-asns/db/
- BIRD BGP: https://bird.network.cz/
- WireGuard: https://www.wireguard.com/
- Cloudflare WARP: https://developers.cloudflare.com/warp-client/

### Geolocation Databases
- Maxmind: https://www.maxmind.com/
- IPInfo: https://ipinfo.io/
- DB-IP: https://db-ip.com/
- IP2Location: https://www.ip2location.com/

### Verification Tools
- IPLark: https://iplark.com/
- BGP Tools: https://bgp.he.net/
- BGP View: https://bgpview.io/
- RIPE Stat: https://stat.ripe.net/

### Reference Article
- Original technique: https://blog.lyc8503.net/en/post/asn-5-worldwide-servers/

## Support

For issues or questions:
1. Check this guide first
2. Review the verification script output
3. Check WHOIS database status
4. Wait for propagation (1 month)
5. Submit corrections to databases if needed

## License

Educational/Research Use Only - Authorized Infrastructure Management

---

Generated by POLYGOTTEM VPS Geolocation Manager v2.0
