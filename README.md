# MikroTik OSSEC Active Response

This is a Go-based OSSEC active response script that integrates with MikroTik RouterOS to automatically block malicious IP addresses by adding them to an address list.

## Features

- Native RouterOS API implementation in Go (no external dependencies)
- Adds blocked IPs to a MikroTik address list
- Supports automatic timeout/expiration
- Optional TLS/SSL connection support
- Proper logging for OSSEC integration
- MD5 challenge-response authentication support for older RouterOS versions

## Prerequisites

- OSSEC/Wazuh server
- MikroTik router with RouterOS (tested on v6.x and v7.x)
- API access enabled on MikroTik
- Go 1.16+ for building the binary

## Installation

### 1. Build the Binary

```bash
go build -o mikrotik-block mikrotik-block.go
```

### 2. Install on OSSEC Server

```bash
# Copy binary to OSSEC active response directory
sudo cp mikrotik-block /var/ossec/active-response/bin/
sudo chmod 750 /var/ossec/active-response/bin/mikrotik-block
sudo chown root:ossec /var/ossec/active-response/bin/mikrotik-block
```

### 3. Configure Environment Variables

Create a configuration file for the script:

```bash
sudo nano /var/ossec/active-response/bin/mikrotik-config.sh
```

Add the following:

```bash
#!/bin/bash
export MIKROTIK_HOST="192.168.88.1"
export MIKROTIK_PORT="8728"
export MIKROTIK_USER="ossec"
export MIKROTIK_PASS="your_secure_password"
export MIKROTIK_LIST="ossec_blocked"
export MIKROTIK_TIMEOUT="24h"
export MIKROTIK_TLS="false"
```

```bash
sudo chmod 640 /var/ossec/active-response/bin/mikrotik-config.sh
sudo chown root:ossec /var/ossec/active-response/bin/mikrotik-config.sh
```

### 4. Create Wrapper Script

Create a wrapper script to load environment variables:

```bash
sudo nano /var/ossec/active-response/bin/mikrotik-block.sh
```

Add the following:

```bash
#!/bin/bash
# Load configuration
source /var/ossec/active-response/bin/mikrotik-config.sh

# Execute the Go binary with all arguments
/var/ossec/active-response/bin/mikrotik-block "$@"
```

```bash
sudo chmod 750 /var/ossec/active-response/bin/mikrotik-block.sh
sudo chown root:ossec /var/ossec/active-response/bin/mikrotik-block.sh
```

### 5. Configure MikroTik Router

#### Create a dedicated API user:

```routeros
/user add name=ossec group=full password=your_secure_password
```

For more restrictive permissions, create a custom group:

```routeros
/user group add name=ossec-api policy=api,read,write,policy,test
/user add name=ossec group=ossec-api password=your_secure_password
```

#### Enable API service:

```routeros
/ip service enable api
/ip service set api port=8728 address=YOUR_OSSEC_SERVER_IP
```

For TLS (recommended):

```routeros
/ip service enable api-ssl
/ip service set api-ssl port=8729 address=YOUR_OSSEC_SERVER_IP certificate=YOUR_CERT
```

#### Create the address list and firewall rule:

```routeros
# Create a firewall rule that uses the address list
/ip firewall filter add chain=input src-address-list=ossec_blocked action=drop \
    comment="OSSEC Active Response - Block malicious IPs" place-before=0

# For blocking forwarded traffic as well
/ip firewall filter add chain=forward src-address-list=ossec_blocked action=drop \
    comment="OSSEC Active Response - Block malicious IPs" place-before=0
```

### 6. Configure OSSEC

Edit `/var/ossec/etc/ossec.conf` and add the active response configuration:

```xml
<ossec_config>
  <command>
    <name>mikrotik-block</name>
    <executable>mikrotik-block.sh</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <active-response>
    <command>mikrotik-block</command>
    <location>local</location>
    <level>6</level>
    <timeout>86400</timeout>
  </active-response>
</ossec_config>
```

### 7. Restart OSSEC

```bash
sudo systemctl restart wazuh-manager
# or
sudo /var/ossec/bin/ossec-control restart
```

## Configuration Options

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MIKROTIK_HOST` | `192.168.88.1` | MikroTik router IP address |
| `MIKROTIK_PORT` | `8728` | API port (8728 for plain, 8729 for TLS) |
| `MIKROTIK_USER` | `admin` | API username |
| `MIKROTIK_PASS` | `` | API password |
| `MIKROTIK_LIST` | `ossec_blocked` | Address list name |
| `MIKROTIK_TIMEOUT` | `24h` | Auto-remove timeout (e.g., 1h, 24h, 7d) |
| `MIKROTIK_TLS` | `false` | Use TLS/SSL connection |

### OSSEC Active Response Parameters

- `level`: Minimum alert level to trigger (recommended: 6-10)
- `timeout`: How long to keep the block in seconds (86400 = 24 hours)
- `location`: Where to execute (local, server, defined-agent, all)

## Testing

### Manual Test

```bash
# Test adding an IP
sudo -u ossec /var/ossec/active-response/bin/mikrotik-block.sh add - 1.2.3.4 123 456

# Test removing an IP
sudo -u ossec /var/ossec/active-response/bin/mikrotik-block.sh delete - 1.2.3.4 123 456
```

### Verify on MikroTik

```routeros
/ip firewall address-list print where list=ossec_blocked
```

### Check OSSEC Logs

```bash
tail -f /var/ossec/logs/active-responses.log
tail -f /var/ossec/logs/ossec.log
```

## Security Considerations

1. **Use strong passwords** for the MikroTik API user
2. **Restrict API access** to only the OSSEC server IP
3. **Use TLS** for production environments (set `MIKROTIK_TLS=true` and use port 8729)
4. **Limit user permissions** - create a dedicated user group with minimal required permissions
5. **Monitor the address list** regularly to prevent legitimate IPs from being blocked
6. **Set appropriate timeouts** to automatically unblock IPs after a reasonable period
7. **Secure the config file** with proper permissions (640, owned by root:ossec)

## Troubleshooting

### Connection Issues

- Verify network connectivity: `telnet MIKROTIK_IP 8728`
- Check MikroTik API service is running: `/ip service print`
- Verify firewall rules allow OSSEC server to connect
- Check MikroTik logs: `/log print where topics~"api"`

### Authentication Failures

- Verify credentials are correct
- Check user has appropriate permissions
- Try connecting manually with another API client to verify credentials

### IPs Not Being Blocked

- Check OSSEC logs for active response execution
- Verify firewall rules reference the correct address list name
- Check if IPs are being added to the list: `/ip firewall address-list print`
- Ensure firewall rules are in the correct order (use `place-before=0`)

### Permission Denied

- Ensure binary has correct ownership and permissions
- Verify OSSEC user can execute the script
- Check log file permissions

## Advanced Usage

### Custom Alert Levels

Block only critical threats (level 10+):

```xml
<active-response>
  <command>mikrotik-block</command>
  <location>local</location>
  <level>10</level>
  <timeout>604800</timeout>  <!-- 7 days -->
</active-response>
```

### Specific Rule IDs

Block only specific attack types:

```xml
<active-response>
  <command>mikrotik-block</command>
  <location>local</location>
  <rules_id>5710,5711,5712</rules_id>  <!-- SSH authentication failures -->
  <timeout>3600</timeout>  <!-- 1 hour -->
</active-response>
```

### Multiple Address Lists

Create different lists for different severity levels by running multiple instances with different configurations.

## License

This script is provided as-is for use with OSSEC/Wazuh and MikroTik RouterOS.

## Contributing

Contributions are welcome! Please test thoroughly before submitting pull requests.
