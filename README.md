# OpenVPN ACL Sync Script

This script synchronizes **OpenVPN client access rules (ACLs)** with `iptables` (FORWARD chain).  
It uses OpenVPN configuration files (`ipp.txt` and `ccd/`) to automatically generate firewall rules that restrict client access to only the networks explicitly allowed.

## How It Works

- Reads the OpenVPN `ipp.txt` file (maps client names to IP addresses).
- Reads client-specific configuration files from the `ccd/` directory.
- Extracts `route` directives (CIDR or netmask notation) from each client's CCD file.
- Creates or refreshes a dedicated iptables chain (`OVPN_ACL`):
  - Ensures it is linked into the `FORWARD` chain.
  - Allows return traffic via `conntrack`.
  - Adds `ACCEPT` rules for each client → allowed network.
  - Drops all other traffic from OpenVPN clients.

## Requirements

- Linux with `iptables` (or `iptables-nft`).
- OpenVPN server configured with:
  - `ipp.txt` at `/etc/openvpn/ipp.txt`
  - CCD directory at `/etc/openvpn/ccd/`

## Usage

```bash
# Run normally (updates iptables rules)
./openvpn-fw.sh

# Test mode (dry-run, shows what would be executed)
./openvpn-fw.sh --dry-run

