#!/usr/bin/env bash
# Sync OpenVPN ACLs -> iptables (FORWARD) based on ipp.txt and ccd/
# Alma/RHEL/CentOS: iptables-nft ensures compatibility with nftables.
set -euo pipefail

IPP_FILE="/etc/openvpn/ipp.txt"
CCD_DIR="/etc/openvpn/ccd"
CHAIN="OVPN_ACL"

DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

need() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing $1 in PATH"; exit 1; }; }

need iptables
[[ -r "$IPP_FILE" ]] || { echo "ERROR: missing file $IPP_FILE"; exit 1; }
[[ -d "$CCD_DIR"  ]] || { echo "ERROR: missing directory $CCD_DIR"; exit 1; }

iptables_cmd() {
  if (( DRY_RUN )); then
    echo "DRY-RUN: iptables $*"
  else
    iptables "$@"
  fi
}

# Create/refresh chain for OpenVPN rules
if ! iptables -nL "$CHAIN" >/dev/null 2>&1; then
  iptables_cmd -N "$CHAIN"
else
  iptables_cmd -F "$CHAIN"
fi

# Ensure FORWARD jumps to our chain (at the beginning)
if ! iptables -C FORWARD -j "$CHAIN" >/dev/null 2>&1; then
  iptables_cmd -I FORWARD 1 -j "$CHAIN"
fi

# Allow return traffic (conntrack)
if ! iptables -C "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1; then
  iptables_cmd -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
fi

# Convert netmask -> prefix /CIDR
mask2cidr() {
  local mask=$1 IFS=.
  read -r o1 o2 o3 o4 <<< "$mask"
  local bits=0
  for oct in $o1 $o2 $o3 $o4; do
    case $oct in
      255) bits=$((bits+8));;
      254) bits=$((bits+7));;
      252) bits=$((bits+6));;
      248) bits=$((bits+5));;
      240) bits=$((bits+4));;
      224) bits=$((bits+3));;
      192) bits=$((bits+2));;
      128) bits=$((bits+1));;
      0)   bits=$((bits+0));;
      *) echo "WARN: invalid netmask $mask" >&2; return 1;;
    esac
  done
  echo "$bits"
}

add_rule() {
  local src_ip="$1" dst_cidr="$2"
  # Avoid duplicates
  if iptables -C "$CHAIN" -s "$src_ip" -d "$dst_cidr" -j ACCEPT >/dev/null 2>&1; then
    return 0
  fi
  iptables_cmd -A "$CHAIN" -s "$src_ip" -d "$dst_cidr" -j ACCEPT
}

extract_routes_from_ccd() {
  # Print to stdout a list of networks in CIDR format (e.g. 192.168.10.0/24)
  local ccd_file="$1"
  # Supported formats:
  #   route 192.168.10.0 255.255.255.0
  #   push "route 192.168.10.0 255.255.255.0"
  #   route 192.168.10.0/24
  #   push "route 192.168.10.0/24"
  # Quotes ' or " and extra spaces are tolerated.
  while IFS= read -r line; do
    # skip comments and empty lines
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

    # route X Y (net mask)
    if [[ $line =~ (^|[[:space:]])route[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
      net="${BASH_REMATCH[2]}"
      mask="${BASH_REMATCH[3]}"
      if prefix=$(mask2cidr "$mask"); then
        echo "${net}/${prefix}"
      fi
      continue
    fi

    # push "route X Y" or push 'route X Y'
    if [[ $line =~ push[[:space:]]*[\"\']route[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)[\"\'] ]]; then
      net="${BASH_REMATCH[1]}"
      mask="${BASH_REMATCH[2]}"
      if prefix=$(mask2cidr "$mask"); then
        echo "${net}/${prefix}"
      fi
      continue
    fi

    # route X/Y (CIDR)
    if [[ $line =~ (^|[[:space:]])route[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/([0-9]{1,2}) ]]; then
      echo "${BASH_REMATCH[2]}/${BASH_REMATCH[3]}"
      continue
    fi

    # push "route X/Y"
    if [[ $line =~ push[[:space:]]*[\"\']route[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/([0-9]{1,2})[\"\'] ]]; then
      echo "${BASH_REMATCH[1]}/${BASH_REMATCH[2]}"
      continue
    fi
  done < "$ccd_file"
}

echo "Building ACL based on:"
echo "  IPP: $IPP_FILE"
echo "  CCD: $CCD_DIR"
(( DRY_RUN )) && echo "MODE: DRY-RUN (no iptables modifications)"

# Process ipp.txt
# Typical format: "CN,10.8.0.10" (optionally extra fields after comma)
while IFS= read -r line; do
  [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
  IFS=',' read -r USERNAME USER_IP _ <<< "$line"
  [[ -z "${USERNAME:-}" || -z "${USER_IP:-}" ]] && continue

  CCD_FILE="${CCD_DIR}/${USERNAME}"
  if [[ ! -f "$CCD_FILE" ]]; then
    # No individual CCD – skip
    continue
  fi

  routes=()
  while IFS= read -r r; do
    routes+=("$r")
  done < <(extract_routes_from_ccd "$CCD_FILE")

  # Add ACCEPT rules: src = user IP, dst = each allowed network
  for cidr in "${routes[@]}"; do
    add_rule "$USER_IP" "$cidr"
  done
done < "$IPP_FILE"

iptables_cmd -A "$CHAIN" -j DROP

echo "Done. Chain $CHAIN refreshed."
