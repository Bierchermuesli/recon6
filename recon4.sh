#!/bin/bash
# recon4.sh — IPv4 Active Reconnaissance & Research Tool (Shell Version)
#
# PURPOSE:
# Legacy lightweight alternative to recon4 (Go binary).
# Useful on constrained targets where deploying a compiled binary is not
# practical. Functionality is equivalent but less precise than recon4.go.
#
# TECHNIQUES:
# 1. Interface Enumeration
# 2. Broadcast Ping (ARP-like Discovery)
# 3. Neighbor Cache Enumeration
# 4. Port Scanning (common ports)
# 5. Public Reachability
#
# USAGE:
#   ./recon4.sh [-v] [-p probe_id] [-c comment]
#
# DEPENDENCIES:
#   ip, ping, curl, grep, awk, sed
#   Optional: nc (netcat) for port scanning (falls back to /dev/tcp)

set -u

# --- Configuration ---
REPORT_URL="https://research.tail-f.ch/recon6"
VERSION="3sh"
PROBE="0"
VERBOSE=false
COMMENT=""

# --- Arguments ---
while getopts "vp:c:" opt; do
  case $opt in
    v) VERBOSE=true ;;
    p) PROBE="$OPTARG" ;;
    c) COMMENT="$OPTARG" ;;
    *) echo "Usage: $0 [-v] [-p probe_id] [-c comment]" >&2; exit 1 ;;
  esac
done

# --- Helpers ---
log() {
    if [ "$VERBOSE" = true ]; then
        echo "[*] $@" >&2
    fi
}

error() {
    echo "[!] $@" >&2
}

# Check if command exists
has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

# JSON Helpers
json_escape() {
    echo "$1" | sed 's/"/\\"/g' | tr -d '\n'
}

# --- System Info ---
HOSTNAME=$(hostname)
FQDN=$(hostname -f 2>/dev/null || echo "$HOSTNAME")
OS=$(uname -s)
ARCH=$(uname -m)

# --- Discovery Functions ---

get_interfaces_json() {
    # Returns a JSON array of interface objects
    # Format: [{"name": "eth0", "mac_address": "...", "ipv4_addresses": ["..."]}, ...]
    
    local first=true
    echo "["
    
    for iface in $(ls /sys/class/net/); do
        # Skip loopback
        if [ "$iface" = "lo" ]; then continue; fi
        
        # Check if up
        local state=$(cat /sys/class/net/$iface/operstate 2>/dev/null)
        if [ "$state" != "up" ] && [ "$state" != "unknown" ]; then continue; fi
        
        local mac=$(cat /sys/class/net/$iface/address 2>/dev/null)
        
        # Get IPv4 addresses (CIDR format)
        local addrs=$(ip -4 addr show dev "$iface" | awk '/inet / {print $2}')
        
        if [ -z "$addrs" ]; then continue; fi
        
        local addr_json="["
        local afirst=true
        for addr in $addrs; do
            if [ "$afirst" = true ]; then afirst=false; else addr_json="$addr_json,"; fi
            addr_json="$addr_json \"$addr\""
        done
        addr_json="$addr_json]"
        
        if [ "$first" = true ]; then first=false; else echo ","; fi
        
        echo "{ \"name\": \"$iface\", \"mac_address\": \"$mac\", \"ipv4_addresses\": $addr_json }"
    done
    echo "]"
}

perform_broadcast_ping() {
    # Send ICMP Echo Request to broadcast address on all interfaces
    log "Starting ARP-like discovery (broadcast ping)..."
    
    # We need to find broadcast addresses for interfaces
    ip -4 addr show | grep "brd" | while read -r line; do
        # Example: inet 192.168.1.50/24 brd 192.168.1.255 scope global dynamic wlan0
        local brd=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i=="brd") print $(i+1)}')
        local dev=$(echo "$line" | awk '{print $NF}')
        
        if [ -n "$brd" ] && [ "$dev" != "lo" ]; then
            log "  Pinging broadcast $brd on $dev..."
            # -b allows broadcast. -c 2 count. -w 2 timeout.
            ping -b -c 2 -w 2 "$brd" >/dev/null 2>&1 &
        fi
    done
    
    # Wait a bit for replies to populate ARP cache
    wait
    sleep 1
}

scan_port() {
    local ip=$1
    local port=$2
    
    # Try nc first
    if has_cmd nc; then
        nc -z -w 1 "$ip" "$port" 2>/dev/null && return 0
        return 1
    else
        # Bash /dev/tcp fallback
        timeout 1 bash -c "echo > /dev/tcp/$ip/$port" 2>/dev/null && return 0
        return 1
    fi
}

get_neighbors_json() {
    # Parse `ip -4 neigh`
    # Format: [{"iface": "...", "ip": "...", "method": "arp", "open_ports": [...]}, ...]
    
    local tmp_neighs=$(mktemp)
    
    # Get neighbors (reachable or stale)
    ip -4 neigh show | grep -v "FAILED" | while read -r line; do
        # Line format example: 192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
        local ip=$(echo "$line" | awk '{print $1}')
        local dev=$(echo "$line" | awk '{print $3}')
        
        # Filter out own IPs? (harder in shell, but ARP table usually excludes self)
        
        # --- Port Scan ---
        local open_ports="["
        local pfirst=true
        
        log "  Scanning ports for $ip on $dev..."
        for port in 22 23 80 443; do
            if scan_port "$ip" "$port"; then
                log "    Host $ip port $port OPEN"
                if [ "$pfirst" = true ]; then pfirst=false; else open_ports="$open_ports,"; fi
                open_ports="$open_ports $port"
            fi
        done
        open_ports="$open_ports]"
        
        echo "{ \"iface\": \"$dev\", \"ip\": \"$ip\", \"method\": \"arp\", \"open_ports\": $open_ports }," >> "$tmp_neighs"
    done
    
    echo "["
    if [ -s "$tmp_neighs" ]; then
        sed '$ s/,$//' "$tmp_neighs"
    fi
    echo "]"
    rm -f "$tmp_neighs"
}

perform_public_probes_json() {
    # Check public targets
    # Targets from recon4.go: 8.8.8.8, 1.1.1.1, 8.8.4.4
    local targets="8.8.8.8 1.1.1.1 8.8.4.4"
    
    echo "["
    local first=true
    
    log "Starting public probes..."
    for t in $targets; do
        local reachable="false"
        if ping -c 1 -w 2 "$t" >/dev/null 2>&1; then
            reachable="true"
            log "  $t is REACHABLE"
        else
            log "  $t is UNREACHABLE"
        fi
        
        if [ "$first" = true ]; then first=false; else echo ","; fi
        echo "{ \"target\": \"$t\", \"icmp_reachable\": $reachable }"
    done
    echo "]"
}

# --- Main Execution ---

echo "This is recon4.sh (v$VERSION). IPv4 Research Tool."
echo "Press Ctrl+C to cancel... (sleeping 2s)"
sleep 2

# 1. Interfaces
log "Enumerating interfaces..."
INTERFACES_JSON=$(get_interfaces_json)

# 2. Broadcast Ping (Populate ARP)
perform_broadcast_ping

# 3. Collect Neighbors (and scan ports)
log "Collecting neighbors..."
NEIGHBORS_JSON=$(get_neighbors_json)

# 4. Public Probes
PUBLIC_PROBES_JSON=$(perform_public_probes_json)

# 5. Comment
if [ -z "$COMMENT" ]; then
    FIRST_MAC=$(ip link | awk '/ether/ {print $2; exit}')
    COMMENT="AutoMeasurement+${FIRST_MAC}"
fi

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# 6. Build Final Report
REPORT_JSON="{
  \"timestamp\": \"$TIMESTAMP\",
  \"host\": {
    \"hostname\": \"$(json_escape "$HOSTNAME")\",
    \"fqdn\": \"$(json_escape "$FQDN")\",
    \"os\": \"$(json_escape "$OS")\",
    \"arch\": \"$(json_escape "$ARCH")\"
  },
  \"comment\": \"$(json_escape "$COMMENT")\",
  \"interfaces\": $INTERFACES_JSON,
  \"neighbors\": $NEIGHBORS_JSON,
  \"public_probes\": $PUBLIC_PROBES_JSON
}"

if [ "$VERBOSE" = true ]; then
    echo "--- Report ---"
    echo "$REPORT_JSON"
    echo "--------------"
fi

# 7. Submit
log "Submitting report to $REPORT_URL..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -A "recon4/$VERSION.$PROBE" \
    -d "$REPORT_JSON" \
    "$REPORT_URL")

if [ "$HTTP_CODE" -eq 200 ] || [ "$HTTP_CODE" -eq 201 ]; then
    echo "Done: $HTTP_CODE OK"
else
    echo "Submission failed: HTTP $HTTP_CODE"
fi
