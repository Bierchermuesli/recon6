#!/bin/bash
# recon6.sh — IPv6 Active Reconnaissance & Research Tool (Shell Version)
#
# PURPOSE:
# Legacy lightweight alternative to recon6 (Go binary).
# Useful on constrained targets where deploying a compiled binary is not
# practical. Functionality is equivalent but less precise than recon6.go.
#
# TECHNIQUES:
# 1. Interface Enumeration
# 2. Multicast NDP Discovery (ping ff02::1)
# 3. Neighbor Cache Enumeration
# 4. Port Scanning (common ports)
# 5. Public Reachability
#
# USAGE:
#   ./recon6.sh [-v] [-p probe_id] [-c comment]
#
# DEPENDENCIES:
#   ip, ping (with -6 support), curl, grep, awk, sed
#   Optional: nc (netcat) for port scanning (falls back to /dev/tcp)

set -u

# --- Configuration ---
REPORT_URL="https://research.tail-f.ch/recon6"
VERSION="3sh"
PROBE="7"
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

# JSON Helpers (manual construction to avoid jq dependency)
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
    # Format: [{"name": "eth0", "mac_address": "...", "ipv6_addresses": ["..."]}, ...]
    
    local first=true
    echo "["
    
    # Iterate over interfaces using /sys/class/net to be generic
    for iface in $(ls /sys/class/net/); do
        # Skip loopback
        if [ "$iface" = "lo" ]; then continue; fi
        
        # Check if up
        local state=$(cat /sys/class/net/$iface/operstate 2>/dev/null)
        if [ "$state" != "up" ] && [ "$state" != "unknown" ]; then continue; fi
        
        local mac=$(cat /sys/class/net/$iface/address 2>/dev/null)
        
        # Get IPv6 addresses
        # Output of 'ip -6 addr show dev eth0' needs parsing
        local addrs=$(ip -6 addr show dev "$iface" scope global | awk '/inet6/ {print $2}' | cut -d' ' -f1)
        # Also include link-local for completeness if needed, but recon6.go filters complexly.
        # recon6.go: "if ipnet.IP.To16() != nil && ipnet.IP.To4() == nil"
        # We will include all inet6 scope global and link
        local all_addrs=$(ip -6 addr show dev "$iface" | awk '/inet6/ {print $2}')
        
        if [ -z "$all_addrs" ]; then continue; fi
        
        # Format addresses into JSON array
        local addr_json="["
        local afirst=true
        for addr in $all_addrs; do
            if [ "$afirst" = true ]; then afirst=false; else addr_json="$addr_json,"; fi
            addr_json="$addr_json \"$addr\""
        done
        addr_json="$addr_json]"
        
        if [ "$first" = true ]; then first=false; else echo ","; fi
        
        echo "{ \"name\": \"$iface\", \"mac_address\": \"$mac\", \"ipv6_addresses\": $addr_json }"
    done
    echo "]"
}

perform_ndp_discovery() {
    # Ping ff02::1 on all interfaces to populate neighbor table
    log "Starting NDP discovery (multicast ping)..."
    for iface in $(ls /sys/class/net/); do
        if [ "$iface" = "lo" ]; then continue; fi
        # Check if up
        local state=$(cat /sys/class/net/$iface/operstate 2>/dev/null)
        if [ "$state" != "up" ] && [ "$state" != "unknown" ]; then continue; fi
        
        # Check if interface has IPv6
        if ! ip -6 addr show dev "$iface" | grep -q "inet6"; then continue; fi
        
        log "  Pinging ff02::1 on $iface..."
        # Send 2 packets, wait max 2 seconds. Backgrounding not done to avoid mixup, but could be faster.
        ping -6 -I "$iface" -c 2 -w 2 ff02::1 >/dev/null 2>&1
    done
}

scan_port() {
    local ip=$1
    local port=$2
    local iface=$3 # needed for link-local
    
    # Handle Link-Local addresses for connectivity check (needs %iface)
    local target_ip="$ip"
    if [[ "$ip" == fe80* ]]; then
        target_ip="$ip%$iface"
    fi

    # Try nc first
    if has_cmd nc; then
        nc -z -w 1 "$ip" "$port" 2>/dev/null && return 0
        # Some nc versions require %iface syntax for link-local, but strictly nc often doesn't handle scope IDs well without specialized flags.
        # Actually standard netcat-openbsd supports -s source or just standard connect.
        # Let's try passing the scope ID in the IP if it's link local
        if [[ "$ip" == fe80* ]]; then
             nc -z -w 1 "${ip}%${iface}" "$port" 2>/dev/null && return 0
        fi
        return 1
    else
        # Bash /dev/tcp fallback
        # Note: /dev/tcp usually doesn't handle scope IDs well for IPv6 link-locals in older bash.
        # This is a best-effort.
        timeout 1 bash -c "echo > /dev/tcp/$ip/$port" 2>/dev/null && return 0
        return 1
    fi
}

get_neighbors_json() {
    # Parse `ip -6 neigh`
    # Format: [{"iface": "...", "ip": "...", "method": "ndp", "open_ports": [...]}, ...]
    
    # We use a temporary file to build the list because of the loop subshell scope issues
    local tmp_neighs=$(mktemp)
    
    # Get neighbors (reachable or stale)
    ip -6 neigh show | grep -v "FAILED" | while read -r line; do
        # Line format example: fe80::1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
        local ip=$(echo "$line" | awk '{print $1}')
        local dev=$(echo "$line" | awk '{print $3}')
        
        # Filter out multicast/broadcast or weird entries if any
        if [ "$ip" = "ff02::1" ]; then continue; fi
        
        # --- Port Scan ---
        local open_ports="["
        local pfirst=true
        
        log "  Scanning ports for $ip on $dev..."
        for port in 22 23 80 443; do
            if scan_port "$ip" "$port" "$dev"; then
                log "    Host $ip port $port OPEN"
                if [ "$pfirst" = true ]; then pfirst=false; else open_ports="$open_ports,"; fi
                open_ports="$open_ports $port"
            fi
        done
        open_ports="$open_ports]"
        
        echo "{ \"iface\": \"$dev\", \"ip\": \"$ip\", \"method\": \"ndp\", \"open_ports\": $open_ports }," >> "$tmp_neighs"
    done
    
    echo "["
    if [ -s "$tmp_neighs" ]; then
        # Remove trailing comma
        sed '$ s/,$//' "$tmp_neighs"
    fi
    echo "]"
    rm -f "$tmp_neighs"
}

perform_public_probes_json() {
    # Check public targets
    # Targets from recon6.go: 2620:fe::9, 2001:4860:4860::8888, 2606:4700:4700::1111
    local targets="2620:fe::9 2001:4860:4860::8888 2606:4700:4700::1111"
    
    echo "["
    local first=true
    
    log "Starting public probes..."
    for t in $targets; do
        local reachable="false"
        if ping -6 -c 1 -w 2 "$t" >/dev/null 2>&1; then
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

echo "This is recon6.sh (v$VERSION). IPv6 Research Tool."
echo "Press Ctrl+C to cancel... (sleeping 2s)"
sleep 2

# 1. Interfaces
log "Enumerating interfaces..."
INTERFACES_JSON=$(get_interfaces_json)

# 2. NDP Discovery
perform_ndp_discovery

# 3. Collect Neighbors (and scan ports)
log "Collecting neighbors..."
NEIGHBORS_JSON=$(get_neighbors_json)

# 4. Public Probes
PUBLIC_PROBES_JSON=$(perform_public_probes_json)

# 5. Comment
if [ -z "$COMMENT" ]; then
    # Auto-comment similar to recon6.go: AutoMeasurement+<FirstMAC>
    # Extract MAC from first interface in JSON is hard with regex, let's just grab first from system
    FIRST_MAC=$(ip link | awk '/ether/ {print $2; exit}')
    COMMENT="AutoMeasurement+${FIRST_MAC}"
fi

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# 6. Build Final Report
# We manually construct the JSON structure
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
    -A "recon6/$VERSION.$PROBE" \
    -d "$REPORT_JSON" \
    "$REPORT_URL")

if [ "$HTTP_CODE" -eq 200 ] || [ "$HTTP_CODE" -eq 201 ]; then
    echo "Done: $HTTP_CODE OK"
else
    echo "Submission failed: HTTP $HTTP_CODE"
fi
