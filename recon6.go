// recon6.go — IPv6 Active Reconnaissance & Research Tool
//
// PURPOSE:
// This tool performs active network discovery using IPv6-specific mechanisms.
// It is designed to verify IPv6 connectivity and mimic lateral movement by probing live hosts, IPv6-enabled interfaces, and neighbor relationships
// in a controlled laboratory or sandbox environment.
//
// TECHNIQUES:
// 1. Interface Enumeration: Identifies local IPv6 interfaces and prefixes.
// 2. Rogue Router Advertisement (RA): Injects RAs to force silent hosts to generate traffic
//    (Stateless Address Autoconfiguration events) which reveals their presence.
// 3. Multicast NDP Discovery: Sends ICMPv6 Echo Requests to the link-local all-nodes multicast address (ff02::1).
// 4. Heuristic Subnet Scanning: Scans likely addresses within discovered subnets.
// 5. Port Scanning: Checks common TCP ports on discovered neighbors.
// 6. Public Reachability: Verifies internet connectivity via IPv6.
//
// SAFETY WARNING:
// This program opens raw sockets and injects network control traffic (RAs).
// It MUST NOT be run on production networks without explicit authorization.
// Requires root privileges or CAP_NET_RAW capability.

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

type InterfaceInfo struct {
	Name          string      `json:"name"`
	MACAddress    string      `json:"mac_address"`
	IPv6Addresses []string    `json:"ipv6_addresses"`
	Nets          []net.IPNet `json:"-"`
}

type Neighbor struct {
	Iface     string `json:"iface"`
	IP        string `json:"ip"`
	Method    string `json:"method"` // "ndp" or "icmp"
	OpenPorts []int  `json:"open_ports,omitempty"`
}

type PublicProbe struct {
	Target        string `json:"target"`
	ICMPReachable bool   `json:"icmp_reachable"`
}

type HostInfo struct {
	Hostname string `json:"hostname"`
	FQDN     string `json:"fqdn"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
}

type Report struct {
	Timestamp    string          `json:"timestamp"`
	Host         HostInfo        `json:"host"`
	Comment      string          `json:"comment"`
	Interfaces   []InterfaceInfo `json:"interfaces"`
	Neighbors    []Neighbor      `json:"neighbors"`
	PublicProbes []PublicProbe   `json:"public_probes"`
}

var (
	verbose, veryVerbose bool

	// Configuration
	reportURL     = "https://research.tail-f.ch/recon6"
	raPrefix      = "2001:db8:666::"
	publicTargets = []string{
		"2620:fe::9",
		"2001:4860:4860::8888",
		"2606:4700:4700::1111",
	}

	version = "3"
	probe   = "0"
)

func vprintf(f string, a ...interface{}) {
	if verbose || veryVerbose {
		fmt.Printf(f, a...)
	}
}
func vvprintf(f string, a ...interface{}) {
	if veryVerbose {
		fmt.Printf(f, a...)
	}
}

// ---- system info ----
func getHostInfo() HostInfo {
	h, _ := os.Hostname()
	fqdn := h
	if addrs, err := net.LookupIP(h); err == nil && len(addrs) > 0 {
		names, _ := net.LookupAddr(addrs[0].String())
		if len(names) > 0 {
			fqdn = strings.TrimSuffix(names[0], ".")
		}
	}
	return HostInfo{
		Hostname: h,
		FQDN:     fqdn,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
	}
}

// ---- interface discovery ----
func getIPv6Interfaces() ([]InterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	blacklist := map[string]bool{"lo": true, "lo0": true, "loopback": true, "Loopback Pseudo-Interface 1": true}
	var infos []InterfaceInfo
	for _, iface := range ifaces {
		if blacklist[strings.ToLower(iface.Name)] {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		var ipv6s []string
		var nets []net.IPNet
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ipnet.IP.To16() != nil && ipnet.IP.To4() == nil {
					ipv6s = append(ipv6s, ipnet.IP.String()+"/"+fmt.Sprintf("%d", maskBits(*ipnet)))
					nets = append(nets, *ipnet)
				}
			}
		}
		if len(ipv6s) > 0 {
			infos = append(infos, InterfaceInfo{
				Name:          iface.Name,
				MACAddress:    iface.HardwareAddr.String(),
				IPv6Addresses: ipv6s,
				Nets:          nets,
			})
		}
	}
	return infos, nil
}

// ---- ICMPv6 (native) ----
func icmpv6Ping(addr string, timeout time.Duration, iface *net.Interface) (bool, time.Duration) {
	c, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return false, 0
	}
	defer c.Close()
	return icmpv6PingWithConn(c, addr, timeout, iface)
}

func icmpv6PingWithConn(c *icmp.PacketConn, addr string, timeout time.Duration, iface *net.Interface) (bool, time.Duration) {
	dstIP := net.ParseIP(strings.Split(addr, "%")[0])
	if dstIP == nil {
		return false, 0
	}

	if iface != nil {
		pc := c.IPv6PacketConn()
		_ = pc.SetControlMessage(ipv6.FlagInterface, true)
	}

	msg := icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("recon612356"),
		},
	}
	b, _ := msg.Marshal(nil)

	dst := &net.IPAddr{IP: dstIP}
	start := time.Now()
	c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.WriteTo(b, dst); err != nil {
		return false, 0
	}
	buf := make([]byte, 1500)
	n, _, err := c.ReadFrom(buf)
	if err != nil {
		return false, 0
	}
	duration := time.Since(start)
	rm, err := icmp.ParseMessage(58, buf[:n])
	if err != nil {
		return false, 0
	}
	return rm.Type == ipv6.ICMPTypeEchoReply, duration
}

// ---- multicast NDP discovery ----
//
// discoverNeighbors performs active neighbor discovery using Multicast ICMPv6.
//
// MECHANISM:
// Sends an ICMPv6 Echo Request to the "All Nodes" multicast group (ff02::1).
// All IPv6-compliant hosts on the local link are required to join this group and should reply,
// bypassing typical unicast firewall rules that might block direct pings.
//
// It listens on the raw socket for Echo Replies that arrive with control message IfIndex matching iface.
func discoverNeighbors(iface net.Interface) []Neighbor {
	vprintf("Discovering neighbors via ff02::1 on %s\n", iface.Name)

	c, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		vprintf("  icmp.ListenPacket error: %v\n", err)
		return nil
	}
	defer c.Close()

	pc := c.IPv6PacketConn()
	_ = pc.SetControlMessage(ipv6.FlagInterface, true)
	// join group so the kernel will deliver multicast replies
	_ = pc.JoinGroup(&iface, &net.UDPAddr{IP: net.ParseIP("ff02::1")})

	dst := &net.IPAddr{IP: net.ParseIP("ff02::1"), Zone: iface.Name}
	msg := icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("ndp-scan"),
		},
	}
	b, _ := msg.Marshal(nil)

	// send multicast echo
	if _, err := c.WriteTo(b, dst); err != nil {
		vprintf("  write ff02::1 on %s failed: %v\n", iface.Name, err)
		// proceed to listen anyway
	}

	// listen for a brief window
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	var neighs []Neighbor
	for {
		n, cm, src, err := pc.ReadFrom(buf)
		if err != nil {
			// timeout or closed
			break
		}
		rm, err := icmp.ParseMessage(58, buf[:n])
		if err != nil {
			continue
		}
		if rm.Type != ipv6.ICMPTypeEchoReply {
			continue
		}
		// ensure reply came on this interface
		if cm != nil && cm.IfIndex == iface.Index {
			if srcAddr, ok := src.(*net.IPAddr); ok {
				ipaddr := srcAddr.IP.String()
				neighs = append(neighs, Neighbor{
					Iface:  iface.Name,
					IP:     ipaddr,
					Method: "ndp",
				})
			}
		}
	}
	return neighs
}

// ---- TCP port check ----
func checkPort(ip string, iface string, port int, timeout time.Duration) bool {
	address := ip
	parsedIP := net.ParseIP(ip)
	if parsedIP != nil && parsedIP.IsLinkLocalUnicast() {
		address = fmt.Sprintf("%s%%%s", ip, iface)
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("[%s]:%d", address, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// ---- subnet helpers ----
func addIPv6(ip net.IP, add uint64) net.IP {
	ip = ip.To16()
	if ip == nil {
		return nil
	}
	i := new(big.Int).SetBytes(ip)
	i.Add(i, big.NewInt(int64(add)))
	b := i.Bytes()
	if len(b) < 16 {
		tmp := make([]byte, 16)
		copy(tmp[16-len(b):], b)
		b = tmp
	}
	return net.IP(b)
}

func hostsInSubnet(ipnet net.IPNet, n int) []string {
	var hosts []string
	ones, bits := ipnet.Mask.Size()
	if bits != 128 || 128-ones <= 0 {
		return hosts
	}
	network := ipnet.IP.Mask(ipnet.Mask)
	for i := 0; i <= n; i++ {
		h := addIPv6(network, uint64(i))
		if ipnet.Contains(h) {
			hosts = append(hosts, h.String())
		}
	}
	return hosts
}

func maskBits(n net.IPNet) int {
	ones, _ := n.Mask.Size()
	return ones
}

func hasGlobalUnicastAddress(ifaces []InterfaceInfo) bool {
	for _, iface := range ifaces {
		for _, n := range iface.Nets {
			if n.IP.IsGlobalUnicast() {
				return true
			}
		}
	}
	return false
}

// ---- Router Advertisement builder & sender ----

// sendRouterAdvertisement injects a "Rogue" Router Advertisement (Type 134) onto the link.
//
// OBJECTIVE:
// By advertising a new prefix, we attempt to trigger target operating systems to:
// 1. Perform Duplicate Address Detection (DAD) for a new auto-configured address.
// 2. Update their routing tables.
// This generates network traffic from otherwise silent or firewall-protected hosts,
// revealing their presence (MAC and Link-Local addresses) to the monitoring host.
func sendRouterAdvertisement(iface net.Interface, prefix net.IP, prefixLen int) error {
	vprintf("Sending Router Advertisement on %s for %s/%d\n", iface.Name, prefix.String(), prefixLen)

	c, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return fmt.Errorf("listen icmp: %w", err)
	}
	defer c.Close()

	pc := c.IPv6PacketConn()
	_ = pc.SetControlMessage(ipv6.FlagInterface, true)
	_ = pc.JoinGroup(&iface, &net.UDPAddr{IP: net.ParseIP("ff02::1")})

	raHdr := make([]byte, 12)
	raHdr[0] = 64                                       // Cur Hop Limit
	raHdr[1] = 0                                        // flags: none (M/O = 0)
	binary.BigEndian.PutUint16(raHdr[2:], uint16(1800)) // Router Lifetime (seconds)
	binary.BigEndian.PutUint32(raHdr[4:], 0)            // Reachable Time
	binary.BigEndian.PutUint32(raHdr[8:], 0)            // Retrans Timer

	// Prefix Information option (type 3, length 4 (32 bytes), prefix length, flags)
	// Option layout: Type(1), Len(1), PrefixLen(1), Flags(1), ValidLifetime (4),
	// PreferredLifetime (4), Reserved (4), Prefix (16)
	opt := make([]byte, 32)
	opt[0] = 3 // Prefix Info
	opt[1] = 4 // length (units of 8 bytes -> 4 => 32 bytes)
	opt[2] = byte(prefixLen)
	opt[3] = 0xC0 // Flags: On-link (L=1, 0x80) + Autonomous (A=1, 0x40) => 0xC0
	// lifetimes (valid/preferred)
	binary.BigEndian.PutUint32(opt[4:], uint32(24*3600)) // Valid lifetime (24h)
	binary.BigEndian.PutUint32(opt[8:], uint32(12*3600)) // Preferred lifetime (12h)
	// reserved 12..15 left zero
	// prefix bytes into opt[16..31]
	prefBytes := prefix.To16()
	copy(opt[16:], prefBytes)

	payload := append(raHdr, opt...)

	msg := icmp.Message{
		Type: ipv6.ICMPTypeRouterAdvertisement,
		Code: 0,
		Body: &icmp.RawBody{Data: payload},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return err
	}

	dst := &net.IPAddr{IP: net.ParseIP("ff02::1"), Zone: iface.Name}
	if _, err := c.WriteTo(b, dst); err != nil {
		return fmt.Errorf("write RA: %w", err)
	}
	return nil
}

// ---- main ----
func main() {
	var comment string
	flag.BoolVar(&verbose, "v", false, "verbose output")
	flag.BoolVar(&veryVerbose, "vv", false, "very verbose output")
	flag.StringVar(&comment, "c", "", "add a custom comment to the report")
	flag.Parse()

	fmt.Println("This is recon6 - research for IPv6. This binary is meant for Sandboxes, Honeypots and Labs.")
	fmt.Println("It collects network information, sends ICMPv6 Echo Requests, Router Advertisements and TCP SYN packets.")
	fmt.Println("Do not run this tool on personal or production networks without permission!")
	fmt.Println("Press Ctrl+C to cancel")
	fmt.Println("")
	time.Sleep(5 * time.Second)

	// -------------------------------------------------------------------------
	// PHASE 1: Report Preparation & Interface Discovery
	// -------------------------------------------------------------------------
	rep := Report{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Host:      getHostInfo(),
	}

	// ---- interface discovery ----
	ifaces, err := getIPv6Interfaces()
	if err == nil {
		rep.Interfaces = ifaces
	} else {
		fmt.Printf("Error getting interfaces: %v\n", err)
	}

	for _, ii := range rep.Interfaces {
		vprintf("Interface %s: %v\n", ii.Name, ii.IPv6Addresses)
	}

	if comment != "" {
		rep.Comment = comment
	} else {
		firstMac := ""
		if len(ifaces) > 0 {
			firstMac = ifaces[0].MACAddress
		}
		rep.Comment = "AutoMeassurement+" + firstMac
	}

	// -------------------------------------------------------------------------
	// PHASE 2: Active Stimulation (Rogue Router Advertisements)
	// -------------------------------------------------------------------------
	if hasGlobalUnicastAddress(ifaces) {
		vprintf("Skipping Router Advertisements, global unicast address present.\n")
	} else {
		for _, ii := range ifaces {
			ifaceObj, err := net.InterfaceByName(ii.Name)
			if err != nil {
				continue
			}
			if err := sendRouterAdvertisement(*ifaceObj, net.ParseIP(raPrefix), 64); err != nil {
				vprintf("RA send error on %s: %v\n", ii.Name, err)
			} else {
				vprintf("RA sent on %s (advertising %s/64)\n", ii.Name, raPrefix)
			}
		}
	}

	// -------------------------------------------------------------------------
	// PHASE 3: Initial Neighbor Discovery (Multicast NDP)
	// -------------------------------------------------------------------------
	vprintf("Starting initial NDP discovery...\n")
	allMap := map[string]Neighbor{}
	ndpResults := make(chan []Neighbor)
	var ndpWg sync.WaitGroup
	for _, ii := range ifaces {
		ndpWg.Add(1)
		go func(ifaceInfo InterfaceInfo) {
			defer ndpWg.Done()
			ifaceObj, err := net.InterfaceByName(ifaceInfo.Name)
			if err != nil {
				return
			}
			found := discoverNeighbors(*ifaceObj)
			ndpResults <- found
		}(ii)
	}

	go func() {
		ndpWg.Wait()
		close(ndpResults)
	}()

	for found := range ndpResults {
		for _, n := range found {
			if _, ok := allMap[n.IP]; !ok {
				allMap[n.IP] = n
			}
		}
	}

	// -------------------------------------------------------------------------
	// PHASE 4: Heuristic Subnet Scanning (ICMPv6)
	// -------------------------------------------------------------------------
	vprintf("Starting ICMP subnet scans...\n")
	type icmpJob struct {
		iface string
		net   net.IPNet
	}
	icmpJobs := make(chan icmpJob)
	icmpResults := make(chan Neighbor)
	const icmpWorkers = 8
	var icmpWg sync.WaitGroup

	for w := 0; w < icmpWorkers; w++ {
		icmpWg.Add(1)
		go func() {
			defer icmpWg.Done()
			c, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
			if err != nil {
				vprintf("Worker failed to create ICMP socket: %v\n", err)
				return
			}
			defer c.Close()

			for j := range icmpJobs {
				if !j.net.IP.IsGlobalUnicast() {
					vvprintf("Skipping non-global subnet %s\n", j.net.IP.String())
					continue
				}
				vprintf("Scanning subnet %s/%d on %s\n", j.net.IP.String(), maskBits(j.net), j.iface)
				hosts := hostsInSubnet(j.net, 20)
				for _, h := range hosts {
					vvprintf(" → ICMP check %s\n", h)
					ok, rtt := icmpv6PingWithConn(c, h, 1*time.Second, nil)
					if ok {
						if veryVerbose {
							fmt.Printf("reply from %s time=%.1fms\n", h, float64(rtt.Microseconds())/1000.0)
						}
						icmpResults <- Neighbor{
							Iface:  j.iface,
							IP:     h,
							Method: "icmp",
						}
					}
				}
			}
		}()
	}

	go func() {
		for _, iface := range ifaces {
			for _, n := range iface.Nets {
				icmpJobs <- icmpJob{iface: iface.Name, net: n}
			}
		}
		close(icmpJobs)
	}()

	go func() {
		icmpWg.Wait()
		close(icmpResults)
		// close(icmpJobs)
	}()

	for n := range icmpResults {
		if _, ok := allMap[n.IP]; !ok {
			allMap[n.IP] = n
		}
	}
	vprintf("ICMP subnet scans finished.\n")

	// -------------------------------------------------------------------------
	// PHASE 5: Service Enumeration (Port Scanning)
	// -------------------------------------------------------------------------
	vprintf("Starting port scans for all discovered neighbors...\n")
	portScanJobs := make(chan Neighbor, len(allMap))
	portScanResults := make(chan Neighbor, len(allMap))
	var portScanWg sync.WaitGroup
	const portScanWorkers = 10

	for w := 0; w < portScanWorkers; w++ {
		portScanWg.Add(1)
		go func() {
			defer portScanWg.Done()
			for n := range portScanJobs {
				vvprintf("Port scanning %s\n", n.IP)
				ports := []int{}
				for _, p := range []int{22, 23, 80, 443} {
					if checkPort(n.IP, n.Iface, p, 1*time.Second) {
						ports = append(ports, p)
					}
				}
				n.OpenPorts = ports
				if verbose && len(ports) > 0 {
					fmt.Printf("Host %s open ports %v\n", n.IP, ports)
				}
				portScanResults <- n
			}
		}()
	}

	for _, n := range allMap {
		portScanJobs <- n
	}
	close(portScanJobs)

	portScanWg.Wait()
	close(portScanResults)

	for n := range portScanResults {
		allMap[n.IP] = n
	}
	vprintf("Port scans finished.\n")

	// -------------------------------------------------------------------------
	// PHASE 6: Internet Connectivity Check
	// -------------------------------------------------------------------------
	vprintf("Starting public probes...\n")
	for _, t := range publicTargets {
		ok, _ := icmpv6Ping(t, 2*time.Second, nil)
		rep.PublicProbes = append(rep.PublicProbes, PublicProbe{Target: t, ICMPReachable: ok})
		if verbose && ok {
			fmt.Printf("Public target reachable: %s\n", t)
		}
	}
	vprintf("Public probes finished.\n")

	// -------------------------------------------------------------------------
	// PHASE 7: Re-verification & Reporting
	// -------------------------------------------------------------------------
	vprintf("Re-running neighbor discovery...\n")
	recheckNdpResults := make(chan []Neighbor)
	var recheckNdpWg sync.WaitGroup
	for _, ii := range ifaces {
		recheckNdpWg.Add(1)
		go func(ifaceInfo InterfaceInfo) {
			defer recheckNdpWg.Done()
			ifaceObj, err := net.InterfaceByName(ifaceInfo.Name)
			if err != nil {
				return
			}
			found := discoverNeighbors(*ifaceObj)
			recheckNdpResults <- found
		}(ii)
	}

	go func() {
		recheckNdpWg.Wait()
		close(recheckNdpResults)
	}()

	for found := range recheckNdpResults {
		for _, n := range found {
			if _, ok := allMap[n.IP]; !ok {
				vprintf("Found new neighbor on re-scan: %s\n", n.IP)
				n.Method = "ndp-rescan"
				allMap[n.IP] = n
			}
		}
	}
	vprintf("Neighbor re-scan complete.\n")

	rep.Neighbors = make([]Neighbor, 0, len(allMap))
	for _, n := range allMap {
		rep.Neighbors = append(rep.Neighbors, n)
	}

	j, _ := json.MarshalIndent(rep, "", "  ")
	vvprintf(string(j))

	if err := submitReport(reportURL, rep); err != nil {
		vprintf("submit error:", err)
	}
}

// submitReport posts JSON to the provided URL (best-effort)
func submitReport(url string, payload interface{}) error {
	body, _ := json.MarshalIndent(payload, "", "  ")
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "recon6/"+version+"."+probe)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	fmt.Printf("Done: %s\n", resp.Status)
	return nil
}
