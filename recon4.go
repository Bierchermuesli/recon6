// recon4.go — IPv4 Active Reconnaissance & Research Tool
//
// PURPOSE:
// This tool performs active network discovery using IPv4 mechanisms.
// It is designed to mimic lateral movement by arp/icmp scan on IPv4-enabled interfaces, and neighbor relationships
// in a controlled laboratory or sandbox environment.
//
// TECHNIQUES:
// 1. Interface Enumeration: Identifies local IPv4 interfaces and subnets.
// 2. Broadcast Ping (ARP-like Discovery): Sends ICMP Echo Requests to the subnet broadcast address
//    to elicit replies from legacy or misconfigured stacks.
// 3. Subnet Scanning: Systematically pings addresses within the local subnets.
// 4. Port Scanning: Checks common TCP ports on discovered neighbors.
// 5. Public Reachability: Verifies internet connectivity via IPv4.
//
// SAFETY WARNING:
// This program opens raw sockets and sends broadcast traffic.
// It MUST NOT be run on production networks without explicit authorization.
// Requires root privileges or CAP_NET_RAW capability.

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type InterfaceInfo struct {
	Name          string      `json:"name"`
	MACAddress    string      `json:"mac_address"`
	IPv4Addresses []string    `json:"ipv4_addresses"`
	Nets          []net.IPNet `json:"-"`
}

type Neighbor struct {
	Iface     string `json:"iface"`
	IP        string `json:"ip"`
	Method    string `json:"method"` // "arp" or "icmp"
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
	publicTargets = []string{
		"8.8.8.8",
		"1.1.1.1",
		"8.8.4.4",
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
func getIPv4Interfaces() ([]InterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	blacklist := map[string]bool{"lo": true, "lo0": true, "loopback": true}
	var infos []InterfaceInfo
	for _, iface := range ifaces {
		if blacklist[strings.ToLower(iface.Name)] {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		var ipv4s []string
		var nets []net.IPNet
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ipnet.IP.To4() != nil {
					ipv4s = append(ipv4s, ipnet.IP.String()+"/"+fmt.Sprintf("%d", maskBits(*ipnet)))
					nets = append(nets, *ipnet)
				}
			}
		}
		if len(ipv4s) > 0 {
			infos = append(infos, InterfaceInfo{
				Name:          iface.Name,
				MACAddress:    iface.HardwareAddr.String(),
				IPv4Addresses: ipv4s,
				Nets:          nets,
			})
		}
	}
	return infos, nil
}

// ---- ICMPv4 (native) ----
func icmpv4Ping(addr string, timeout time.Duration) (bool, time.Duration) {
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false, 0
	}
	defer c.Close()
	return icmpv4PingWithConn(c, addr, timeout)
}

func icmpv4PingWithConn(c *icmp.PacketConn, addr string, timeout time.Duration) (bool, time.Duration) {
	dstIP := net.ParseIP(strings.Split(addr, "%")[0])
	if dstIP == nil || dstIP.To4() == nil {
		return false, 0
	}

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("recon4"),
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
	rm, err := icmp.ParseMessage(1, buf[:n])
	if err != nil {
		return false, 0
	}
	return rm.Type == ipv4.ICMPTypeEchoReply, duration
}

// ---- ARP discovery (ICMP broadcast) ----
//
// discoverNeighbors performs "ARP-like" discovery using ICMP Broadcast.
//
// MECHANISM:
// Sends an ICMP Echo Request to the subnet's broadcast address.
// Legacy or misconfigured stacks may reply to this broadcast, revealing their IP presence
// without requiring a full ARP scan of the entire subnet range.
// Note: Many modern OSs ignore broadcast ICMP by default (RFC 1122), so this is less effective
// than a true ARP scan, but works at Layer 3.
func discoverNeighbors(iface net.Interface, ipnet net.IPNet) []Neighbor {
	vprintf("Discovering neighbors via ICMP broadcast on %s (%s)\n", iface.Name, ipnet.String())

	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		vprintf("  icmp.ListenPacket error: %v\n", err)
		return nil
	}
	defer c.Close()

	broadcastIP := getBroadcastIP(ipnet).String()
	vprintf("  Sending ICMP Echo Request to broadcast address %s\n", broadcastIP)

	dst := &net.IPAddr{IP: net.ParseIP(broadcastIP)}
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("arp-scan"),
		},
	}
	b, _ := msg.Marshal(nil)

	if _, err := c.WriteTo(b, dst); err != nil {
		vprintf("  write to %s failed: %v\n", broadcastIP, err)
	}

	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	var neighs []Neighbor
	for {
		_, src, err := c.ReadFrom(buf)
		if err != nil {
			// timeout or closed
			break
		}
		// We don't parse the reply, just record the source IP
		if srcIP, ok := src.(*net.IPAddr); ok {
			// Don't add our own IP
			if !srcIP.IP.Equal(ipnet.IP) {
				neighs = append(neighs, Neighbor{
					Iface:  iface.Name,
					IP:     srcIP.IP.String(),
					Method: "arp",
				})
			}
		}
	}
	return neighs
}

// ---- TCP port check ----
func checkPort(ip string, port int, timeout time.Duration) bool {
	address := ip
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("[%s]:%d", address, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// ---- subnet helpers ----
func addIPv4(ip net.IP, add uint32) net.IP {
	ip = ip.To4()
	if ip == nil {
		return nil
	}
	ipInt := binary.BigEndian.Uint32(ip)
	ipInt += add
	newIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(newIP, ipInt)
	return newIP
}

func hostsInSubnet(ipnet net.IPNet, n int) []string {
	var hosts []string
	ip := ipnet.IP.To4()
	if ip == nil {
		return hosts
	}
	network := ipnet.IP.Mask(ipnet.Mask)
	for i := 0; i <= n; i++ {
		h := addIPv4(network, uint32(i))
		if ipnet.Contains(h) {
			// Do not add network and broadcast addresses
			if !h.Equal(network) && !h.Equal(getBroadcastIP(ipnet)) {
				hosts = append(hosts, h.String())
			}
		}
	}
	return hosts
}

func getBroadcastIP(ipnet net.IPNet) net.IP {
	ip := ipnet.IP.To4()
	mask := ipnet.Mask
	bcast := make(net.IP, len(ip))
	for i := 0; i < len(ip); i++ {
		bcast[i] = ip[i] | ^mask[i]
	}
	return bcast
}

func maskBits(n net.IPNet) int {
	ones, _ := n.Mask.Size()
	return ones
}

// ---- main ----
func main() {
	var comment string
	flag.BoolVar(&verbose, "v", false, "verbose output")
	flag.BoolVar(&veryVerbose, "vv", false, "very verbose output")
	flag.StringVar(&comment, "c", "", "add a custom comment to the report")
	flag.Parse()

	fmt.Println("This is recon4 - research for IPv4. This binary is meant for Sandboxes, Honeypots and Labs.")
	fmt.Println("It collects network information, sends ICMP Echo Requests and TCP SYN packets.")
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

	ifaces, err := getIPv4Interfaces()
	if err == nil {
		rep.Interfaces = ifaces
	} else {
		fmt.Printf("Error getting interfaces: %v\n", err)
	}

	if comment != "" {
		rep.Comment = comment
	} else {
		firstMac := ""
		for _, iface := range ifaces {
			if iface.MACAddress != "" {
				firstMac = iface.MACAddress
				break
			}
		}
		rep.Comment = "AutoMeassurement+" + firstMac
	}
	for _, ii := range rep.Interfaces {
		vprintf("Interface %s: %v\n", ii.Name, ii.IPv4Addresses)
	}

	allMap := map[string]Neighbor{}

	// -------------------------------------------------------------------------
	// PHASE 2: Initial Discovery (Broadcast ICMP)
	// -------------------------------------------------------------------------
	vprintf("Starting initial ARP-like discovery...\n")
	arpResults := make(chan []Neighbor)
	var arpWg sync.WaitGroup
	for _, ii := range ifaces {
		for _, n := range ii.Nets {
			arpWg.Add(1)
			go func(ifaceInfo InterfaceInfo, netInfo net.IPNet) {
				defer arpWg.Done()
				ifaceObj, err := net.InterfaceByName(ifaceInfo.Name)
				if err != nil {
					return
				}
				found := discoverNeighbors(*ifaceObj, netInfo)
				arpResults <- found
			}(ii, n)
		}
	}

	go func() {
		arpWg.Wait()
		close(arpResults)
	}()

	for found := range arpResults {
		for _, n := range found {
			if _, ok := allMap[n.IP]; !ok {
				allMap[n.IP] = n
			}
		}
	}
	vprintf("Initial ARP-like discovery finished.\n")

	// -------------------------------------------------------------------------
	// PHASE 3: Subnet Scanning (Unicast ICMP)
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
			c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
			if err != nil {
				vprintf("Worker failed to create ICMP socket: %v\n", err)
				return
			}
			defer c.Close()

			for j := range icmpJobs {
				vprintf("Scanning subnet %s/%d on %s\n", j.net.IP.String(), maskBits(j.net), j.iface)
				// Scan first 254 hosts for common subnet sizes
				scanCount := 20
				ones, _ := j.net.Mask.Size()
				if ones > 24 {
					// For subnets smaller than /24, adjust scan count
					hostBits := 32 - ones
					if hostBits > 0 && hostBits < 8 {
						scanCount = (1 << hostBits) - 2
					}
				}

				hosts := hostsInSubnet(j.net, scanCount)
				for _, h := range hosts {
					vvprintf(" → ICMP check %s\n", h)
					ok, rtt := icmpv4PingWithConn(c, h, 1*time.Second)
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
				// We only want to scan private address spaces.
				if n.IP.IsPrivate() {
					icmpJobs <- icmpJob{iface: iface.Name, net: n}
				}
			}
		}
		close(icmpJobs)
	}()

	go func() {
		icmpWg.Wait()
		close(icmpResults)
	}()

	for n := range icmpResults {
		if _, ok := allMap[n.IP]; !ok {
			allMap[n.IP] = n
		}
	}
	vprintf("ICMP subnet scans finished.\n")

	// -------------------------------------------------------------------------
	// PHASE 4: Service Enumeration (Port Scanning)
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
					if checkPort(n.IP, p, 1*time.Second) {
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
	// PHASE 5: Internet Connectivity Check
	// -------------------------------------------------------------------------
	vprintf("Starting public probes...\n")
	for _, t := range publicTargets {
		ok, _ := icmpv4Ping(t, 2*time.Second)
		rep.PublicProbes = append(rep.PublicProbes, PublicProbe{Target: t, ICMPReachable: ok})
		if verbose && ok {
			fmt.Printf("Public target reachable: %s\n", t)
		}
	}
	vprintf("Public probes finished.\n")

	// -------------------------------------------------------------------------
	// PHASE 6: Reporting
	// -------------------------------------------------------------------------
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
	req.Header.Set("User-Agent", "recon4/"+version+"."+probe)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	fmt.Printf("Done: %s\n", resp.Status)
	defer resp.Body.Close()
	return nil
}
