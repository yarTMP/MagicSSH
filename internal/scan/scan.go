// Package scan finds hosts with an open SSH port on a local subnet and
// collects the details used to identify them.
package scan

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"magicssh/internal/osdetect"
)

type Host struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
	MAC      string `json:"mac,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	SSH      bool   `json:"ssh"` // SSH port is open
	Banner   string `json:"banner,omitempty"`
	HostKey  string `json:"host_key,omitempty"` // "<type> SHA256:<fingerprint>"
	// KeyChanged is set when HostKey differs from the key remembered for this
	// device: it may be a different machine answering on its address.
	KeyChanged bool `json:"key_changed,omitempty"`
	// KnownHosts is the result of checking the host key against the user's
	// known_hosts as ssh would: "ok", "unknown", "mismatch" or "revoked"
	// ("" = not checked). See package sshcheck.
	KnownHosts string          `json:"known_hosts,omitempty"`
	Latency    time.Duration   `json:"latency"`
	TTL        int             `json:"ttl,omitempty"`
	OpenPorts  []int           `json:"open_ports,omitempty"`
	OS         osdetect.Result `json:"os"`
	Self       bool            `json:"self,omitempty"`
}

type Options struct {
	Subnet   *net.IPNet
	Port     int
	Timeout  time.Duration
	Workers  int
	SSHOnly  bool     // drop live devices without the SSH port open
	Deep     bool     // use nmap -O (needs root, or SudoNmap)
	SudoNmap bool     // run nmap through "sudo -n" (credentials cached beforehand)
	Local    *Network // optional, marks the scanning host itself
}

type Progress struct {
	Done, Total int
	Found       int // live devices
	SSH         int // devices with the SSH port open
	Phase       string
}

// probePorts are checked on every live device to help tell operating systems apart.
var probePorts = []int{135, 3389, 445, 88, 548, 3283}

// Run discovers live devices on the subnet. A device counts as live if it
// accepts or refuses a TCP connection on the SSH port, answers ping, or shows
// up in the kernel ARP table (which catches firewalled devices on the local
// link). On the local link the ARP table already tells which addresses are in
// use, so only live devices are pinged (for TTL); off-link every address is
// pinged during the scan. progress (optional) is called from worker goroutines.
func Run(ctx context.Context, opt Options, progress func(Progress)) ([]Host, error) {
	if opt.Port == 0 {
		opt.Port = 22
	}
	if opt.Timeout == 0 {
		opt.Timeout = 500 * time.Millisecond
	}
	if opt.Workers <= 0 {
		opt.Workers = 256
	}
	report := func(p Progress) {
		if progress != nil {
			progress(p)
		}
	}

	targets := Hosts(opt.Subnet)
	total := len(targets)
	var done, found, sshCount int64
	var mu sync.Mutex
	byIP := map[string]*Host{}

	pingFn, closePing := newPinger()
	defer closePing()
	sameLink := opt.Local != nil && onLink(opt.Local.Subnet, opt.Subnet)
	var scanPing pingFunc // ping during the TCP scan only when ARP can't show liveness
	if !sameLink {
		scanPing = pingFn
	}

	// Poll the ARP table while scanning: the kernel evicts entries once it holds
	// more than gc_thresh3 (1024 by default), so one read at the end misses
	// devices on large subnets.
	arp := map[string]string{}
	stopARP, arpDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(arpDone)
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				mergeARP(arp)
			case <-stopARP:
				return
			}
		}
	}()

	jobs := make(chan net.IP)
	var wg sync.WaitGroup
	for w := 0; w < opt.Workers && w < total; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				if h, ok := probe(ctx, ip.String(), opt.Port, opt.Timeout, scanPing); ok {
					mu.Lock()
					byIP[h.IP] = &h
					mu.Unlock()
					atomic.AddInt64(&found, 1)
					if h.SSH {
						atomic.AddInt64(&sshCount, 1)
					}
				}
				d := atomic.AddInt64(&done, 1)
				report(Progress{Done: int(d), Total: total, Found: int(atomic.LoadInt64(&found)),
					SSH: int(atomic.LoadInt64(&sshCount)), Phase: "scanning"})
			}
		}()
	}
feed:
	for _, ip := range targets {
		select {
		case jobs <- ip:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	close(stopARP)
	<-arpDone
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Devices that dropped both TCP and ping still answered ARP for the probes above.
	mergeARP(arp)
	for ip := range arp {
		if _, ok := byIP[ip]; !ok && opt.Subnet.Contains(net.ParseIP(ip)) {
			byIP[ip] = &Host{IP: ip}
		}
	}
	if opt.Local != nil && opt.Subnet.Contains(opt.Local.LocalIP) {
		if _, ok := byIP[opt.Local.LocalIP.String()]; !ok {
			byIP[opt.Local.LocalIP.String()] = &Host{IP: opt.Local.LocalIP.String()}
		}
	}

	hosts := make([]Host, 0, len(byIP))
	for _, h := range byIP {
		if opt.SSHOnly && !h.SSH {
			continue
		}
		hosts = append(hosts, *h)
	}
	report(Progress{Done: total, Total: total, Found: len(byIP), SSH: int(sshCount), Phase: "identifying"})
	var enrichPing pingFunc
	if sameLink {
		enrichPing = pingFn
	}
	enrich(ctx, hosts, arp, opt, enrichPing)

	sort.Slice(hosts, func(i, j int) bool { return ipLess(hosts[i].IP, hosts[j].IP) })
	return hosts, nil
}

// probe checks one address: a TCP connect to the SSH port (reading the banner
// if it is open) and, if pingFn is set, a ping. ok reports whether the device
// answered at all.
func probe(ctx context.Context, ip string, port int, timeout time.Duration, pingFn pingFunc) (h Host, ok bool) {
	h.IP = ip
	var pingOK bool
	var pingRTT time.Duration
	var wg sync.WaitGroup
	if pingFn != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.TTL, pingRTT, pingOK = pingFn(ctx, ip)
		}()
	}

	d := net.Dialer{Timeout: timeout}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	tcpRTT := time.Since(start)
	refused := errors.Is(err, syscall.ECONNREFUSED)
	if err == nil {
		h.SSH = true
		h.Banner = readBanner(conn)
		conn.Close()
	}
	wg.Wait()

	switch {
	case pingOK:
		h.Latency = pingRTT
	case h.SSH || refused:
		h.Latency = tcpRTT
	}
	return h, h.SSH || refused || pingOK
}

// maxBannerRead bounds how much a server can make us buffer while looking for
// its identification line.
const maxBannerRead = 4096

// readBanner reads the SSH identification line. Servers may send other lines
// before it (RFC 4253 §4.2). The banner is attacker-controlled, so it is
// read through a size limit and cleaned before use.
func readBanner(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	r := bufio.NewReader(io.LimitReader(conn, maxBannerRead))
	for i := 0; i < 5; i++ {
		line, err := r.ReadString('\n')
		line = Clean(line, maxBannerLen)
		if strings.HasPrefix(line, "SSH-") {
			return line
		}
		if err != nil {
			break
		}
	}
	return ""
}

// enrich fills in hostname, MAC, vendor, extra ports and the OS guess.
// enrichWorkers bounds how many hosts are identified at once; each one runs a
// DNS lookup, possibly two helper processes, a ping and several connections.
const enrichWorkers = 64

// pingFn, if set, pings each host for its TTL and latency.
func enrich(ctx context.Context, hosts []Host, arp map[string]string, opt Options, pingFn pingFunc) {
	jobs := make(chan *Host)
	var wg sync.WaitGroup
	for w := 0; w < enrichWorkers && w < len(hosts); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range jobs {
				if pingFn != nil {
					if ttl, rtt, ok := pingFn(ctx, h.IP); ok {
						h.TTL, h.Latency = ttl, rtt
					}
				}
				h.Hostname = lookupName(ctx, h.IP)
				h.OpenPorts = openPorts(ctx, h.IP, probePorts, opt.Timeout)
				if h.SSH {
					h.HostKey = hostKey(ctx, h.IP, opt.Port, opt.Timeout)
				}
			}
		}()
	}
	for i := range hosts {
		jobs <- &hosts[i]
	}
	close(jobs)
	wg.Wait()

	for i := range hosts {
		h := &hosts[i]
		if opt.Local != nil && h.IP == opt.Local.LocalIP.String() {
			h.Self = true
			h.MAC = opt.Local.LocalHW.String()
			if h.Hostname == "" {
				h.Hostname, _ = os.Hostname()
			}
		} else {
			h.MAC = arp[h.IP]
		}
		if h.MAC != "" {
			h.Vendor = osdetect.Vendor(h.MAC)
		}
		h.classify("")
	}

	// nmap -O is slow (seconds per host), so only ask it about hosts the cheap
	// signals left unsure of.
	if opt.Deep && (os.Geteuid() == 0 || opt.SudoNmap) {
		var unsure []*Host
		var ips []string
		for i := range hosts {
			if hosts[i].OS.Confidence < osdetect.High {
				unsure = append(unsure, &hosts[i])
				ips = append(ips, hosts[i].IP)
			}
		}
		nmapOS := nmapDetect(ctx, ips, opt.Port, os.Geteuid() != 0)
		for _, h := range unsure {
			if n := nmapOS[h.IP]; n != "" {
				h.classify(n)
			}
		}
	}
}

func (h *Host) classify(nmapOS string) {
	h.OS = osdetect.Classify(osdetect.Signals{
		Banner:    h.Banner,
		Vendor:    h.Vendor,
		TTL:       h.TTL,
		Hostname:  h.Hostname,
		OpenPorts: h.OpenPorts,
		NmapOS:    nmapOS,
	})
}

// Recheck probes the SSH port of a single host again, e.g. after the user
// enabled SSH on it, and updates SSH, Banner and the OS guess.
func Recheck(ctx context.Context, h *Host, port int, timeout time.Duration) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(h.IP, strconv.Itoa(port)))
	if err != nil {
		h.SSH, h.Banner = false, ""
		return
	}
	h.SSH, h.Banner = true, readBanner(conn)
	conn.Close()
	h.HostKey = hostKey(ctx, h.IP, port, timeout)
	h.classify("")
}

// lookupName tries reverse DNS, then NSS (which may include mDNS), then avahi.
// Names come from other devices on the network, so they are cleaned.
func lookupName(ctx context.Context, ip string) string {
	return Clean(rawLookupName(ctx, ip), maxHostnameLen)
}

func rawLookupName(ctx context.Context, ip string) string {
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	if names, err := net.DefaultResolver.LookupAddr(ctx, ip); err == nil && len(names) > 0 {
		return strings.TrimSuffix(names[0], ".")
	}
	if out, err := exec.CommandContext(ctx, "getent", "hosts", ip).Output(); err == nil {
		if f := strings.Fields(string(out)); len(f) >= 2 {
			return f[1]
		}
	}
	if nssHasMDNS() {
		return "" // getent already asked mDNS; avahi would only repeat it
	}
	if out, err := exec.CommandContext(ctx, "avahi-resolve", "-a", ip).Output(); err == nil {
		if f := strings.Fields(string(out)); len(f) >= 2 {
			return strings.TrimSuffix(f[1], ".")
		}
	}
	return ""
}

func openPorts(ctx context.Context, ip string, ports []int, timeout time.Duration) []int {
	var mu sync.Mutex
	var wg sync.WaitGroup
	var open []int
	for _, p := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			d := net.Dialer{Timeout: timeout}
			c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(p)))
			if err != nil {
				return
			}
			c.Close()
			mu.Lock()
			open = append(open, p)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	sort.Ints(open)
	return open
}

// nssHasMDNS reports whether the hosts line of /etc/nsswitch.conf includes an
// mDNS module (nss-mdns), in which case getent resolves .local names itself.
var nssHasMDNS = sync.OnceValue(func() bool {
	data, err := os.ReadFile("/etc/nsswitch.conf")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if f := strings.Fields(line); len(f) > 0 && f[0] == "hosts:" {
			return strings.Contains(line, "mdns")
		}
	}
	return false
})

// mergeARP adds the IP -> MAC entries of the kernel neighbour table to m.
func mergeARP(m map[string]string) {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		f := strings.Fields(line)
		// f[2] is the flags field; 0x2 (ATF_COM) marks a resolved entry.
		if len(f) >= 4 && f[2] != "0x0" && f[3] != "00:00:00:00:00:00" {
			m[f[0]] = f[3]
		}
	}
}

// onLink reports whether the scanned subnet lies within the local interface's
// subnet, i.e. its devices are reached directly and show up in the ARP table.
func onLink(local, scanned *net.IPNet) bool {
	lo, _ := local.Mask.Size()
	so, _ := scanned.Mask.Size()
	return so >= lo && local.Contains(scanned.IP)
}

func ipLess(a, b string) bool {
	ia, ib := net.ParseIP(a).To4(), net.ParseIP(b).To4()
	if ia == nil || ib == nil {
		return a < b
	}
	return binary.BigEndian.Uint32(ia) < binary.BigEndian.Uint32(ib)
}

// FormatLatency renders a latency compactly, e.g. "3ms".
func FormatLatency(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	if d < time.Millisecond {
		return fmt.Sprintf("%dµs", d.Microseconds())
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}
