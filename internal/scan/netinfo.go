package scan

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
)

// Network describes the local interface the scan runs from.
type Network struct {
	Iface   string
	LocalIP net.IP
	LocalHW net.HardwareAddr
	Subnet  *net.IPNet
}

// DetectNetwork finds the interface carrying the default IPv4 route (or the
// named one) and returns its subnet.
func DetectNetwork(ifaceName string) (*Network, error) {
	if ifaceName == "" {
		ifaceName = defaultRouteIface()
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, ifc := range ifaces {
		if ifaceName != "" && ifc.Name != ifaceName {
			continue
		}
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil {
				continue
			}
			return &Network{
				Iface:   ifc.Name,
				LocalIP: ipn.IP.To4(),
				LocalHW: ifc.HardwareAddr,
				Subnet:  &net.IPNet{IP: ipn.IP.Mask(ipn.Mask).To4(), Mask: ipn.Mask},
			}, nil
		}
	}
	if ifaceName != "" {
		return nil, fmt.Errorf("no IPv4 address found on interface %q", ifaceName)
	}
	return nil, errors.New("no active IPv4 interface found; pass --subnet")
}

// defaultRouteIface reads /proc/net/route for the interface with destination 0.0.0.0.
func defaultRouteIface() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[1] == "00000000" {
			return fields[0]
		}
	}
	return ""
}

// ParseSubnet accepts "192.168.1.0/24" or a bare IP (treated as /32).
func ParseSubnet(s string) (*net.IPNet, error) {
	if !strings.Contains(s, "/") {
		s += "/32"
	}
	_, ipn, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}
	if ipn.IP.To4() == nil {
		return nil, fmt.Errorf("%s: only IPv4 subnets are supported", s)
	}
	return ipn, nil
}

// HostCount is len(Hosts(n)) without building the list.
func HostCount(n *net.IPNet) int {
	ones, bits := n.Mask.Size()
	size := 1 << uint(bits-ones)
	if size > 2 {
		size -= 2
	}
	return size
}

// Hosts lists the usable host addresses in a subnet (network and broadcast
// addresses are excluded for prefixes shorter than /31).
func Hosts(n *net.IPNet) []net.IP {
	ones, bits := n.Mask.Size()
	size := uint32(1) << uint(bits-ones)
	start := binary.BigEndian.Uint32(n.IP.To4())
	first, last := start, start+size-1
	if size > 2 {
		first++
		last--
	}
	out := make([]net.IP, 0, last-first+1)
	for i := first; ; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		out = append(out, ip)
		if i == last {
			break
		}
	}
	return out
}

// nonPublic are the IPv4 ranges that are never routed on the internet:
// RFC 1918 private, carrier-grade NAT, link-local and loopback.
var nonPublic = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8"} {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

// IsPrivate reports whether the whole subnet lies in a non-public range.
func IsPrivate(n *net.IPNet) bool {
	first := n.IP.Mask(n.Mask).To4()
	last := make(net.IP, 4)
	for i := range last {
		last[i] = first[i] | ^n.Mask[len(n.Mask)-4+i]
	}
	for _, r := range nonPublic {
		if r.Contains(first) && r.Contains(last) {
			return true
		}
	}
	return false
}
