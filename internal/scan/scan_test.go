package scan

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestHosts(t *testing.T) {
	cases := []struct {
		cidr        string
		n           int
		first, last string
	}{
		{"192.168.1.0/24", 254, "192.168.1.1", "192.168.1.254"},
		{"192.168.1.77/24", 254, "192.168.1.1", "192.168.1.254"},
		{"10.0.0.0/30", 2, "10.0.0.1", "10.0.0.2"},
		{"10.0.0.0/31", 2, "10.0.0.0", "10.0.0.1"},
		{"10.0.0.5/32", 1, "10.0.0.5", "10.0.0.5"},
		{"172.16.0.0/16", 65534, "172.16.0.1", "172.16.255.254"},
	}
	for _, c := range cases {
		n, err := ParseSubnet(c.cidr)
		if err != nil {
			t.Fatal(err)
		}
		h := Hosts(n)
		if len(h) != c.n || h[0].String() != c.first || h[len(h)-1].String() != c.last {
			t.Errorf("%s: got %d hosts %s..%s, want %d %s..%s", c.cidr, len(h), h[0], h[len(h)-1], c.n, c.first, c.last)
		}
	}
}

func TestParseSubnet(t *testing.T) {
	if n, err := ParseSubnet("10.1.2.3"); err != nil || n.String() != "10.1.2.3/32" {
		t.Errorf("bare IP: %v %v", n, err)
	}
	if _, err := ParseSubnet("fe80::/64"); err == nil {
		t.Error("expected IPv6 to be rejected")
	}
	if _, err := ParseSubnet("nonsense"); err == nil {
		t.Error("expected error")
	}
}

// fakeSSH serves a banner (optionally preceded by other lines) on a random port.
func fakeSSH(t *testing.T, lines ...string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			for _, l := range lines {
				c.Write([]byte(l + "\r\n"))
			}
			c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestProbeSSHBanner(t *testing.T) {
	port := fakeSSH(t, "Welcome!", "SSH-2.0-OpenSSH_for_Windows_9.5")
	h, ok := probe(context.Background(), "127.0.0.1", port, time.Second, execPing)
	if !ok || !h.SSH || h.Banner != "SSH-2.0-OpenSSH_for_Windows_9.5" {
		t.Fatalf("probe = %+v, %v", h, ok)
	}
}

func TestRunFindsHost(t *testing.T) {
	port := fakeSSH(t, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5")
	sn, _ := ParseSubnet("127.0.0.1/32")
	hosts, err := Run(context.Background(), Options{Subnet: sn, Port: port, Timeout: 300 * time.Millisecond}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0].OS.Label() != "Linux (Ubuntu)" {
		t.Fatalf("Run = %+v", hosts)
	}
}

func TestProbeClosedPort(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	// A refused connection still proves the device is up, but SSH is closed.
	h, ok := probe(context.Background(), "127.0.0.1", port, 200*time.Millisecond, execPing)
	if !ok || h.SSH {
		t.Errorf("closed port %s: probe = %+v, %v; want live without SSH", strconv.Itoa(port), h, ok)
	}
}

func TestRunSSHOnly(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	sn, _ := ParseSubnet("127.0.0.1/32")
	all, _ := Run(context.Background(), Options{Subnet: sn, Port: port, Timeout: 200 * time.Millisecond}, nil)
	sshOnly, _ := Run(context.Background(), Options{Subnet: sn, Port: port, Timeout: 200 * time.Millisecond, SSHOnly: true}, nil)
	if len(all) != 1 || len(sshOnly) != 0 {
		t.Errorf("all=%d sshOnly=%d, want 1 and 0", len(all), len(sshOnly))
	}
}

func TestParseNmapXML(t *testing.T) {
	xml := `<?xml version="1.0"?><nmaprun>
<host><address addr="192.168.1.5" addrtype="ipv4"/><address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
<os><osmatch name="Linux 5.0 - 5.14" accuracy="95"/><osmatch name="Microsoft Windows 11" accuracy="98"/></os></host>
<host><address addr="192.168.1.6" addrtype="ipv4"/></host>
</nmaprun>`
	got := parseNmapXML([]byte(xml))
	if got["192.168.1.5"] != "Microsoft Windows 11" || len(got) != 1 {
		t.Errorf("parseNmapXML = %v", got)
	}
}

func TestIPLess(t *testing.T) {
	if !ipLess("192.168.1.9", "192.168.1.10") {
		t.Error("expected numeric ordering")
	}
}

func TestClean(t *testing.T) {
	cases := []struct{ in, want string }{
		{"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"},
		{"SSH-2.0-x\x1b]52;c;cm0gLXJmIH4=\x07\x1b[2J", "SSH-2.0-x]52;c;cm0gLXJmIH4=[2J"},
		{"evil‮gpj.exe", "evilgpj.exe"},  // bidi override
		{"bad\xffutf8\u009b", "badutf8"}, // invalid UTF-8 and C1 CSI
		{"héllo.local", "héllo.local"},
	}
	for _, c := range cases {
		if got := Clean(c.in, 100); got != c.want {
			t.Errorf("Clean(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := Clean("abcdef", 3); got != "abc" {
		t.Errorf("Clean cap = %q", got)
	}
}

func TestReadBannerLimits(t *testing.T) {
	// A server that streams data without a newline must not make us buffer it all.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		junk := make([]byte, 64<<10)
		for i := range junk {
			junk[i] = 'A'
		}
		for i := 0; i < 100; i++ {
			if _, err := c.Write(junk); err != nil {
				return
			}
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	if b := readBanner(c); b != "" {
		t.Errorf("banner = %q, want empty", b)
	}
	if time.Since(start) > time.Second {
		t.Error("readBanner kept reading past its limit")
	}
}

func TestProbeCleansBanner(t *testing.T) {
	port := fakeSSH(t, "SSH-2.0-OpenSSH_9.8\x1b[31m red")
	h, ok := probe(context.Background(), "127.0.0.1", port, time.Second, nil)
	if !ok || h.Banner != "SSH-2.0-OpenSSH_9.8[31m red" {
		t.Fatalf("probe = %q, %v", h.Banner, ok)
	}
}

func TestSanitize(t *testing.T) {
	bad := Host{IP: "-oProxyCommand=touch /tmp/x"}
	if bad.Sanitize() {
		t.Error("expected invalid IP to be rejected")
	}
	h := Host{IP: "192.168.1.5", MAC: "not-a-mac", Hostname: "pc\x1b[2J"}
	if !h.Sanitize() || h.MAC != "" || h.Hostname != "pc[2J" {
		t.Errorf("Sanitize = %+v", h)
	}
}

func TestOnLink(t *testing.T) {
	local, _ := ParseSubnet("192.168.1.0/24")
	for cidr, want := range map[string]bool{
		"192.168.1.0/24": true, "192.168.1.64/26": true, "192.168.1.5": true,
		"192.168.0.0/16": false, "10.0.0.0/24": false,
	} {
		sn, _ := ParseSubnet(cidr)
		if got := onLink(local, sn); got != want {
			t.Errorf("onLink(%s) = %v, want %v", cidr, got, want)
		}
	}
}

func TestICMPPinger(t *testing.T) {
	p, err := newICMPPinger()
	if err != nil {
		t.Skip("no ICMP socket available:", err)
	}
	defer p.close()
	ttl, rtt, ok := p.ping(context.Background(), "127.0.0.1")
	if !ok || ttl <= 0 || rtt <= 0 {
		t.Fatalf("ping 127.0.0.1 = ttl %d rtt %v ok %v", ttl, rtt, ok)
	}
	// 192.0.2.0/24 is reserved for documentation and never answers.
	if _, _, ok := p.ping(context.Background(), "192.0.2.1"); ok {
		t.Error("unexpected reply from TEST-NET-1")
	}
}

func TestHostCount(t *testing.T) {
	for _, cidr := range []string{"192.168.1.0/24", "10.0.0.0/30", "10.0.0.0/31", "10.0.0.5/32", "172.16.0.0/16"} {
		n, _ := ParseSubnet(cidr)
		if got, want := HostCount(n), len(Hosts(n)); got != want {
			t.Errorf("HostCount(%s) = %d, want %d", cidr, got, want)
		}
	}
}
