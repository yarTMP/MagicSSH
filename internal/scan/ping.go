package scan

import (
	"context"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// pingFunc sends one ICMP echo and reports the reply's TTL and round trip.
type pingFunc func(ctx context.Context, ip string) (ttl int, rtt time.Duration, ok bool)

const pingTimeout = time.Second

// newPinger returns an in-process ICMP pinger, or falls back to running the
// system ping binary when no ICMP socket can be opened. close releases it.
func newPinger() (ping pingFunc, close func()) {
	p, err := newICMPPinger()
	if err != nil {
		return execPing, func() {}
	}
	return p.ping, p.close
}

// icmpPinger sends all echo requests from one socket and matches replies by
// source address, so a scan needs no ping processes. It uses an unprivileged
// ICMP datagram socket (net.ipv4.ping_group_range), or a raw socket as root.
type icmpPinger struct {
	conn *icmp.PacketConn
	raw  bool
	id   int
	seq  atomic.Uint32

	mu      sync.Mutex
	waiters map[string]chan int // source IP -> reply TTL
}

func newICMPPinger() (*icmpPinger, error) {
	raw := false
	conn, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil && os.Geteuid() == 0 {
		conn, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		raw = true
	}
	if err != nil {
		return nil, err
	}
	if err := conn.IPv4PacketConn().SetControlMessage(ipv4.FlagTTL, true); err != nil {
		conn.Close()
		return nil, err
	}
	p := &icmpPinger{conn: conn, raw: raw, id: os.Getpid() & 0xffff, waiters: map[string]chan int{}}
	go p.readLoop()
	return p, nil
}

func (p *icmpPinger) close() { p.conn.Close() }

func (p *icmpPinger) readLoop() {
	buf := make([]byte, 1500)
	for {
		n, cm, src, err := p.conn.IPv4PacketConn().ReadFrom(buf)
		if err != nil {
			return // socket closed
		}
		msg, err := icmp.ParseMessage(1, buf[:n]) // 1 = ICMP for IPv4
		if err != nil || msg.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		// Datagram sockets only deliver our own replies (the kernel owns the ID);
		// a raw socket sees every reply on the host.
		if echo, ok := msg.Body.(*icmp.Echo); !ok || (p.raw && echo.ID != p.id) {
			continue
		}
		ttl := 0
		if cm != nil {
			ttl = cm.TTL
		}
		p.mu.Lock()
		ch := p.waiters[addrIP(src)]
		p.mu.Unlock()
		if ch != nil {
			select {
			case ch <- ttl:
			default:
			}
		}
	}
}

func (p *icmpPinger) ping(ctx context.Context, ip string) (ttl int, rtt time.Duration, ok bool) {
	dst := net.ParseIP(ip).To4()
	if dst == nil {
		return 0, 0, false
	}
	ch := make(chan int, 1)
	p.mu.Lock()
	p.waiters[ip] = ch
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		if p.waiters[ip] == ch {
			delete(p.waiters, ip)
		}
		p.mu.Unlock()
	}()

	msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{
		ID: p.id, Seq: int(p.seq.Add(1) & 0xffff), Data: []byte("magicssh"),
	}}
	b, err := msg.Marshal(nil)
	if err != nil {
		return 0, 0, false
	}
	var addr net.Addr = &net.UDPAddr{IP: dst}
	if p.raw {
		addr = &net.IPAddr{IP: dst}
	}
	start := time.Now()
	if _, err := p.conn.WriteTo(b, addr); err != nil {
		return 0, 0, false
	}
	t := time.NewTimer(pingTimeout)
	defer t.Stop()
	select {
	case ttl := <-ch:
		return ttl, time.Since(start), true
	case <-t.C:
	case <-ctx.Done():
	}
	return 0, 0, false
}

func addrIP(a net.Addr) string {
	switch a := a.(type) {
	case *net.UDPAddr:
		return a.IP.String()
	case *net.IPAddr:
		return a.IP.String()
	}
	return ""
}

var (
	ttlRe = regexp.MustCompile(`ttl=(\d+)`)
	rttRe = regexp.MustCompile(`time=([0-9.]+) ms`)
)

// execPing runs the system ping (setcap'd or using ping sockets, no root
// needed). It is the fallback when magicssh cannot open an ICMP socket itself.
func execPing(ctx context.Context, ip string) (ttl int, rtt time.Duration, ok bool) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "ping", "-n", "-c1", "-W1", ip).Output()
	m := ttlRe.FindSubmatch(out)
	if m == nil {
		return 0, 0, false
	}
	ttl, _ = strconv.Atoi(string(m[1]))
	if r := rttRe.FindSubmatch(out); r != nil {
		if ms, err := strconv.ParseFloat(string(r[1]), 64); err == nil {
			rtt = time.Duration(ms * float64(time.Millisecond))
		}
	}
	return ttl, rtt, true
}
