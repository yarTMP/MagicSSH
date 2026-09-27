package scan

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestHostKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		ssh.NewServerConn(c, cfg)
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	want := "ssh-ed25519 " + ssh.FingerprintSHA256(signer.PublicKey())
	if got := hostKey(context.Background(), "127.0.0.1", port, time.Second); got != want {
		t.Errorf("hostKey = %q, want %q", got, want)
	}
}

func TestIsPrivate(t *testing.T) {
	for cidr, want := range map[string]bool{
		"192.168.1.0/24": true, "10.0.0.0/16": true, "172.31.0.0/16": true,
		"100.64.1.0/24": true, "127.0.0.1": true,
		"8.8.8.0/24": false, "172.32.0.0/16": false, "192.169.0.0/16": false,
	} {
		sn, _ := ParseSubnet(cidr)
		if got := IsPrivate(sn); got != want {
			t.Errorf("IsPrivate(%s) = %v, want %v", cidr, got, want)
		}
	}
}
