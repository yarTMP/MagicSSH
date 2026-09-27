package sshcheck

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func newSigner(t *testing.T, kind string) ssh.Signer {
	t.Helper()
	var key any
	switch kind {
	case "ed25519":
		_, key, _ = ed25519.GenerateKey(rand.Reader)
	case "ecdsa":
		key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// server serves the given host keys on 127.0.0.1 and returns its port.
func server(t *testing.T, keys ...ssh.Signer) int {
	t.Helper()
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	for _, k := range keys {
		cfg.AddHostKey(k)
	}
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
			go func() {
				defer c.Close()
				ssh.NewServerConn(c, cfg)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

type env struct {
	ssh   string
	known string
	port  int
}

// setup writes known_hosts lines (with HOST standing for the server's
// known_hosts name) and returns ssh options that use only that file.
func setup(t *testing.T, port int, lines ...string) (env, []string) {
	t.Helper()
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("ssh client not installed")
	}
	known := filepath.Join(t.TempDir(), "known_hosts")
	name := knownhosts.Normalize(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(strings.ReplaceAll(l, "HOST", name) + "\n")
	}
	if err := os.WriteFile(known, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := []string{"-F", "/dev/null", "-p", strconv.Itoa(port),
		"-o", "UserKnownHostsFile=" + known, "-o", "GlobalKnownHostsFile=/dev/null"}
	return env{sshPath, known, port}, opts
}

func line(k ssh.PublicKey) string {
	return "HOST " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

func check(t *testing.T, e env, opts []string) Result {
	t.Helper()
	r := Check(context.Background(), e.ssh, opts, "127.0.0.1", time.Second)
	if r.Err != nil {
		t.Fatalf("Check: %v", r.Err)
	}
	return r
}

func TestCheck(t *testing.T) {
	ed, ec := newSigner(t, "ed25519"), newSigner(t, "ecdsa")
	oldEd, oldEc := newSigner(t, "ed25519"), newSigner(t, "ecdsa")
	port := server(t, ed, ec)

	cases := []struct {
		name  string
		lines []string
		want  Status
		key   ssh.PublicKey // key the server should be asked for
	}{
		{"match", []string{line(ed.PublicKey())}, OK, ed.PublicKey()},
		{"no entry", nil, Unknown, ed.PublicKey()},
		{"same type differs", []string{line(oldEd.PublicKey())}, Mismatch, ed.PublicKey()},
		// Both types changed, as after a reinstall.
		{"reinstalled", []string{line(oldEd.PublicKey()), line(oldEc.PublicKey())}, Mismatch, ed.PublicKey()},
		// ssh asks for the ECDSA key it knows, although ed25519 is preferred by default.
		{"known type preferred", []string{line(ec.PublicKey())}, OK, ec.PublicKey()},
		{"revoked", []string{"@revoked " + line(ed.PublicKey())}, Revoked, ed.PublicKey()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, opts := setup(t, port, c.lines...)
			r := check(t, e, opts)
			if r.Status != c.want || r.Key != Fingerprint(c.key) {
				t.Errorf("status %q key %s, want %q key %s (known %v)", r.Status, r.Key, c.want, Fingerprint(c.key), r.Known)
			}
			if r.Name != "[127.0.0.1]:"+strconv.Itoa(port) {
				t.Errorf("name = %q", r.Name)
			}
		})
	}
}

func TestOtherTypeOnlyIsUnknown(t *testing.T) {
	// The server only has ed25519 now; known_hosts only an old ECDSA key.
	// ssh asks as for a new host rather than refusing.
	ed := newSigner(t, "ed25519")
	port := server(t, ed)
	e, opts := setup(t, port, line(newSigner(t, "ecdsa").PublicKey()))
	if r := check(t, e, opts); r.Status != Unknown || len(r.Known) != 1 {
		t.Errorf("status %q known %v, want unknown with the ECDSA entry listed", r.Status, r.Known)
	}
}

func TestHostKeyAliasAndStrict(t *testing.T) {
	ed := newSigner(t, "ed25519")
	port := server(t, ed)
	e, opts := setup(t, port, "magicssh-aabbcc "+strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ed.PublicKey()))))
	opts = append(opts, "-o", "HostKeyAlias=magicssh-aabbcc", "-o", "StrictHostKeyChecking=yes")
	r := check(t, e, opts)
	if r.Status != OK || r.Name != "magicssh-aabbcc" || !r.Strict {
		t.Errorf("got %+v", r)
	}
}

func TestRemove(t *testing.T) {
	ed := newSigner(t, "ed25519")
	port := server(t, ed)
	keep := "other.example " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ed.PublicKey())))
	e, opts := setup(t, port, line(newSigner(t, "ed25519").PublicKey()), keep)
	r := check(t, e, opts)
	if r.Status != Mismatch {
		t.Fatalf("status %q, want mismatch", r.Status)
	}
	if err := Remove(context.Background(), r.Name, r.Files()); err != nil {
		t.Fatal(err)
	}
	if r := check(t, e, opts); r.Status != Unknown {
		t.Errorf("after Remove: status %q, want unknown", r.Status)
	}
	data, _ := os.ReadFile(e.known)
	if !strings.Contains(string(data), "other.example") {
		t.Error("Remove deleted another host's entry")
	}
	if _, err := os.Stat(e.known + ".old"); err != nil {
		t.Error("no .old backup kept")
	}
}
