// Package sshcheck runs the host key check ssh would run against known_hosts
// before magicssh hands over to ssh, so a mismatch can be explained and fixed
// in the picker instead of ending in ssh's "REMOTE HOST IDENTIFICATION HAS
// CHANGED" error.
package sshcheck

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type Status string

const (
	NotChecked Status = ""
	OK         Status = "ok"       // a known_hosts entry matches the server's key
	Unknown    Status = "unknown"  // no entry of this key type; ssh will ask to add it
	Mismatch   Status = "mismatch" // an entry of the same key type differs; ssh refuses to connect
	Revoked    Status = "revoked"  // known_hosts marks the server's key @revoked
)

// Entry is a known_hosts line for the host.
type Entry struct {
	Key  string // "<type> SHA256:<fingerprint>"
	File string
	Line int
}

type Result struct {
	Status Status
	Name   string  // name ssh looks up in known_hosts: HostKeyAlias, "ip" or "[ip]:port"
	Key    string  // "<type> SHA256:<fingerprint>" the server presented
	Known  []Entry // known_hosts entries for Name that did not match Key
	Strict bool    // StrictHostKeyChecking=yes: ssh won't offer to add an unknown key
	Err    error   // the check could not run; ssh will still do its own
}

// Fingerprint formats a key the way magicssh shows keys everywhere.
func Fingerprint(k ssh.PublicKey) string {
	return k.Type() + " " + ssh.FingerprintSHA256(k)
}

// defaultAlgorithms is OpenSSH's order when it has no known_hosts entry.
var defaultAlgorithms = []string{
	ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256,
}

// settings are the parts of ssh's effective configuration that decide the
// host key check, as printed by "ssh -G".
type settings struct {
	hostname string
	port     int
	alias    string
	files    []string
	strict   bool
}

// Check does what ssh would do with opts (the options magicssh passes to ssh,
// without -l or the host) for ip: resolve the configuration, fetch the server's
// host key and compare it with known_hosts. It never authenticates.
func Check(ctx context.Context, sshPath string, opts []string, ip string, timeout time.Duration) Result {
	st, err := resolve(ctx, sshPath, opts, ip)
	if err != nil {
		return Result{Err: err}
	}
	// ssh looks up "host" or "[host]:port", but a HostKeyAlias as written. The
	// knownhosts package drops port 22 when normalizing, so give it that.
	addr := net.JoinHostPort(st.hostname, strconv.Itoa(st.port))
	if st.alias != "" {
		addr = net.JoinHostPort(st.alias, "22")
	}
	res := Result{Name: knownhosts.Normalize(addr), Strict: st.strict}

	var files []string
	for _, f := range st.files {
		if _, err := os.Stat(f); err == nil {
			files = append(files, f)
		}
	}
	check, err := knownhosts.New(files...)
	if err != nil {
		res.Err = err
		return res
	}
	remote := &net.TCPAddr{IP: net.ParseIP(ip), Port: st.port}

	// Like ssh, ask the server first for key types known_hosts already holds.
	key, err := fetchKey(ctx, net.JoinHostPort(st.hostname, strconv.Itoa(st.port)),
		preferred(knownEntries(check, addr, remote)), timeout)
	if err != nil {
		res.Err = err
		return res
	}
	res.Key = Fingerprint(key)

	var keyErr *knownhosts.KeyError
	var revErr *knownhosts.RevokedError
	switch err := check(addr, remote, key); {
	case err == nil:
		res.Status = OK
	case errors.As(err, &revErr):
		res.Status = Revoked
		res.Known = []Entry{entry(revErr.Revoked)}
	case errors.As(err, &keyErr):
		// ssh only refuses when a key of the same type differs; entries of
		// other types just make it ask as for a new host.
		res.Status = Unknown
		for _, k := range keyErr.Want {
			if k.Key.Type() == key.Type() {
				res.Status = Mismatch
			}
			res.Known = append(res.Known, entry(k))
		}
	default:
		res.Err = err
	}
	return res
}

func entry(k knownhosts.KnownKey) Entry {
	return Entry{Key: Fingerprint(k.Key), File: k.Filename, Line: k.Line}
}

func resolve(ctx context.Context, sshPath string, opts []string, ip string) (settings, error) {
	args := append(append([]string{"-G"}, opts...), "--", ip)
	out, err := exec.CommandContext(ctx, sshPath, args...).Output()
	if err != nil {
		return settings{}, fmt.Errorf("ssh -G: %w", err)
	}
	st := settings{hostname: ip, port: 22}
	for _, line := range strings.Split(string(out), "\n") {
		key, val, _ := strings.Cut(strings.TrimSpace(line), " ")
		switch key {
		case "hostname":
			st.hostname = val
		case "port":
			if p, err := strconv.Atoi(val); err == nil {
				st.port = p
			}
		case "hostkeyalias":
			if val != "none" {
				st.alias = val
			}
		case "userknownhostsfile", "globalknownhostsfile":
			for _, f := range strings.Fields(val) {
				st.files = append(st.files, expandHome(f))
			}
		case "stricthostkeychecking":
			st.strict = val == "true" || val == "yes"
		}
	}
	return st, nil
}

func expandHome(p string) string {
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, rest)
		}
	}
	return p
}

// probeKey matches no known_hosts entry, so checking it lists every entry
// for a host.
var probeKey = sync.OnceValue(func() ssh.PublicKey {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := ssh.NewPublicKey(pub)
	return k
})

func knownEntries(check ssh.HostKeyCallback, addr string, remote net.Addr) []knownhosts.KnownKey {
	var keyErr *knownhosts.KeyError
	if errors.As(check(addr, remote, probeKey()), &keyErr) {
		return keyErr.Want
	}
	return nil
}

// preferred orders host key algorithms the way ssh does: those matching key
// types already in known_hosts first, then the defaults.
func preferred(known []knownhosts.KnownKey) []string {
	var out []string
	seen := map[string]bool{}
	add := func(algos ...string) {
		for _, a := range algos {
			if !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	for _, k := range known {
		switch t := k.Key.Type(); t {
		case ssh.KeyAlgoRSA:
			add(ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256)
		case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
			add(t)
		}
	}
	add(defaultAlgorithms...)
	return out
}

var errGotKey = errors.New("host key received")

// fetchKey runs the key exchange with the server and returns its host key,
// aborting before authentication.
func fetchKey(ctx context.Context, addr string, algos []string, timeout time.Duration) (ssh.PublicKey, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	var key ssh.PublicKey
	_, _, _, err = ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:              "magicssh",
		HostKeyAlgorithms: algos,
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			key = k
			return errGotKey
		},
	})
	if key == nil {
		return nil, fmt.Errorf("ssh handshake with %s: %w", addr, err)
	}
	return key, nil
}

// Remove deletes the entries for name from each file with "ssh-keygen -R",
// which keeps the previous file as <file>.old. It is only called after the
// user confirmed the new key.
func Remove(ctx context.Context, name string, files []string) error {
	seen := map[string]bool{}
	for _, f := range files {
		if seen[f] {
			continue
		}
		seen[f] = true
		out, err := exec.CommandContext(ctx, "ssh-keygen", "-R", name, "-f", f).CombinedOutput()
		if err != nil {
			return fmt.Errorf("ssh-keygen -R %s -f %s: %v: %s", name, f, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// Files lists the distinct files the entries come from.
func (r Result) Files() []string {
	var out []string
	for _, e := range r.Known {
		if len(out) == 0 || out[len(out)-1] != e.File {
			out = append(out, e.File)
		}
	}
	return out
}
