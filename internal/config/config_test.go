package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"magicssh/internal/scan"
)

func load(t *testing.T) *Store {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestUsersKeyedByDevice(t *testing.T) {
	s := load(t)
	laptop := scan.Host{IP: "192.168.1.5", MAC: "AA:BB:CC:DD:EE:FF"}
	s.SetUser(laptop, "ray")

	moved := scan.Host{IP: "192.168.1.77", MAC: "aa:bb:cc:dd:ee:ff"}
	if u := s.User(moved); u != "ray" {
		t.Errorf("same MAC on a new IP: user %q, want ray", u)
	}
	// Another device that later gets the laptop's address must not inherit its user.
	other := scan.Host{IP: "192.168.1.5", MAC: "11:22:33:44:55:66"}
	if u := s.User(other); u != "" {
		t.Errorf("different device on the same IP inherited user %q", u)
	}
}

func TestCheckHostKeys(t *testing.T) {
	s := load(t)
	h := scan.Host{IP: "192.168.1.5", MAC: "aa:bb:cc:dd:ee:ff", SSH: true, HostKey: "ssh-ed25519 SHA256:one"}
	hosts := []scan.Host{h}
	s.CheckHostKeys(hosts)
	if hosts[0].KeyChanged || s.KnownHostKey(h).Key != h.HostKey {
		t.Fatal("first sighting should be remembered, not flagged")
	}

	h.HostKey = "ssh-ed25519 SHA256:two"
	hosts = []scan.Host{h}
	s.CheckHostKeys(hosts)
	if !hosts[0].KeyChanged || s.KnownHostKey(h).Key != "ssh-ed25519 SHA256:one" {
		t.Fatal("a different key must be flagged and not stored")
	}

	s.TrustHostKey(&hosts[0])
	if hosts[0].KeyChanged || s.KnownHostKey(h).Key != "ssh-ed25519 SHA256:two" {
		t.Fatal("TrustHostKey should accept the new key")
	}
}

func TestLoadDropsTamperedHosts(t *testing.T) {
	s := load(t)
	s.Hosts = []scan.Host{{IP: "-oProxyCommand=sh"}, {IP: "192.168.1.5", Banner: "SSH-2.0-x\x1b[2J"}}
	s.Users["ip:192.168.1.5"] = "ray\x1b]0;pwned\x07"
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Hosts) != 1 || s.Hosts[0].Banner != "SSH-2.0-x[2J" || s.Users["ip:192.168.1.5"] != "ray]0;pwned" {
		t.Errorf("Load = %+v users %q", s.Hosts, s.Users)
	}
	if fi, err := os.Stat(s.path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("cache file mode = %v, %v", fi.Mode(), err)
	}
}

func TestConcurrentSaves(t *testing.T) {
	s := load(t)
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Separate stores, as two magicssh processes would have.
			st := &Store{path: s.path, uid: -1, gid: -1, Users: map[string]string{"ip:10.0.0.1": fmt.Sprint(i)}}
			errs <- st.Save()
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Load(); err != nil {
		t.Fatalf("cache corrupted by concurrent saves: %v", err)
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(s.path), "*.tmp"))
	if len(left) != 0 {
		t.Errorf("temp files left behind: %v", left)
	}
}

func TestSeenKeyOldFormat(t *testing.T) {
	s := load(t)
	old := `{"host_keys": {"mac:aa:bb:cc:dd:ee:ff": "ssh-ed25519 SHA256:one"}}`
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	k := s.KnownHostKey(scan.Host{MAC: "aa:bb:cc:dd:ee:ff"})
	if k.Key != "ssh-ed25519 SHA256:one" || !k.Since.IsZero() {
		t.Errorf("old format read as %+v", k)
	}
	// New keys record when they were first seen, and survive a save.
	hosts := []scan.Host{{IP: "10.0.0.2", MAC: "11:22:33:44:55:66", HostKey: "ssh-ed25519 SHA256:two"}}
	s.CheckHostKeys(hosts)
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	s, _ = Load()
	if k := s.KnownHostKey(hosts[0]); k.Key != "ssh-ed25519 SHA256:two" || k.Since.IsZero() {
		t.Errorf("new key read back as %+v", k)
	}
}
