package tui

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"magicssh/internal/config"
	"magicssh/internal/scan"
	"magicssh/internal/sshcheck"
)

// fakeKeys answers checks from a table and records removals.
type fakeKeys struct {
	results map[string]sshcheck.Result
	removed []string
}

func (f *fakeKeys) keys() HostKeys {
	return HostKeys{
		Check: func(_ context.Context, h scan.Host) sshcheck.Result { return f.results[h.IP] },
		Remove: func(_ context.Context, name string, files []string) error {
			f.removed = append(f.removed, name+" "+strings.Join(files, ","))
			r := f.results[strings.Trim(name, "[]")]
			r.Status = sshcheck.Unknown
			f.results[strings.Trim(name, "[]")] = r
			return nil
		},
	}
}

// run executes cmd and feeds its message back, like the Bubble Tea runtime.
func run(m *Model, cmd tea.Cmd) {
	for cmd != nil {
		msg := cmd()
		if msg == nil {
			return
		}
		if _, ok := msg.(tea.BatchMsg); ok {
			return
		}
		_, cmd = m.Update(msg)
	}
}

func press(m *Model, k string) {
	_, cmd := m.Update(key(k))
	run(m, cmd)
}

func typeText(m *Model, s string) {
	for _, r := range s {
		m.Update(key(string(r)))
	}
}

var (
	macbook  = scan.Host{IP: "192.168.50.13", Hostname: "C7MPro01", MAC: "6c:96:cf:f0:4f:c8", SSH: true, HostKey: "ssh-ed25519 SHA256:new"}
	mismatch = sshcheck.Result{Status: sshcheck.Mismatch, Name: "192.168.50.13", Key: "ssh-ed25519 SHA256:new",
		Known: []sshcheck.Entry{
			{Key: "ssh-ed25519 SHA256:old", File: "/home/u/.ssh/known_hosts", Line: 3},
			{Key: "ecdsa-sha2-nistp256 SHA256:oldec", File: "/home/u/.ssh/known_hosts", Line: 4},
		}}
)

func TestBackgroundCheckMarksMismatch(t *testing.T) {
	f := &fakeKeys{results: map[string]sshcheck.Result{macbook.IP: mismatch}}
	m := newTestModelKeys(t, f.keys(), macbook, scan.Host{IP: "192.168.50.20"})
	run(m, m.Init())
	if m.hosts[0].KnownHosts != "mismatch" || m.hosts[1].KnownHosts != "" {
		t.Fatalf("known_hosts status = %q, %q", m.hosts[0].KnownHosts, m.hosts[1].KnownHosts)
	}
	if v := m.View(); !strings.Contains(v, "⚠ known_hosts") || !strings.Contains(v, "don't match your known_hosts") {
		t.Errorf("mismatch not shown in the list:\n%s", v)
	}
}

func TestMismatchScreenAndRemoval(t *testing.T) {
	f := &fakeKeys{results: map[string]sshcheck.Result{macbook.IP: mismatch}}
	m := newTestModelKeys(t, f.keys(), macbook)
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})

	press(m, "enter")
	if m.mode != modeHostKey {
		t.Fatalf("mode = %d, want the host key screen", m.mode)
	}
	v := m.View()
	for _, want := range []string{"doesn't match your known_hosts", "SHA256:old", "known_hosts:3", "SHA256:new",
		"ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub", "no earlier record"} {
		if !strings.Contains(v, want) {
			t.Errorf("screen lacks %q:\n%s", want, v)
		}
	}

	// Anything but "yes" keeps known_hosts untouched.
	typeText(m, "no")
	press(m, "enter")
	if m.mode != modeHostKey || len(f.removed) != 0 {
		t.Fatalf("\"no\" removed entries or left the screen: mode %d removed %v", m.mode, f.removed)
	}
	m.keyInput.SetValue("")
	typeText(m, "yes")
	press(m, "enter")
	if len(f.removed) != 1 || f.removed[0] != "192.168.50.13 /home/u/.ssh/known_hosts" {
		t.Fatalf("removed = %v", f.removed)
	}
	if m.mode != modeUser || m.target.IP != macbook.IP || m.hosts[0].KnownHosts != "unknown" {
		t.Errorf("after removal: mode %d target %s status %q, want the user prompt", m.mode, m.target.IP, m.hosts[0].KnownHosts)
	}
}

func TestMismatchEscLeavesKnownHosts(t *testing.T) {
	f := &fakeKeys{results: map[string]sshcheck.Result{macbook.IP: mismatch}}
	m := newTestModelKeys(t, f.keys(), macbook)
	press(m, "enter")
	press(m, "esc")
	if m.mode != modeList || len(f.removed) != 0 || m.Choice != nil {
		t.Errorf("esc: mode %d removed %v choice %v", m.mode, f.removed, m.Choice)
	}
}

func TestRevokedCannotBeRemoved(t *testing.T) {
	rev := sshcheck.Result{Status: sshcheck.Revoked, Name: macbook.IP, Key: "ssh-ed25519 SHA256:new",
		Known: []sshcheck.Entry{{Key: "ssh-ed25519 SHA256:new", File: "/etc/ssh/ssh_known_hosts", Line: 1}}}
	f := &fakeKeys{results: map[string]sshcheck.Result{macbook.IP: rev}}
	m := newTestModelKeys(t, f.keys(), macbook)
	press(m, "enter")
	typeText(m, "yes")
	press(m, "enter")
	if m.mode != modeHostKey || len(f.removed) != 0 || !strings.Contains(m.View(), "revoked") {
		t.Errorf("revoked key: mode %d removed %v", m.mode, f.removed)
	}
}

func TestMatchingKeyGoesStraightToPrompt(t *testing.T) {
	f := &fakeKeys{results: map[string]sshcheck.Result{macbook.IP: {Status: sshcheck.OK, Key: macbook.HostKey}}}
	m := newTestModelKeys(t, f.keys(), macbook)
	press(m, "enter")
	if m.mode != modeUser {
		t.Errorf("mode = %d, want the user prompt", m.mode)
	}
}

func TestStalePreconnectIsDropped(t *testing.T) {
	f := &fakeKeys{results: map[string]sshcheck.Result{macbook.IP: mismatch}}
	m := newTestModelKeys(t, f.keys(), macbook)
	_, cmd := m.Update(key("enter"))
	msg := cmd()
	m.scanGen++ // a rescan happened meanwhile
	m.Update(msg)
	if m.mode != modeList {
		t.Errorf("stale check opened mode %d", m.mode)
	}
}

func TestExplain(t *testing.T) {
	started := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	earlier := started.Add(-48 * time.Hour)
	res := mismatch
	cases := []struct {
		name     string
		h        scan.Host
		seenKey  string
		seenAt   time.Time
		wantText string
	}{
		{"stale entry", macbook, macbook.HostKey, earlier, "since Sep 25 2026"},
		{"first seen this session", macbook, macbook.HostKey, started.Add(time.Minute), "no earlier record"},
		{"old cache format", macbook, macbook.HostKey, time.Time{}, "no earlier record"},
		{"device changed keys", func() scan.Host { h := macbook; h.KeyChanged = true; return h }(), "ssh-ed25519 SHA256:older", earlier, "Its keys changed"},
		{"changed since scan", func() scan.Host { h := macbook; h.HostKey = "ssh-ed25519 SHA256:scan"; return h }(), "", time.Time{}, "since the scan"},
	}
	for _, c := range cases {
		got := strings.Join(explain(c.h, res, c.seenKey, c.seenAt, started), " ")
		if !strings.Contains(got, c.wantText) {
			t.Errorf("%s: %q lacks %q", c.name, got, c.wantText)
		}
	}
}

func TestFingerprintCommand(t *testing.T) {
	win := scan.Host{}
	win.OS.OS = "Windows"
	if got := fingerprintCommand(win, "ecdsa-sha2-nistp256 SHA256:x"); got != `ssh-keygen -lf C:\ProgramData\ssh\ssh_host_ecdsa_key.pub` {
		t.Errorf("windows: %s", got)
	}
	if got := fingerprintCommand(scan.Host{}, "rsa-sha2-512 SHA256:x"); got != "ssh-keygen -lf /etc/ssh/ssh_host_rsa_key.pub" {
		t.Errorf("rsa: %s", got)
	}
}

// Review fix 1: the warning shows the remembered fingerprint, not a struct.
func TestKeyChangedWarningShowsFingerprint(t *testing.T) {
	h := macbook
	h.KeyChanged = true
	m := newTestModel(t, h)
	m.store.HostKeys["mac:"+h.MAC] = config.SeenKey{Key: "ssh-ed25519 SHA256:old", Since: time.Now()}
	press(m, "enter")
	if !strings.Contains(m.warn, "was ssh-ed25519 SHA256:old, now ssh-ed25519 SHA256:new") || strings.Contains(m.warn, "{") {
		t.Errorf("warning = %q", m.warn)
	}
}

// Review fix 2: a status from the cache doesn't survive a failed or skipped check.
func TestStaleStatusCleared(t *testing.T) {
	cached := macbook
	cached.KnownHosts = "mismatch"

	failing := HostKeys{Check: func(context.Context, scan.Host) sshcheck.Result {
		return sshcheck.Result{Err: errors.New("host offline")}
	}}
	m := newTestModelKeys(t, failing, cached)
	run(m, m.Init())
	if m.hosts[0].KnownHosts != "" || strings.Contains(m.View(), "⚠ known_hosts") {
		t.Errorf("failed check kept status %q", m.hosts[0].KnownHosts)
	}

	m = newTestModelKeys(t, HostKeys{}, cached) // no check possible (e.g. under sudo)
	run(m, m.Init())
	if m.hosts[0].KnownHosts != "" {
		t.Errorf("no check kept status %q", m.hosts[0].KnownHosts)
	}

	// The check on enter clears it too when it fails.
	m = newTestModelKeys(t, failing, cached)
	press(m, "enter")
	if m.hosts[0].KnownHosts != "" || m.mode != modeUser {
		t.Errorf("failed pre-connect check: status %q mode %d", m.hosts[0].KnownHosts, m.mode)
	}
}

// Review fix 3: after "yes", magicssh only records the key the user compared.
func TestRemovalTrustsOnlyVerifiedKey(t *testing.T) {
	changed := macbook
	changed.KeyChanged = true
	for _, c := range []struct {
		name      string
		shown     string // key on the host key screen
		wantKnown string // what magicssh remembers afterwards
		wantMode  mode
	}{
		{"same key as the scan", changed.HostKey, changed.HostKey, modeUser},
		// ssh preferred the known ECDSA type: the ed25519 key magicssh tracks
		// wasn't shown, so it is confirmed via the "key changed" warning.
		{"other key type", "ecdsa-sha2-nistp256 SHA256:ec", "ssh-ed25519 SHA256:old", modeList},
	} {
		t.Run(c.name, func(t *testing.T) {
			res := mismatch
			res.Key = c.shown
			f := &fakeKeys{results: map[string]sshcheck.Result{changed.IP: res}}
			m := newTestModelKeys(t, f.keys(), changed)
			m.store.HostKeys["mac:"+changed.MAC] = config.SeenKey{Key: "ssh-ed25519 SHA256:old"}
			press(m, "enter")
			typeText(m, "yes")
			press(m, "enter")
			if len(f.removed) != 1 {
				t.Fatalf("removed = %v", f.removed)
			}
			if got := m.store.KnownHostKey(changed).Key; got != c.wantKnown {
				t.Errorf("remembered %q, want %q", got, c.wantKnown)
			}
			if m.mode != c.wantMode {
				t.Errorf("mode = %d, want %d (warn %q)", m.mode, c.wantMode, m.warn)
			}
			if c.wantMode == modeList && !strings.Contains(m.warn, "different SSH host key") {
				t.Errorf("expected the key changed warning, got %q", m.warn)
			}
		})
	}
}

// Review fix 4: leaving the screen while ssh-keygen runs doesn't lose the result.
func TestEscDuringRemoval(t *testing.T) {
	for _, fail := range []bool{false, true} {
		f := &fakeKeys{results: map[string]sshcheck.Result{macbook.IP: mismatch}}
		keys := f.keys()
		if fail {
			keys.Remove = func(context.Context, string, []string) error { return errors.New("permission denied") }
		}
		m := newTestModelKeys(t, keys, macbook)
		press(m, "enter")
		typeText(m, "yes")
		_, cmd := m.Update(key("enter")) // start the removal but don't deliver it yet
		press(m, "esc")
		m.Update(cmd())

		if m.mode != modeList || m.Choice != nil {
			t.Errorf("fail=%v: mode %d choice %v; the user left, so no prompt", fail, m.mode, m.Choice)
		}
		if fail {
			if !strings.Contains(m.warn, "permission denied") {
				t.Errorf("error not shown: warn %q", m.warn)
			}
		} else if m.hosts[0].KnownHosts != "unknown" || !strings.Contains(m.status, "removed the old") {
			t.Errorf("result lost: status %q known_hosts %q", m.status, m.hosts[0].KnownHosts)
		}
	}
}
