package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"magicssh/internal/config"
	"magicssh/internal/scan"
)

func newTestModel(t *testing.T, hosts ...scan.Host) *Model {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	store, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	sn, _ := scan.ParseSubnet("192.168.1.0/24")
	return New(scan.Options{Subnet: sn, Port: 22}, store, "me", hosts, time.Now())
}

func key(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func TestRecheckAfterRescanIsDropped(t *testing.T) {
	m := newTestModel(t, scan.Host{IP: "192.168.1.5"}, scan.Host{IP: "192.168.1.9"})
	stale := recheckMsg{scanGen: m.scanGen, host: scan.Host{IP: "192.168.1.5", SSH: true}}

	// A rescan finished while the recheck was in flight, with fewer hosts.
	m.startScan()
	m.cancel()
	m.Update(doneMsg{hosts: []scan.Host{{IP: "192.168.1.9"}}})

	m.Update(stale)
	if len(m.hosts) != 1 || m.hosts[0].IP != "192.168.1.9" || m.hosts[0].SSH {
		t.Errorf("stale recheck changed hosts: %+v", m.hosts)
	}
	if m.mode != modeList {
		t.Errorf("stale recheck opened mode %d", m.mode)
	}
}

func TestRecheckDuringScanIsDropped(t *testing.T) {
	m := newTestModel(t, scan.Host{IP: "192.168.1.5"})
	msg := recheckMsg{scanGen: m.scanGen, host: scan.Host{IP: "192.168.1.5", SSH: true}}
	m.startScan()
	defer m.cancel()
	m.Update(msg)
	if m.mode != modeScanning {
		t.Errorf("recheck during a scan switched to mode %d", m.mode)
	}
}

func TestRecheckMatchesByIPAndKeepsTarget(t *testing.T) {
	m := newTestModel(t, scan.Host{IP: "192.168.1.5"}, scan.Host{IP: "192.168.1.9"})
	// User pressed enter on .9 (SSH closed), then moved the cursor to .5.
	m.cursor = 1
	m.Update(key("enter"))
	m.cursor = 0

	m.Update(recheckMsg{scanGen: m.scanGen, host: scan.Host{IP: "192.168.1.9", SSH: true}})
	if m.hosts[0].SSH || !m.hosts[1].SSH {
		t.Fatalf("recheck updated the wrong host: %+v", m.hosts)
	}
	if m.mode != modeUser {
		t.Fatalf("mode = %d, want user prompt", m.mode)
	}
	m.Update(key("enter"))
	if m.Choice == nil || m.Choice.Host.IP != "192.168.1.9" {
		t.Errorf("connected to %+v, want 192.168.1.9", m.Choice)
	}
}

func TestRecheckDoesNotStealFilterInput(t *testing.T) {
	m := newTestModel(t, scan.Host{IP: "192.168.1.5"})
	m.Update(key("/"))
	m.Update(recheckMsg{scanGen: m.scanGen, host: scan.Host{IP: "192.168.1.5", SSH: true}})
	if m.mode != modeFilter || !m.hosts[0].SSH {
		t.Errorf("mode = %d, ssh = %v; want filter mode kept and host updated", m.mode, m.hosts[0].SSH)
	}
}

func TestChangedHostKeyNeedsConfirmation(t *testing.T) {
	h := scan.Host{IP: "192.168.1.5", MAC: "aa:bb:cc:dd:ee:ff", SSH: true, HostKey: "ssh-ed25519 SHA256:new"}
	m := newTestModel(t)
	m.store.HostKeys["mac:aa:bb:cc:dd:ee:ff"] = "ssh-ed25519 SHA256:old"
	m.startScan()
	m.cancel()
	m.Update(doneMsg{hosts: []scan.Host{h}})
	if !m.hosts[0].KeyChanged {
		t.Fatal("changed key not flagged after scan")
	}

	m.Update(key("enter"))
	if m.mode != modeList || m.warn == "" {
		t.Fatalf("first enter: mode %d warn %q, want a warning and no prompt", m.mode, m.warn)
	}
	// Any other key cancels the confirmation.
	m.Update(key("j"))
	m.Update(key("enter"))
	if m.mode != modeList {
		t.Fatal("confirmation survived another key press")
	}
	m.Update(key("enter"))
	if m.mode != modeUser {
		t.Fatalf("second enter: mode %d, want user prompt", m.mode)
	}
	m.Update(key("enter"))
	if m.Choice == nil || m.store.KnownHostKey(h) != h.HostKey {
		t.Errorf("connecting should trust the new key; known = %q", m.store.KnownHostKey(h))
	}
}

func TestFilterUsesCachedRows(t *testing.T) {
	m := newTestModel(t,
		scan.Host{IP: "192.168.1.5", Hostname: "homelab", SSH: true, Banner: "SSH-2.0-OpenSSH_9.6"},
		scan.Host{IP: "192.168.1.9", Hostname: "printer"})
	m.Update(key("/"))
	for _, r := range "home" {
		m.Update(key(string(r)))
	}
	if len(m.visible) != 1 || m.hosts[m.visible[0]].IP != "192.168.1.5" {
		t.Fatalf("visible = %v", m.visible)
	}
	v := m.View()
	if !strings.Contains(v, "homelab") || strings.Contains(v, "printer") || !strings.Contains(v, "OpenSSH_9.6") {
		t.Errorf("view:\n%s", v)
	}
	// A recheck updates the cached row, not just the host.
	m.Update(key("esc"))
	m.Update(recheckMsg{scanGen: m.scanGen, host: scan.Host{IP: "192.168.1.9", Hostname: "printer", SSH: true, Banner: "SSH-2.0-dropbear"}})
	if !strings.Contains(m.View(), "dropbear") {
		t.Error("recheck result missing from the table")
	}
}

func TestLogo(t *testing.T) {
	for _, l := range logo {
		if n := len([]rune(l)); n != len([]rune(logo[0])) || n <= logoSplit {
			t.Fatalf("logo lines must be equally wide and longer than logoSplit: %q", l)
		}
	}
	var hosts []scan.Host
	for i := 1; i <= 50; i++ {
		hosts = append(hosts, scan.Host{IP: fmt.Sprintf("192.168.1.%d", i)})
	}
	m := newTestModel(t, hosts...)
	for _, h := range []int{logoMinHeight, logoMinHeight - 1, 40} {
		m.Update(tea.WindowSizeMsg{Width: 100, Height: h})
		v := m.View()
		if got := strings.Contains(v, logo[0]); got != (h >= logoMinHeight) {
			t.Errorf("height %d: logo shown = %v", h, got)
		}
		if lines := strings.Count(v, "\n"); lines > h {
			t.Errorf("height %d: view is %d lines, taller than the terminal", h, lines)
		}
	}
}
