package tui

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"magicssh/internal/osdetect"
	"magicssh/internal/scan"
	"magicssh/internal/sshcheck"
)

// HostKeys checks hosts against known_hosts the way ssh will, so a mismatch
// is explained here instead of ending in ssh's error. Check is nil when ssh
// isn't available; then the picker skips the checks and ssh decides alone.
type HostKeys struct {
	Check  func(ctx context.Context, h scan.Host) sshcheck.Result
	Remove func(ctx context.Context, name string, files []string) error
}

type (
	// knownHostsMsg carries the background check of every SSH host after a scan.
	knownHostsMsg struct {
		scanGen int
		results map[string]sshcheck.Result // by IP
	}
	// preconnectMsg is the check run when the user presses enter on a host.
	preconnectMsg struct {
		scanGen int
		ip      string
		res     sshcheck.Result
	}
	// removedMsg reports the removal of stale entries for the host at ip,
	// whose check result the user confirmed.
	removedMsg struct {
		ip  string
		res sshcheck.Result
		err error
	}
)

const checkWorkers = 8

// checkAll checks every host with SSH open, in the background.
func (m *Model) checkAll() tea.Cmd {
	if m.keys.Check == nil {
		// Without a check, a status loaded from the cache could be stale.
		for i := range m.hosts {
			m.hosts[i].KnownHosts = ""
		}
		m.hostsChanged()
		return nil
	}
	var hosts []scan.Host
	for _, h := range m.hosts {
		if h.SSH {
			hosts = append(hosts, h)
		}
	}
	if len(hosts) == 0 {
		return nil
	}
	gen, check := m.scanGen, m.keys.Check
	return func() tea.Msg {
		results := make(map[string]sshcheck.Result, len(hosts))
		var mu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, checkWorkers)
		for _, h := range hosts {
			wg.Add(1)
			sem <- struct{}{}
			go func(h scan.Host) {
				defer func() { <-sem; wg.Done() }()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				r := check(ctx, h)
				mu.Lock()
				results[h.IP] = r
				mu.Unlock()
			}(h)
		}
		wg.Wait()
		return knownHostsMsg{scanGen: gen, results: results}
	}
}

func (m *Model) applyKnownHosts(msg knownHostsMsg) {
	if msg.scanGen != m.scanGen || m.mode == modeScanning {
		return
	}
	bad := 0
	for i := range m.hosts {
		// A failed or skipped check must not leave an older status behind.
		m.hosts[i].KnownHosts = ""
		r, ok := msg.results[m.hosts[i].IP]
		if !ok || r.Err != nil {
			continue
		}
		m.hosts[i].KnownHosts = string(r.Status)
		if r.Status == sshcheck.Mismatch || r.Status == sshcheck.Revoked {
			bad++
		}
	}
	m.hostsChanged()
	if bad > 0 && m.warn == "" {
		m.warn = fmt.Sprintf("⚠ %d device(s) don't match your known_hosts — select one and press enter for details", bad)
	}
}

// checkThenConnect runs the host key check before opening the username
// prompt, so a mismatch shows the host key screen instead of failing in ssh.
func (m *Model) checkThenConnect(h scan.Host) tea.Cmd {
	if m.keys.Check == nil {
		return m.connectTo(h)
	}
	m.status = fmt.Sprintf("checking the host key of %s…", h.IP)
	gen, check := m.scanGen, m.keys.Check
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return preconnectMsg{scanGen: gen, ip: h.IP, res: check(ctx, h)}
	}
}

func (m *Model) handlePreconnect(msg preconnectMsg) tea.Cmd {
	if msg.scanGen != m.scanGen || m.mode == modeScanning {
		return nil
	}
	idx := m.indexOf(msg.ip)
	if idx < 0 {
		return nil
	}
	m.status = ""
	m.hosts[idx].KnownHosts = ""
	if msg.res.Err == nil {
		m.hosts[idx].KnownHosts = string(msg.res.Status)
	}
	m.hostsChanged()
	if m.mode != modeList {
		return nil // the user moved on to a filter or username prompt
	}
	h := m.hosts[idx]
	switch msg.res.Status {
	case sshcheck.Mismatch, sshcheck.Revoked:
		m.target, m.keyRes = h, msg.res
		m.mode = modeHostKey
		m.keyInput.SetValue("")
		if msg.res.Status == sshcheck.Mismatch {
			return m.keyInput.Focus()
		}
		return nil
	}
	// Match, new host, or the check failed: ssh does its own check anyway.
	return m.connectTo(h)
}

func (m *Model) updateHostKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.keyInput.Blur()
		m.mode = modeList
		return m, nil
	case "enter":
		if m.keyRes.Status != sshcheck.Mismatch || m.removing {
			return m, nil
		}
		if strings.ToLower(strings.TrimSpace(m.keyInput.Value())) != "yes" {
			m.warn = `type "yes" to remove the old entries, or press esc`
			return m, nil
		}
		m.keyInput.Blur()
		m.removing = true
		ip, res, remove := m.target.IP, m.keyRes, m.keys.Remove
		return m, func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return removedMsg{ip: ip, res: res, err: remove(ctx, res.Name, res.Files())}
		}
	}
	var cmd tea.Cmd
	m.keyInput, cmd = m.keyInput.Update(msg)
	return m, cmd
}

// handleRemoved records the outcome of removing stale entries. It runs even
// if the user left the host key screen meanwhile: the entries are gone either
// way, and an error must still be shown.
func (m *Model) handleRemoved(msg removedMsg) tea.Cmd {
	m.removing = false
	onScreen := m.mode == modeHostKey && m.target.IP == msg.ip
	if onScreen {
		m.mode = modeList
	}
	if msg.err != nil {
		m.warn = "⚠ could not remove the old entries: " + msg.err.Error()
		return nil
	}
	m.status = fmt.Sprintf("removed the old %s entries from %s (previous file kept as .old) — ssh will ask you to accept the new key",
		msg.res.Name, strings.Join(msg.res.Files(), ", "))
	idx := m.indexOf(msg.ip)
	if idx < 0 {
		return nil
	}
	h := &m.hosts[idx]
	h.KnownHosts = string(sshcheck.Unknown)
	// Update magicssh's own record only with the key the user just compared.
	// If the check showed another key than the scan recorded (another key type,
	// or it changed since), the "key changed" warning below shows the one
	// magicssh tracks, so that one is confirmed separately.
	if h.KeyChanged && msg.res.Key == h.HostKey {
		m.store.TrustHostKey(h)
	}
	m.saveCache()
	m.hostsChanged()
	if !onScreen {
		return nil
	}
	return m.connectTo(*h)
}

// viewHostKey explains a known_hosts mismatch and what can be done about it.
func (m *Model) viewHostKey() string {
	h, r := m.target, m.keyRes
	var b strings.Builder
	name := h.IP
	if h.Hostname != "" {
		name += " (" + h.Hostname + ")"
	}
	if r.Status == sshcheck.Revoked {
		b.WriteString("  " + errSt.Render("✖ The host key of "+name+" is marked @revoked in your known_hosts.") + "\n\n")
		b.WriteString(fmt.Sprintf("  key:     %s\n  revoked: %s:%d\n\n", r.Key, r.Known[0].File, r.Known[0].Line))
		b.WriteString(dim.Render("  ssh will refuse this key. magicssh won't remove a revocation; edit the file yourself if it is wrong.") + "\n\n")
		b.WriteString(help("esc", "back"))
		return b.String()
	}

	b.WriteString("  " + warnSt.Render("⚠ The host key of "+name+" doesn't match your known_hosts.") + "\n")
	b.WriteString(dim.Render("  ssh would refuse to connect (\"REMOTE HOST IDENTIFICATION HAS CHANGED\").") + "\n\n")
	for _, e := range r.Known {
		b.WriteString(fmt.Sprintf("  saved: %s  %s\n", e.Key, dim.Render(fmt.Sprintf("%s:%d", e.File, e.Line))))
	}
	b.WriteString(fmt.Sprintf("  now:   %s\n\n", keySt.Render(r.Key)))

	for _, line := range explain(h, r, m.store.KnownHostKey(h).Key, m.store.KnownHostKey(h).Since, m.started) {
		b.WriteString(lipglossWrap(line, m.width-4) + "\n")
	}
	b.WriteString("\n" + lipglossWrap("To be sure, compare the \"now\" fingerprint with the one the device prints for:", m.width-4) + "\n")
	b.WriteString("    " + keySt.Render(fingerprintCommand(h, r.Key)) + "\n\n")
	b.WriteString(lipglossWrap(fmt.Sprintf("If it matches, type yes to remove the old entries for %s (ssh-keygen -R, previous file kept as .old). ssh then asks you to accept the new key.", r.Name), m.width-4) + "\n")
	if r.Strict {
		b.WriteString(warnSt.Render(lipglossWrap("Note: StrictHostKeyChecking is yes in your ssh config, so ssh will refuse the new key until you add it yourself.", m.width-4)) + "\n")
	}
	b.WriteString("\n  " + m.keyInput.View() + "\n")
	b.WriteString(help("enter", "remove & connect", "esc", "back"))
	return b.String()
}

// explain says what most likely happened, from what magicssh remembers about
// the device (its key and since when) and the key presented now.
func explain(h scan.Host, r sshcheck.Result, seenKey string, seenSince, started time.Time) []string {
	sameType := func(a, b string) bool {
		ta, _, _ := strings.Cut(a, " ")
		tb, _, _ := strings.Cut(b, " ")
		return ta == tb
	}
	device := "This device"
	if h.MAC != "" {
		device = "This device (MAC " + h.MAC + ")"
	}
	var out []string
	switch {
	case h.HostKey != "" && sameType(h.HostKey, r.Key) && h.HostKey != r.Key:
		out = append(out, "✖ The key also changed since the scan a moment ago. That is unusual: be careful.")
	case h.KeyChanged:
		out = append(out, fmt.Sprintf("%s presented a different key to magicssh before (%s). Its keys changed: usually a reinstall, but it could also be another machine pretending to be it.", device, seenKey))
	case seenKey != "" && seenKey == h.HostKey && !seenSince.IsZero() && seenSince.Before(started):
		out = append(out, fmt.Sprintf("%s has presented this same key to magicssh since %s, so your known_hosts entry is probably stale: the address belonged to another device before, or this one was reinstalled earlier.",
			device, seenSince.Format("Jan 2 2006 15:04")))
	default:
		out = append(out, "magicssh has no earlier record of this device's key, so it can't tell a reinstall or an address reused by another device from an attack.")
	}
	return out
}

// fingerprintCommand is what to run on the device to print its key's fingerprint.
func fingerprintCommand(h scan.Host, key string) string {
	typ, _, _ := strings.Cut(key, " ")
	file := "ed25519"
	switch {
	case strings.HasPrefix(typ, "ecdsa"):
		file = "ecdsa"
	case strings.Contains(typ, "rsa"):
		file = "rsa"
	}
	if h.OS.OS == osdetect.Windows {
		return `ssh-keygen -lf C:\ProgramData\ssh\ssh_host_` + file + `_key.pub`
	}
	return "ssh-keygen -lf /etc/ssh/ssh_host_" + file + "_key.pub"
}
