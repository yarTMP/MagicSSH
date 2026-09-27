// Package tui implements the interactive host picker.
package tui

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"magicssh/internal/config"
	"magicssh/internal/osdetect"
	"magicssh/internal/scan"
)

// Selection is what the user picked; nil Host means they quit.
type Selection struct {
	Host scan.Host
	User string
}

type mode int

const (
	modeScanning mode = iota
	modeList
	modeFilter
	modeUser
)

type (
	progressMsg scan.Progress
	recheckMsg  struct {
		scanGen int // scan the host came from; stale results are dropped
		host    scan.Host
	}
	doneMsg struct {
		hosts []scan.Host
		err   error
	}
)

type Model struct {
	opts        scan.Options
	store       *config.Store
	defaultUser string

	mode     mode
	hosts    []scan.Host
	rows     []row // derived from hosts by hostsChanged
	widths   []int // column widths for all hosts, capped per column
	visible  []int // indices into hosts after filtering
	cursor   int
	offset   int
	progress scan.Progress
	events   chan tea.Msg
	cancel   context.CancelFunc
	scanGen  int // bumped on every scan so late recheck results can be recognised
	scanned  time.Time
	status   string
	warn     string // shown prominently until the next key press
	err      error

	spin      spinner.Model
	filter    textinput.Model
	userInput textinput.Model
	connect   bool      // user prompt was opened by Enter (connect) rather than 'u'
	target    scan.Host // host the user prompt applies to
	confirmIP string    // host whose changed key was shown; enter again connects
	sshOnly   bool      // hide devices without the SSH port open

	width, height int

	Choice *Selection
}

// New creates the picker. If cached is non-empty the list is shown immediately
// instead of starting a scan.
func New(opts scan.Options, store *config.Store, defaultUser string, cached []scan.Host, scannedAt time.Time) *Model {
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(accent)

	fi := textinput.New()
	fi.Prompt = "/ "
	fi.Placeholder = "filter by IP, name, OS, vendor…"

	ui := textinput.New()
	ui.Prompt = "user: "
	ui.CharLimit = 64

	// The scan always keeps every device; SSH-only is a view toggle ('s').
	m := &Model{opts: opts, store: store, defaultUser: defaultUser, sshOnly: opts.SSHOnly,
		spin: sp, filter: fi, userInput: ui, width: 100, height: 24}
	m.opts.SSHOnly = false
	if len(cached) > 0 {
		m.hosts, m.scanned, m.mode = cached, scannedAt, modeList
		m.status = "cached results from " + scannedAt.Format("Jan 2 15:04") + " — press r to rescan"
		m.hostsChanged()
	}
	return m
}

func (m *Model) Init() tea.Cmd {
	if m.mode == modeScanning {
		return tea.Batch(m.spin.Tick, m.startScan())
	}
	return nil
}

func (m *Model) startScan() tea.Cmd {
	m.mode = modeScanning
	m.scanGen++
	m.progress = scan.Progress{Total: scan.HostCount(m.opts.Subnet), Phase: "scanning"}
	m.err = nil
	events := make(chan tea.Msg, 64)
	ctx, cancel := context.WithCancel(context.Background())
	m.events, m.cancel = events, cancel
	go func() {
		deliver := scan.Throttle(50 * time.Millisecond)
		hosts, err := scan.Run(ctx, m.opts, func(p scan.Progress) {
			if !deliver(p) {
				return
			}
			select {
			case events <- progressMsg(p):
			default:
			}
		})
		events <- doneMsg{hosts, err}
	}()
	return m.waitEvent()
}

func (m *Model) waitEvent() tea.Cmd {
	ch := m.events
	return func() tea.Msg { return <-ch }
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.clampScroll()
		return m, nil

	case spinner.TickMsg:
		if m.mode != modeScanning {
			return m, nil
		}
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd

	case progressMsg:
		m.progress = scan.Progress(msg)
		return m, m.waitEvent()

	case doneMsg:
		m.cancel()
		m.mode = modeList
		if msg.err != nil {
			m.err = msg.err
			return m, nil
		}
		m.hosts, m.scanned = msg.hosts, time.Now()
		m.store.CheckHostKeys(m.hosts)
		m.status = fmt.Sprintf("found %d device(s), %d with SSH, on %s", len(m.hosts), countSSH(m.hosts), m.opts.Subnet)
		if n := countKeyChanged(m.hosts); n > 0 {
			m.warn = fmt.Sprintf("⚠ %d device(s) present a different SSH host key than before — marked ⚠ in the list", n)
		}
		m.saveCache()
		m.hostsChanged()
		return m, nil

	case recheckMsg:
		// A rescan started since the recheck began: its results replace this one.
		if msg.scanGen != m.scanGen || m.mode == modeScanning {
			return m, nil
		}
		h := msg.host
		idx := m.indexOf(h.IP)
		if idx < 0 {
			return m, nil
		}
		hs := []scan.Host{h}
		m.store.CheckHostKeys(hs)
		h = hs[0]
		m.hosts[idx] = h
		m.saveCache()
		m.hostsChanged()
		if !h.SSH {
			m.status = ""
			target := h.IP
			if h.Hostname != "" {
				target += " (" + h.Hostname + ")"
			}
			m.warn = fmt.Sprintf("⚠ Can't connect: %s has no SSH server on port %d. Enable SSH on it and press enter again.",
				target, m.opts.Port)
			return m, nil
		}
		m.status = fmt.Sprintf("SSH is now open on %s", h.IP)
		if m.mode != modeList {
			// The user is typing a filter or a username; don't steal the input.
			return m, nil
		}
		return m, m.connectTo(h)

	case tea.KeyMsg:
		m.warn = ""
		if msg.String() != "enter" {
			m.confirmIP = ""
		}
		if msg.String() == "ctrl+c" {
			if m.cancel != nil {
				m.cancel()
			}
			return m, tea.Quit
		}
		switch m.mode {
		case modeScanning:
			if msg.String() == "q" || msg.String() == "esc" {
				m.cancel()
				return m, tea.Quit
			}
		case modeFilter:
			return m.updateFilter(msg)
		case modeUser:
			return m.updateUser(msg)
		case modeList:
			return m.updateList(msg)
		}
	}
	return m, nil
}

func (m *Model) updateList(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q":
		return m, tea.Quit
	case "esc":
		if m.filter.Value() != "" {
			m.filter.SetValue("")
			m.applyFilter()
			return m, nil
		}
		return m, tea.Quit
	case "up", "k":
		m.move(-1)
	case "down", "j":
		m.move(1)
	case "pgup", "ctrl+u":
		m.move(-m.pageSize())
	case "pgdown", "ctrl+d":
		m.move(m.pageSize())
	case "home", "g":
		m.move(-len(m.visible))
	case "end", "G":
		m.move(len(m.visible))
	case "/":
		m.mode = modeFilter
		return m, m.filter.Focus()
	case "r":
		return m, tea.Batch(m.spin.Tick, m.startScan())
	case "s":
		m.sshOnly = !m.sshOnly
		m.applyFilter()
	case "u":
		if h, ok := m.selected(); ok {
			return m, m.promptUser(h, false)
		}
	case "enter":
		h, ok := m.selected()
		if !ok {
			return m, nil
		}
		if h.SSH {
			return m, m.connectTo(h)
		}
		// SSH was closed at scan time; check again in case it was enabled since.
		m.status = fmt.Sprintf("checking SSH on %s…", h.IP)
		gen, port := m.scanGen, m.opts.Port
		return m, func() tea.Msg {
			scan.Recheck(context.Background(), &h, port, 2*time.Second)
			return recheckMsg{scanGen: gen, host: h}
		}
	}
	return m, nil
}

// connectTo opens the username prompt for connecting to h, unless h's host key
// changed: then it first warns, and a second enter on the same host proceeds.
func (m *Model) connectTo(h scan.Host) tea.Cmd {
	if h.KeyChanged && m.confirmIP != h.IP {
		m.confirmIP = h.IP
		m.warn = fmt.Sprintf("⚠ %s presents a different SSH host key (was %s, now %s). It may be another machine. Press enter again to connect anyway.",
			h.IP, m.store.KnownHostKey(h), h.HostKey)
		return nil
	}
	m.confirmIP = ""
	return m.promptUser(h, true)
}

// promptUser opens the username prompt; connect decides whether Enter then
// starts ssh or only saves the name.
func (m *Model) promptUser(h scan.Host, connect bool) tea.Cmd {
	m.connect, m.target = connect, h
	u := m.store.User(h)
	if u == "" {
		u = m.defaultUser
	}
	m.userInput.SetValue(u)
	m.userInput.CursorEnd()
	m.mode = modeUser
	return m.userInput.Focus()
}

func (m *Model) saveCache() {
	m.store.Subnet, m.store.ScanTime, m.store.Hosts = m.opts.Subnet.String(), m.scanned, m.hosts
	if err := m.store.Save(); err != nil {
		m.status += " (cache not saved: " + err.Error() + ")"
	}
}

func (m *Model) updateFilter(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.filter.SetValue("")
		fallthrough
	case "enter":
		m.filter.Blur()
		m.mode = modeList
		m.applyFilter()
		return m, nil
	case "up", "down":
		m.move(map[string]int{"up": -1, "down": 1}[msg.String()])
		return m, nil
	}
	var cmd tea.Cmd
	m.filter, cmd = m.filter.Update(msg)
	m.applyFilter()
	return m, cmd
}

func (m *Model) updateUser(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.userInput.Blur()
		m.mode = modeList
		return m, nil
	case "enter":
		user := strings.TrimSpace(m.userInput.Value())
		if user == "" {
			return m, nil
		}
		h := m.target
		m.store.SetUser(h, user)
		if m.connect && h.KeyChanged {
			// The user confirmed the new key; ssh still checks known_hosts.
			m.store.TrustHostKey(&h)
			if i := m.indexOf(h.IP); i >= 0 {
				m.hosts[i] = h
				m.hostsChanged()
			}
			m.store.Hosts = m.hosts
		}
		if err := m.store.Save(); err != nil {
			m.status = "could not save username: " + err.Error()
		}
		m.userInput.Blur()
		m.mode = modeList
		if m.connect {
			m.Choice = &Selection{Host: h, User: user}
			return m, tea.Quit
		}
		m.status = fmt.Sprintf("username for %s set to %q", h.IP, user)
		return m, nil
	}
	var cmd tea.Cmd
	m.userInput, cmd = m.userInput.Update(msg)
	return m, cmd
}

func (m *Model) selected() (scan.Host, bool) {
	if m.cursor < 0 || m.cursor >= len(m.visible) {
		return scan.Host{}, false
	}
	return m.hosts[m.visible[m.cursor]], true
}

// indexOf returns the position of the host with the given IP in m.hosts, or -1.
func (m *Model) indexOf(ip string) int {
	for i, h := range m.hosts {
		if h.IP == ip {
			return i
		}
	}
	return -1
}

// row is what the view derives from one host, computed once per host change
// instead of on every key press and render.
type row struct {
	search string   // lower-cased text the filter matches against
	cells  []string // unpadded table cell values, one per column
}

// hostsChanged rebuilds rows and column widths from m.hosts and reapplies the
// filter. Call it whenever m.hosts changes. Widths cover all hosts, not just
// the filtered ones, so columns stay put while typing a filter.
func (m *Model) hostsChanged() {
	m.rows = make([]row, len(m.hosts))
	m.widths = make([]int, len(columns))
	for j, c := range columns {
		m.widths[j] = len([]rune(c.title))
	}
	for i, h := range m.hosts {
		cells := make([]string, len(columns))
		for j, c := range columns {
			cells[j] = strconv.Itoa(i + 1)
			if c.val != nil {
				cells[j] = c.val(h)
			}
			m.widths[j] = max(m.widths[j], len([]rune(cells[j])))
		}
		m.rows[i] = row{search: searchText(h), cells: cells}
	}
	for j, c := range columns {
		m.widths[j] = min(m.widths[j], c.max)
	}
	m.applyFilter()
}

func (m *Model) applyFilter() {
	q := strings.ToLower(strings.TrimSpace(m.filter.Value()))
	m.visible = m.visible[:0]
	for i, h := range m.hosts {
		if m.sshOnly && !h.SSH {
			continue
		}
		if q == "" || strings.Contains(m.rows[i].search, q) {
			m.visible = append(m.visible, i)
		}
	}
	m.clampScroll()
}

func countKeyChanged(hosts []scan.Host) int {
	n := 0
	for _, h := range hosts {
		if h.KeyChanged {
			n++
		}
	}
	return n
}

func countSSH(hosts []scan.Host) int {
	n := 0
	for _, h := range hosts {
		if h.SSH {
			n++
		}
	}
	return n
}

func searchText(h scan.Host) string {
	return strings.ToLower(strings.Join([]string{h.IP, h.Hostname, h.OS.Label(), h.Vendor, h.MAC, h.Banner}, " "))
}

func (m *Model) move(d int) {
	m.cursor += d
	m.clampScroll()
}

func (m *Model) pageSize() int {
	// header + table header(1) + details(4) + help(2), plus a spare line
	n := m.height - m.headerLines() - 8
	if n < 3 {
		n = 3
	}
	return n
}

func (m *Model) clampScroll() {
	if m.cursor >= len(m.visible) {
		m.cursor = len(m.visible) - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
	ps := m.pageSize()
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+ps {
		m.offset = m.cursor - ps + 1
	}
	if m.offset < 0 {
		m.offset = 0
	}
}

// ---- view ----

var (
	accent    = lipgloss.Color("39")
	dim       = lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	titleSt   = lipgloss.NewStyle().Bold(true).Foreground(accent)
	headerSt  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("252")).Underline(true)
	cursorSt  = lipgloss.NewStyle().Background(lipgloss.Color("237")).Bold(true)
	errSt     = lipgloss.NewStyle().Foreground(lipgloss.Color("203")).Bold(true)
	warnSt    = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
	keySt     = lipgloss.NewStyle().Foreground(accent).Bold(true)
	sshSt     = lipgloss.NewStyle().Foreground(lipgloss.Color("78"))
	logoSSHSt = sshSt.Bold(true)
	osColors  = map[osdetect.OS]lipgloss.Color{
		osdetect.Windows: lipgloss.Color("33"),
		osdetect.Linux:   lipgloss.Color("220"),
		osdetect.MacOS:   lipgloss.Color("250"),
		osdetect.BSD:     lipgloss.Color("203"),
		osdetect.IOS:     lipgloss.Color("147"),
		osdetect.Android: lipgloss.Color("71"),
		osdetect.Unknown: lipgloss.Color("243"),
	}
)

func osStyle(o osdetect.OS) lipgloss.Style {
	return lipgloss.NewStyle().Foreground(osColors[o])
}

func (m *Model) View() string {
	var b strings.Builder
	b.WriteString(m.header())

	if m.mode == modeScanning {
		p := m.progress
		bar := progressBar(p.Done, p.Total, min(40, max(10, m.width-40)))
		phase := fmt.Sprintf("Scanning %d/%d", p.Done, p.Total)
		if p.Phase == "identifying" {
			phase = "Identifying devices (hostname, MAC, OS)…"
		}
		fmt.Fprintf(&b, "%s %s  %s  %s\n\n", m.spin.View(), phase, bar,
			keySt.Render(fmt.Sprintf("%d devices · %d with SSH", p.Found, p.SSH)))
		b.WriteString(help("q", "cancel"))
		return b.String()
	}

	if m.err != nil {
		b.WriteString(errSt.Render("scan failed: "+m.err.Error()) + "\n\n")
		b.WriteString(help("r", "rescan", "q", "quit"))
		return b.String()
	}

	if len(m.hosts) == 0 {
		b.WriteString("No devices found on " + m.opts.Subnet.String() + ".\n\n")
		b.WriteString(help("r", "rescan", "q", "quit"))
		return b.String()
	}

	b.WriteString(m.table())
	b.WriteString("\n")
	b.WriteString(m.details())
	b.WriteString("\n")

	switch m.mode {
	case modeFilter:
		b.WriteString(m.filter.View() + "\n")
		b.WriteString(help("enter", "apply", "esc", "clear"))
	case modeUser:
		h := m.target
		action := "save"
		if m.connect {
			action = "connect"
		}
		b.WriteString(fmt.Sprintf("SSH to %s — %s\n", keySt.Render(h.IP), m.userInput.View()))
		b.WriteString(help("enter", action, "esc", "back"))
	default:
		if f := m.filter.Value(); f != "" {
			b.WriteString(dim.Render(fmt.Sprintf("filter: %q (%d/%d) · ", f, len(m.visible), len(m.hosts))))
		}
		if m.warn != "" {
			b.WriteString(warnSt.Render(truncate(m.warn, m.width-1)) + "\n")
		} else {
			b.WriteString(dim.Render(m.status) + "\n")
		}
		toggle := "ssh only"
		if m.sshOnly {
			toggle = "show all"
		}
		b.WriteString(help("↑/↓", "move", "enter", "connect", "/", "filter", "s", toggle, "u", "user", "r", "rescan", "q", "quit"))
	}
	return b.String()
}

// logo spells "magicssh"; the first logoSplit runes of each line are "magic".
var logo = [...]string{
	"┌┬┐┌─┐┌─┐┬┌─┐┌─┐┌─┐┬ ┬",
	"│││├─┤│ ┬││  └─┐└─┐├─┤",
	"┴ ┴┴ ┴└─┘┴└─┘└─┘└─┘┴ ┴",
}

const (
	logoSplit     = 13
	logoMinHeight = 20 // below this the logo would cost too many list rows
)

func (m *Model) showLogo() bool { return m.height >= logoMinHeight }

// headerLines is how many lines header() takes, including the blank line after it.
func (m *Model) headerLines() int {
	if m.showLogo() {
		return len(logo) + 2
	}
	return 2
}

// header renders the logo with the subnet and port under it, or a one-line
// title when the terminal is short.
func (m *Model) header() string {
	info := m.opts.Subnet.String() + " · port " + strconv.Itoa(m.opts.Port)
	if !m.showLogo() {
		return titleSt.Render("magicssh") + dim.Render(" · "+info) + "\n\n"
	}
	var b strings.Builder
	for _, line := range logo {
		r := []rune(line)
		b.WriteString("  " + titleSt.Render(string(r[:logoSplit])) + logoSSHSt.Render(string(r[logoSplit:])) + "\n")
	}
	b.WriteString("  " + dim.Render(info) + "\n\n")
	return b.String()
}

type column struct {
	title string
	max   int
	val   func(h scan.Host) string
}

// columns of the host table; the "#" column (nil val) shows the host's position.
var columns = []column{
	{"#", 3, nil},
	{"OS", 20, func(h scan.Host) string { return h.OS.Label() }},
	{"IP", 15, func(h scan.Host) string { return h.IP }},
	{"Hostname", 28, func(h scan.Host) string {
		if h.Self {
			return h.Hostname + " (this)"
		}
		return h.Hostname
	}},
	{"Vendor", 16, func(h scan.Host) string { return h.Vendor }},
	{"SSH", 40, func(h scan.Host) string {
		switch {
		case !h.SSH:
			return "–"
		case h.KeyChanged:
			return "⚠ key changed " + osdetect.BannerSoftware(h.Banner)
		case h.Banner == "":
			return "open"
		}
		return osdetect.BannerSoftware(h.Banner)
	}},
	{"Latency", 7, func(h scan.Host) string { return scan.FormatLatency(h.Latency) }},
}

func (m *Model) table() string {
	widths := append([]int(nil), m.widths...)
	// Shrink the SSH column to fit the terminal.
	total := 2
	for _, w := range widths {
		total += w + 2
	}
	if over := total - m.width; over > 0 {
		sshCol := 5
		widths[sshCol] = max(8, widths[sshCol]-over)
	}

	var b strings.Builder
	var hdr []string
	for i, c := range columns {
		hdr = append(hdr, pad(c.title, widths[i]))
	}
	b.WriteString("  " + headerSt.Render(strings.Join(hdr, "  ")) + "\n")

	end := min(len(m.visible), m.offset+m.pageSize())
	for row := m.offset; row < end; row++ {
		idx := m.visible[row]
		h := m.hosts[idx]
		cells := make([]string, len(columns))
		for i, v := range m.rows[idx].cells {
			cells[i] = pad(v, widths[i])
		}
		line := strings.Join(cells, "  ")
		if row == m.cursor {
			b.WriteString(keySt.Render("▸ ") + cursorSt.Inherit(osStyle(h.OS.OS)).Render(line) + "\n")
			continue
		}
		cells[1] = osStyle(h.OS.OS).Render(cells[1])
		cells[0] = dim.Render(cells[0])
		if h.SSH {
			cells[5] = sshSt.Render(cells[5])
		} else {
			for _, i := range []int{2, 3, 4, 5, 6} {
				cells[i] = dim.Render(cells[i])
			}
		}
		b.WriteString("  " + strings.Join(cells, "  ") + "\n")
	}
	if len(m.visible) == 0 {
		msg := "  no devices match the filter"
		if m.sshOnly && m.filter.Value() == "" {
			msg = "  no devices with SSH open — press s to show all devices"
		}
		b.WriteString(dim.Render(msg) + "\n")
	} else if len(m.visible) > m.pageSize() {
		b.WriteString(dim.Render(fmt.Sprintf("  %d–%d of %d", m.offset+1, end, len(m.visible))) + "\n")
	}
	return b.String()
}

func (m *Model) details() string {
	h, ok := m.selected()
	if !ok {
		return "\n"
	}
	var parts []string
	if h.MAC != "" {
		parts = append(parts, "MAC "+h.MAC)
	}
	if h.TTL > 0 {
		parts = append(parts, "TTL "+strconv.Itoa(h.TTL))
	}
	if len(h.OpenPorts) > 0 {
		ps := make([]string, len(h.OpenPorts))
		for i, p := range h.OpenPorts {
			ps[i] = strconv.Itoa(p)
		}
		parts = append(parts, "ports "+strings.Join(ps, ","))
	}
	if u := m.store.User(h); u != "" {
		parts = append(parts, "user "+u)
	}
	if h.HostKey != "" {
		parts = append(parts, "key "+h.HostKey)
	}
	line1 := osStyle(h.OS.OS).Render(h.OS.Label()) + dim.Render(" · confidence "+h.OS.Confidence.String())
	if len(parts) > 0 {
		line1 += dim.Render(" · " + strings.Join(parts, " · "))
	}
	why := "no identifying signals"
	if len(h.OS.Reasons) > 0 {
		why = strings.Join(h.OS.Reasons, "; ")
	}
	return lipgloss.NewStyle().MaxWidth(m.width).Render(line1) + "\n" + dim.Render(truncate("why: "+why, m.width-1)) + "\n"
}

func help(pairs ...string) string {
	var parts []string
	for i := 0; i+1 < len(pairs); i += 2 {
		parts = append(parts, keySt.Render(pairs[i])+" "+dim.Render(pairs[i+1]))
	}
	return strings.Join(parts, dim.Render("  ·  ")) + "\n"
}

func progressBar(done, total, width int) string {
	if total == 0 {
		total = 1
	}
	filled := done * width / total
	return lipgloss.NewStyle().Foreground(accent).Render(strings.Repeat("█", filled)) +
		dim.Render(strings.Repeat("░", width-filled))
}

func pad(s string, w int) string {
	s = truncate(s, w)
	if n := len([]rune(s)); n < w {
		s += strings.Repeat(" ", w-n)
	}
	return s
}

func truncate(s string, w int) string {
	r := []rune(s)
	if w <= 0 || len(r) <= w {
		return s
	}
	if w == 1 {
		return "…"
	}
	return string(r[:w-1]) + "…"
}
