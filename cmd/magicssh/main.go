// Command magicssh scans the local network for SSH servers, identifies their
// OS and opens an ssh session to the one you pick.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"magicssh/internal/config"
	"magicssh/internal/osdetect"
	"magicssh/internal/scan"
	"magicssh/internal/tui"
)

var version = "0.1.0"

type cliFlags struct {
	subnet, iface, identity, user  string
	port, workers                  int
	timeout                        time.Duration
	deep, cached, jsonOut, ver     bool
	sshOnly, allowPublic, keyAlias bool
}

const maxWorkers = 1024

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "magicssh:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	listMode := len(args) > 0 && args[0] == "list"
	if listMode {
		args = args[1:]
	}

	fs := flag.NewFlagSet("magicssh", flag.ContinueOnError)
	var f cliFlags
	fs.StringVar(&f.subnet, "subnet", "", "subnet to scan in CIDR form, e.g. 192.168.1.0/24 (default: auto-detect)")
	fs.StringVar(&f.iface, "iface", "", "network interface to use for auto-detection")
	fs.IntVar(&f.port, "port", 22, "SSH port to scan and connect to")
	fs.DurationVar(&f.timeout, "timeout", 500*time.Millisecond, "TCP connect timeout per host")
	fs.IntVar(&f.workers, "workers", 256, "number of concurrent connection attempts")
	fs.BoolVar(&f.sshOnly, "ssh-only", false, "only show devices with the SSH port open")
	fs.BoolVar(&f.allowPublic, "allow-public", false, "allow --subnet to name a public (non-private) range")
	fs.BoolVar(&f.keyAlias, "key-alias", false, "key known_hosts entries by MAC address (ssh -o HostKeyAlias) so they survive DHCP changes")
	fs.BoolVar(&f.deep, "deep", false, "use nmap -O for OS detection (asks for sudo for nmap only)")
	fs.BoolVar(&f.cached, "cached", false, "show the last scan results instead of scanning")
	fs.StringVar(&f.identity, "i", "", "identity file passed to ssh")
	fs.StringVar(&f.user, "l", "", "default username (default: $USER)")
	fs.BoolVar(&f.jsonOut, "json", false, "with 'list': print JSON")
	fs.BoolVar(&f.ver, "version", false, "print version and exit")
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintf(out, "magicssh %s — find SSH hosts on your network and connect\n\n", version)
		fmt.Fprintln(out, "Usage:")
		fmt.Fprintln(out, "  magicssh [flags] [-- extra ssh args]   interactive picker")
		fmt.Fprintln(out, "  magicssh list [flags]                  print hosts and exit")
		fmt.Fprintln(out, "\nFlags:")
		fs.PrintDefaults()
		fmt.Fprintln(out, "\nKeys: ↑/↓ or j/k move · enter connect · / filter · s SSH-only · u set user · r rescan · q quit")
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if f.ver {
		fmt.Println("magicssh", version)
		return nil
	}
	sshExtra := fs.Args()
	// Allow flags before the subcommand: "magicssh --deep list --json".
	if !listMode && len(sshExtra) > 0 && sshExtra[0] == "list" {
		listMode = true
		if err := fs.Parse(sshExtra[1:]); err != nil {
			return err
		}
		sshExtra = fs.Args()
	}
	if listMode && len(sshExtra) > 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(sshExtra, " "))
	}

	store, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading cache: %w", err)
	}

	opts, err := scanOptions(f, store)
	if err != nil {
		return err
	}
	if opts.Deep && os.Geteuid() != 0 && !(listMode && f.cached) {
		opts.SudoNmap = cacheSudo()
		opts.Deep = opts.SudoNmap
	}

	var cached []scan.Host
	if f.cached {
		if len(store.Hosts) == 0 {
			return fmt.Errorf("no cached scan yet; run without --cached first")
		}
		cached = store.Hosts
	}

	if listMode {
		return list(opts, store, cached, f.jsonOut)
	}

	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		return fmt.Errorf("ssh client not found in PATH")
	}

	sudoUser := config.SudoUser()
	defUser := f.user
	if defUser == "" {
		defUser = os.Getenv("USER")
		if sudoUser != nil {
			defUser = sudoUser.Username
		}
	}
	m := tui.New(opts, store, defUser, cached, store.ScanTime)
	final, err := tea.NewProgram(m, tea.WithAltScreen()).Run()
	if err != nil {
		return err
	}
	choice := final.(*tui.Model).Choice
	if choice == nil {
		return nil
	}

	sshArgs := []string{"ssh", "-l", choice.User}
	if f.port != 22 {
		sshArgs = append(sshArgs, "-p", strconv.Itoa(f.port))
	}
	if f.identity != "" {
		sshArgs = append(sshArgs, "-i", f.identity)
	}
	if f.keyAlias && choice.Host.MAC != "" {
		sshArgs = append(sshArgs, "-o", "HostKeyAlias=magicssh-"+strings.ReplaceAll(strings.ToLower(choice.Host.MAC), ":", ""))
	}
	sshArgs = append(sshArgs, sshExtra...)
	// "--" keeps a host value that starts with "-" from being read as an ssh option.
	sshArgs = append(sshArgs, "--", choice.Host.IP)

	name := choice.Host.IP
	if choice.Host.Hostname != "" {
		name += " (" + choice.Host.Hostname + ")"
	}
	fmt.Printf("→ connecting to %s@%s · %s\n", choice.User, name, choice.Host.OS.Label())
	env := os.Environ()
	if sudoUser != nil {
		// Don't hand an ssh session root's keys and known_hosts: become the
		// user who ran sudo again.
		if env, err = dropPrivileges(sudoUser); err != nil {
			return fmt.Errorf("dropping root privileges before ssh: %w", err)
		}
	}
	return syscall.Exec(sshPath, sshArgs, env)
}

// cacheSudo asks for the sudo password now, while the terminal is still ours,
// so the scan can later run "sudo -n nmap" without prompting. Only nmap runs
// as root.
func cacheSudo() bool {
	if _, err := exec.LookPath("sudo"); err != nil {
		fmt.Fprintln(os.Stderr, "magicssh: --deep needs root for nmap -O and sudo is not installed; continuing with basic detection")
		return false
	}
	fmt.Fprintln(os.Stderr, "magicssh: --deep runs nmap -O as root via sudo")
	cmd := exec.Command("sudo", "-v")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "magicssh: sudo failed; continuing with basic detection")
		return false
	}
	return true
}

// dropPrivileges switches the process to u (groups first, then gid, then uid)
// and returns an environment pointing at u's home.
func dropPrivileges(u *user.User) ([]string, error) {
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return nil, err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return nil, err
	}
	var groups []int
	if ids, err := u.GroupIds(); err == nil {
		for _, id := range ids {
			if g, err := strconv.Atoi(id); err == nil {
				groups = append(groups, g)
			}
		}
	}
	if err := syscall.Setgroups(groups); err != nil {
		return nil, err
	}
	if err := syscall.Setgid(gid); err != nil {
		return nil, err
	}
	if err := syscall.Setuid(uid); err != nil {
		return nil, err
	}
	var env []string
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); k != "HOME" && k != "USER" && k != "LOGNAME" {
			env = append(env, kv)
		}
	}
	return append(env, "HOME="+u.HomeDir, "USER="+u.Username, "LOGNAME="+u.Username), nil
}

func scanOptions(f cliFlags, store *config.Store) (scan.Options, error) {
	switch {
	case f.port < 1 || f.port > 65535:
		return scan.Options{}, fmt.Errorf("--port %d: must be between 1 and 65535", f.port)
	case f.timeout <= 0 || f.timeout > 10*time.Second:
		return scan.Options{}, fmt.Errorf("--timeout %s: must be above 0 and at most 10s", f.timeout)
	case f.workers < 1 || f.workers > maxWorkers:
		return scan.Options{}, fmt.Errorf("--workers %d: must be between 1 and %d", f.workers, maxWorkers)
	}
	opts := scan.Options{Port: f.port, Timeout: f.timeout, Workers: f.workers, Deep: f.deep, SSHOnly: f.sshOnly}

	netw, detectErr := scan.DetectNetwork(f.iface)
	if detectErr == nil {
		opts.Local = netw
		opts.Subnet = netw.Subnet
	}
	switch {
	case f.subnet != "":
		sn, err := scan.ParseSubnet(f.subnet)
		if err != nil {
			return opts, fmt.Errorf("--subnet: %w", err)
		}
		opts.Subnet = sn
		// Guard against typos that would scan someone else's network. The
		// network you are on is fine even if it uses public addresses.
		local := detectErr == nil && netw.Subnet.Contains(sn.IP)
		if !local && !scan.IsPrivate(sn) && !f.allowPublic {
			return opts, fmt.Errorf("--subnet %s is not a private or local range; pass --allow-public if you mean it", sn)
		}
	case f.cached && store.Subnet != "":
		if sn, err := scan.ParseSubnet(store.Subnet); err == nil {
			opts.Subnet = sn
		}
	case detectErr != nil:
		return opts, detectErr
	}

	if ones, _ := opts.Subnet.Mask.Size(); ones < 16 {
		return opts, fmt.Errorf("subnet %s is too large (more than /16); pass a smaller --subnet", opts.Subnet)
	}
	if config.SudoUser() != nil {
		fmt.Fprintln(os.Stderr, "magicssh: no need to run magicssh with sudo; --deep asks for sudo for nmap only")
	}
	return opts, nil
}

func list(opts scan.Options, store *config.Store, cached []scan.Host, jsonOut bool) error {
	hosts := cached
	if hosts == nil {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		tty := isTerminal(os.Stderr)
		deliver := scan.Throttle(50 * time.Millisecond)
		var err error
		hosts, err = scan.Run(ctx, opts, func(p scan.Progress) {
			if tty && deliver(p) {
				fmt.Fprintf(os.Stderr, "\r\033[K%s %d/%d · %d devices · %d with SSH", p.Phase, p.Done, p.Total, p.Found, p.SSH)
			}
		})
		if tty {
			fmt.Fprint(os.Stderr, "\r\033[K")
		}
		if err != nil {
			return err
		}
		store.CheckHostKeys(hosts)
		if !opts.SSHOnly { // don't let a filtered scan replace the full cache
			store.Subnet, store.ScanTime, store.Hosts = opts.Subnet.String(), time.Now(), hosts
		}
		if err := store.Save(); err != nil {
			fmt.Fprintln(os.Stderr, "magicssh: could not save cache:", err)
		}
	}

	if cached != nil && opts.SSHOnly {
		hosts = nil
		for _, h := range cached {
			if h.SSH {
				hosts = append(hosts, h)
			}
		}
	}

	if jsonOut {
		if hosts == nil {
			hosts = []scan.Host{}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(hosts)
	}
	if len(hosts) == 0 {
		if opts.SSHOnly {
			fmt.Printf("No devices with port %d open on %s\n", opts.Port, opts.Subnet)
		} else {
			fmt.Printf("No devices found on %s\n", opts.Subnet)
		}
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "#\tOS\tCONF\tIP\tHOSTNAME\tVENDOR\tSSH\tLATENCY")
	for i, h := range hosts {
		name := h.Hostname
		if h.Self {
			name += " (this)"
		}
		ssh := "-"
		if h.SSH {
			ssh = osdetect.BannerSoftware(h.Banner)
			if ssh == "" {
				ssh = "open"
			}
			if h.KeyChanged {
				ssh = "⚠ KEY CHANGED " + ssh
			}
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", i+1, h.OS.Label(), h.OS.Confidence,
			h.IP, dash(name), dash(clip(h.Vendor, 20)), ssh, scan.FormatLatency(h.Latency))
	}
	return tw.Flush()
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
