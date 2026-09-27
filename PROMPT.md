# Build prompt: magicssh

Build **magicssh**, a terminal CLI/TUI tool in **Go** that discovers SSH-reachable
devices on my local network, identifies their OS (Windows, Linux, macOS), and lets
me pick one from an interactive list to open an SSH session.

## Context

- Host: Arch-based Linux (Omarchy), Go, `ssh` and `nmap` are installed.
- A manual scan already confirmed that the LAN has **Windows, Linux and macOS**
  devices with **TCP port 22 open**. The tool must handle all three
  (Windows hosts typically run "OpenSSH for Windows").
- The project directory is empty. Start with `go mod init magicssh`.

## Functional requirements

1. **Network detection**
   - Auto-detect the active interface and its IPv4 subnet (e.g. `192.168.1.0/24`).
   - Allow overriding with `--subnet 10.0.0.0/24` and `--iface wlan0`.
   - Refuse or warn on subnets larger than /16.

2. **Scanning (no root required)**
   - Concurrent TCP connect scan of port 22 on every host in the subnet
     (worker pool, default 256 workers, ~500 ms timeout; flags `--port`,
     `--timeout`, `--workers`).
   - For each open host, collect:
     - IP address
     - Hostname (reverse DNS; fall back to mDNS/`.local` name if available)
     - MAC address + vendor from `/proc/net/arp` (after the scan populates the ARP
       cache) and an embedded small OUI table (at least Apple, Microsoft, Raspberry
       Pi, common NIC vendors)
     - SSH banner (read the `SSH-2.0-...` line the server sends on connect)
     - Response latency
   - Show a live progress indicator while scanning (hosts scanned / total, found).

3. **OS identification** — combine signals into a best guess with a confidence level:
   - SSH banner: `OpenSSH_for_Windows` → Windows; `Ubuntu`/`Debian`/`Raspbian`/
     `Fedora` etc. in the banner → Linux (show distro); plain `OpenSSH_X.Y` with
     no suffix → likely macOS or generic Linux.
   - MAC vendor: Apple → macOS; Microsoft/Hyper-V → Windows.
   - TTL of an ICMP ping reply if obtainable without root
     (`ping -c1 -W1`): ~128 → Windows, ~64 → Linux/macOS.
   - Optional `--deep` flag: if running as root, use `nmap -O -p22` for the found
     hosts and use its result to override the guess.
   - Result: `Windows`, `Linux (<distro>)`, `macOS`, or `Unknown`.

4. **Interactive selection (TUI)**
   - Use Bubble Tea + Lip Gloss (charmbracelet) for a table with columns:
     `#  OS-icon/label  IP  Hostname  Vendor  SSH banner  Latency`.
   - Arrow keys / `j`/`k` to move, `Enter` to connect, `/` to filter by any
     column, `r` to rescan, `u` to change the username, `q`/`Esc` to quit.
   - Color-code OS (e.g. Windows blue, Linux yellow, macOS gray).
   - Sort by IP numerically by default.

5. **Connecting**
   - On Enter, prompt for the username (default: last used for that host, else
     `$USER`; Windows hosts often need a different user — remember per host).
   - Exit the TUI cleanly, then run the system `ssh` binary via `syscall.Exec`
     (or `exec.Command` with stdin/stdout/stderr attached) so the session is fully
     interactive and honors `~/.ssh/config`, keys, agent and known_hosts.
   - Support `--port`, `-i <identity>` and extra passthrough args after `--`.

6. **Persistence & extras**
   - Cache last scan results and per-host usernames in
     `~/.config/magicssh/hosts.json`; `--cached` shows the list instantly without
     rescanning.
   - Non-interactive mode: `magicssh list` prints a table (or `--json`) and exits.
   - `--version`, `--help`.

## Non-functional requirements

- Single static binary; no root needed for the default path.
- Clean package layout: `cmd/magicssh`, `internal/scan`, `internal/osdetect`,
  `internal/tui`, `internal/config`.
- Handle errors gracefully (no interface found, no hosts found, ssh missing).
- Unit tests for subnet enumeration, banner parsing / OS classification, and
  OUI lookup.
- A short `README.md` with install (`go install` / `go build`), usage and examples.

## Security / scope

- Only scan the local subnet I'm connected to (or one I explicitly pass);
  this is for my own network.
- Never store passwords; authentication is left entirely to `ssh`.

## Deliverables

1. Working code that builds with `go build ./...` and passes `go test ./...`.
2. A demo run: `magicssh list` against my LAN showing the detected devices.
3. A summary of how OS detection works and its known limitations.
