# magicssh

Find every device on your local network, see what OS it runs and whether SSH
is open, pick one, connect.

```
  ┌┬┐┌─┐┌─┐┬┌─┐┌─┐┌─┐┬ ┬
  │││├─┤│ ┬││  └─┐└─┐├─┤
  ┴ ┴┴ ┴└─┘┴└─┘└─┘└─┘┴ ┴
  192.168.1.0/24 · port 22

  #  OS               IP            Hostname          Vendor        SSH                               Latency
▸ 1  Linux (Ubuntu)   192.168.1.10  homelab.lan       Intel         OpenSSH_9.6p1 Ubuntu-3ubuntu13.5  2ms
  2  Windows          192.168.1.23  DESKTOP-4F2K9QX   Private MAC   OpenSSH_for_Windows_9.5           4ms
  3  macOS            192.168.1.31  Studio.local      Apple         OpenSSH_9.8                       3ms

Linux (Ubuntu) · confidence high · MAC 3c:97:0e:… · TTL 64 · user ray
why: SSH banner: OpenSSH_9.6p1 Ubuntu-3ubuntu13.5
↑/↓ move · enter connect · / filter · u user · r rescan · q quit
```

## Install

```sh
go build -o magicssh ./cmd/magicssh      # or: go install ./cmd/magicssh
sudo install magicssh /usr/local/bin/    # optional
```

Requires the `ssh` client. `getent`, `avahi-resolve` and `nmap` are used when
present to improve hostname and OS detection. Pings are sent from magicssh
itself (unprivileged ICMP sockets, `net.ipv4.ping_group_range`); the system
`ping` is only a fallback.

## Usage

```sh
magicssh                          # scan the current network and open the picker
magicssh --ssh-only               # only list devices with SSH open
magicssh --cached                 # reuse the last scan instantly
magicssh --subnet 10.0.0.0/24     # scan a specific subnet (private ranges only,
                                  #   unless --allow-public)
magicssh --iface wlan0            # auto-detect from a specific interface
magicssh -l admin -i ~/.ssh/work  # default username and identity file
magicssh -- -A -o ServerAliveInterval=30   # extra args passed to ssh
magicssh list                     # print a table and exit
magicssh list --json              # machine-readable output
magicssh --deep                   # add nmap -O fingerprinting (asks for sudo, used for nmap only)
magicssh --key-alias              # key known_hosts by MAC so entries survive DHCP changes
```

Keys: `↑/↓` or `j/k` move · `enter` connect · `/` filter · `s` toggle SSH-only ·
`u` set username · `r` rescan · `q`/`esc` quit.

## How devices are found

Every address in the subnet gets a TCP connection attempt on the SSH port. A
device counts as found if it accepts the connection (SSH open), refuses it (up,
SSH closed), or appears in the kernel ARP table, which catches firewalled
devices on the same link. Only the devices found are then pinged, for TTL and
latency. For a subnet you are not directly attached to, ARP can't help, so
every address is pinged during the scan instead. Only devices with SSH open can
be connected to; the others are shown dimmed.

When you connect, magicssh asks for the username (pre-filled with the one you
last used for that device, else `$USER`), then replaces itself with the system
`ssh`, so `~/.ssh/config`, keys, the agent and `known_hosts` all apply as usual.
Passwords are never stored.

Scan results, per-device usernames and SSH host keys are cached in
`~/.config/magicssh/hosts.json`. Both are keyed by MAC address when known, so
they survive DHCP address changes.

## Safety

- Banners and hostnames come from other devices on the network, so control
  characters (terminal escape sequences) are stripped and lengths capped before
  anything is shown or cached.
- magicssh remembers each device's SSH host key. If a device later presents a
  different key it is marked **⚠ key changed**, and connecting needs a second
  `enter`. `ssh` still verifies the key against `known_hosts` as usual.
- With `--deep`, only `nmap` runs as root (via `sudo -n`, after asking for the
  password up front). Running the whole tool under `sudo` also works: the cache
  stays in your own home, and privileges are dropped before `ssh` starts
  (sudo removes `SSH_AUTH_SOCK`, so the agent is not available then).

## How OS detection works

No root needed for the default path. Each signal adds weighted votes:

| Signal | Example | Points to |
|---|---|---|
| SSH banner | `OpenSSH_for_Windows_9.5` | Windows (strong) |
| SSH banner | `… Ubuntu-3ubuntu13.5`, `Debian`, `Raspbian` | Linux + distro (strong) |
| SSH banner | `dropbear`, `FreeBSD` | embedded Linux, BSD |
| NIC vendor (OUI) | Apple / Microsoft / Raspberry Pi | macOS / Windows / Linux |
| Extra open ports | 135 (MSRPC), 3389 (RDP) | Windows |
| Extra open ports | 548 (AFP), 3283 (ARD), 88+445 without 135 | macOS |
| ICMP TTL | ~128 vs ~64 | Windows vs Unix-like |
| Hostname | `DESKTOP-…`, `…-MacBook-Pro` | Windows, macOS |
| Hostname | `…-iPhone`, `iPad`, `Galaxy…`, `Pixel…` | iOS, Android |
| `nmap -O` (`--deep`, via sudo) | `Microsoft Windows 11` | overrides the rest; only run for hosts not already identified with high confidence |

### Known limitations

- Without an SSH banner, a TTL of 64 alone only says **Unix-like**: that fits
  routers, TVs, streaming sticks and phones as well as computers. An Apple NIC
  with no other clue is shown as `macOS (or iOS)`.
- **macOS vs. Linux** is the hard case. macOS, Arch, Fedora and RHEL all send a
  plain `OpenSSH_X.Y` banner. Without an Apple MAC, Mac-style hostname or Mac
  ports, such hosts show as `Linux (or macOS)` with low confidence.
- Newer phones and laptops often use **private (randomized) MACs**, which hide
  the vendor.
- Windows Firewall usually blocks ping, so TTL is often missing for Windows.
  The `OpenSSH_for_Windows` banner is still a reliable signal.
- MAC addresses are only visible for hosts on the same L2 segment. Across
  routers, the vendor is unknown.
- Only IPv4, and subnets no larger than /16.

## Development

```sh
go test ./...
go vet ./...
```

Layout: `cmd/magicssh` (CLI), `internal/scan` (subnet, TCP scan, enrichment,
nmap), `internal/osdetect` (classification, OUI lookup), `internal/tui`
(Bubble Tea picker), `internal/config` (cache).
