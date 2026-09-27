// Package osdetect guesses a host's operating system from cheap, unprivileged
// signals: the SSH banner, NIC vendor, ICMP TTL, hostname and a few open ports.
package osdetect

import (
	"regexp"
	"strings"
)

type OS string

const (
	Windows OS = "Windows"
	Linux   OS = "Linux"
	MacOS   OS = "macOS"
	BSD     OS = "BSD"
	IOS     OS = "iOS"
	Android OS = "Android"
	Unknown OS = "Unknown"
)

type Confidence int

const (
	None Confidence = iota
	Low
	Medium
	High
)

func (c Confidence) String() string {
	switch c {
	case High:
		return "high"
	case Medium:
		return "medium"
	case Low:
		return "low"
	}
	return "none"
}

// Signals are the observations collected for a single host.
type Signals struct {
	Banner    string // e.g. "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"
	Vendor    string // NIC vendor from the OUI table
	TTL       int    // ICMP reply TTL, 0 if unknown
	Hostname  string // reverse DNS / mDNS name
	OpenPorts []int  // extra ports found open besides SSH
	NmapOS    string // optional nmap -O match, e.g. "Microsoft Windows 11"
}

type Result struct {
	OS         OS         `json:"os"`
	Detail     string     `json:"detail,omitempty"` // distro / version hint
	Confidence Confidence `json:"confidence"`
	Reasons    []string   `json:"reasons,omitempty"`
}

// Label is the display form, e.g. "Linux (Ubuntu)".
func (r Result) Label() string {
	if r.OS == Unknown && r.Detail != "" {
		return r.Detail
	}
	if r.Detail != "" {
		return string(r.OS) + " (" + r.Detail + ")"
	}
	return string(r.OS)
}

var distroTokens = []struct{ token, name string }{
	{"ubuntu", "Ubuntu"}, {"debian", "Debian"}, {"raspbian", "Raspbian"},
	{"fedora", "Fedora"}, {"centos", "CentOS"}, {"rhel", "RHEL"},
	{"alpine", "Alpine"}, {"suse", "SUSE"}, {"gentoo", "Gentoo"},
	{"arch", "Arch"}, {"synology", "Synology"}, {"qnap", "QNAP"},
}

var (
	opensshVersion = regexp.MustCompile(`OpenSSH_[0-9]+\.[0-9]+`)
	archWord       = regexp.MustCompile(`(?i)\barch\b`)
)

// BannerSoftware returns the software part of an SSH banner, e.g.
// "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5" from "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5".
func BannerSoftware(banner string) string {
	b := strings.TrimSpace(banner)
	for _, p := range []string{"SSH-2.0-", "SSH-1.99-", "SSH-1.5-"} {
		if strings.HasPrefix(b, p) {
			return b[len(p):]
		}
	}
	return b
}

// score accumulates weighted votes per OS.
type score struct {
	votes   map[OS]int
	detail  map[OS]string
	reasons map[OS][]string
}

func (s *score) add(os OS, weight int, reason string) {
	s.votes[os] += weight
	s.reasons[os] = append(s.reasons[os], reason)
}

// Classify combines all signals into a best guess.
func Classify(sig Signals) Result {
	s := &score{votes: map[OS]int{}, detail: map[OS]string{}, reasons: map[OS][]string{}}
	unixLike := 0        // evidence for "Linux or macOS" without telling them apart
	macSpecific := false // evidence for macOS itself, not just Apple hardware

	// nmap, when available, is the strongest signal.
	if n := strings.ToLower(sig.NmapOS); n != "" {
		switch {
		case strings.Contains(n, "windows"):
			s.add(Windows, 10, "nmap: "+sig.NmapOS)
		case strings.Contains(n, "mac os") || strings.Contains(n, "macos") || strings.Contains(n, "darwin") || strings.Contains(n, "os x"):
			s.add(MacOS, 10, "nmap: "+sig.NmapOS)
			macSpecific = true
		case strings.Contains(n, "linux"):
			s.add(Linux, 10, "nmap: "+sig.NmapOS)
		case strings.Contains(n, "bsd"):
			s.add(BSD, 10, "nmap: "+sig.NmapOS)
		}
	}

	// SSH banner.
	sw := BannerSoftware(sig.Banner)
	lsw := strings.ToLower(sw)
	switch {
	case lsw == "":
	case strings.Contains(lsw, "for_windows") || strings.Contains(lsw, "microsoft") ||
		strings.Contains(lsw, "winsshd") || strings.Contains(lsw, "bitvise") ||
		strings.Contains(lsw, "cygwin") || strings.Contains(lsw, "freesshd"):
		s.add(Windows, 8, "SSH banner: "+sw)
	case strings.Contains(lsw, "freebsd") || strings.Contains(lsw, "openbsd") || strings.Contains(lsw, "netbsd"):
		s.add(BSD, 8, "SSH banner: "+sw)
	case strings.Contains(lsw, "dropbear"):
		s.add(Linux, 5, "Dropbear SSH (embedded Linux)")
		s.detail[Linux] = "embedded"
	default:
		found := false
		for _, d := range distroTokens {
			// "arch" is too short to match loosely; require it as its own word.
			if d.token == "arch" {
				if !archWord.MatchString(sw) {
					continue
				}
			} else if !strings.Contains(lsw, d.token) {
				continue
			}
			s.add(Linux, 8, "SSH banner: "+sw)
			s.detail[Linux] = d.name
			found = true
			break
		}
		if !found && opensshVersion.MatchString(sw) {
			// Plain "OpenSSH_9.8" is what macOS, Arch, Fedora and RHEL all send.
			unixLike += 2
		}
	}

	// NIC vendor.
	switch v := strings.ToLower(sig.Vendor); {
	case strings.HasPrefix(v, "apple"):
		// Apple hardware, which may just as well run Linux (e.g. Omarchy on a
		// MacBook). Capped below unless something points at macOS itself.
		s.add(MacOS, 6, "Apple network adapter")
	case strings.HasPrefix(v, "microsoft"):
		s.add(Windows, 4, "Microsoft/Hyper-V network adapter")
	case strings.HasPrefix(v, "raspberry"):
		s.add(Linux, 6, "Raspberry Pi network adapter")
		if s.detail[Linux] == "" {
			s.detail[Linux] = "Raspberry Pi"
		}
	case strings.HasPrefix(v, "synology"), strings.HasPrefix(v, "qnap"):
		s.add(Linux, 5, sig.Vendor+" NAS")
	}

	// Hostname conventions.
	h := strings.ToLower(sig.Hostname)
	macHostname := false
	switch {
	case h == "":
	case strings.HasPrefix(h, "desktop-") || strings.HasPrefix(h, "laptop-") || strings.HasPrefix(h, "win-"):
		s.add(Windows, 4, "Windows-style hostname")
	case containsAny(h, "macbook", "imac", "mac-mini", "macmini", "mac-studio", "mbp", "mba-", "-mac."):
		s.add(MacOS, 4, "Mac-style hostname")
		macHostname = true
		macSpecific = true
	case containsAny(h, "iphone", "ipad"):
		// Outvotes the Apple NIC, which iPhones share with Macs.
		s.add(IOS, 8, "iPhone/iPad hostname")
	case containsAny(h, "android", "galaxy", "pixel", "tab-s"):
		s.add(Android, 6, "Android-style hostname")
	case containsAny(h, "raspberrypi", "ubuntu", "debian", "fedora", "archlinux"):
		s.add(Linux, 3, "Linux-style hostname")
	}

	// Extra open ports.
	ports := map[int]bool{}
	for _, p := range sig.OpenPorts {
		ports[p] = true
	}
	if ports[135] {
		s.add(Windows, 6, "MSRPC (135) open")
	}
	if ports[3389] {
		s.add(Windows, 5, "RDP (3389) open")
	}
	if ports[548] || ports[3283] {
		s.add(MacOS, 5, "AFP/Remote Desktop (548/3283) open")
		macSpecific = true
	}
	if ports[88] && ports[445] && !ports[135] {
		s.add(MacOS, 3, "Kerberos + SMB without MSRPC (macOS file sharing)")
		macSpecific = true
	}

	// TTL: Windows starts at 128, Linux/macOS at 64.
	switch {
	case sig.TTL > 64 && sig.TTL <= 128:
		s.add(Windows, 4, "TTL ~128")
	case sig.TTL > 0 && sig.TTL <= 64:
		unixLike += 2
	}

	// Pick the winner.
	best, bestVotes := Unknown, 0
	for _, os := range []OS{Windows, IOS, MacOS, Android, Linux, BSD} {
		if s.votes[os] > bestVotes {
			best, bestVotes = os, s.votes[os]
		}
	}

	if best == Windows && unixLike > 0 && bestVotes < 8 {
		// Conflicting evidence: weak Windows signals but Unix-like banner/TTL.
		bestVotes -= unixLike
	}

	if best == Unknown || bestVotes <= 0 {
		switch {
		case sw != "" && unixLike > 0:
			return Result{OS: Linux, Detail: "or macOS", Confidence: Low,
				Reasons: []string{"generic OpenSSH banner"}}
		case unixLike > 0:
			// TTL 64 alone also fits phones, TVs and other embedded devices.
			return Result{OS: Unknown, Detail: "Unix-like", Confidence: Low,
				Reasons: []string{"TTL ~64"}}
		}
		return Result{OS: Unknown, Confidence: None}
	}
	if best == MacOS && sw == "" && sig.NmapOS == "" && !macHostname {
		// An Apple NIC without an SSH server is just as likely an iPhone or iPad.
		s.detail[MacOS] = "or iOS"
	}
	if best != Windows {
		// Generic Unix evidence only nudges the score; it can't tell them apart.
		bestVotes += min(unixLike, 2)
	}

	conf := Low
	switch {
	case bestVotes >= 8:
		conf = High
	case bestVotes >= 5:
		conf = Medium
	}
	reasons := s.reasons[best]
	if best == MacOS && !macSpecific {
		// Only the Apple NIC says "Mac", and that is hardware, not the OS.
		if sw != "" {
			// A plain OpenSSH banner fits Linux as well, and Linux boxes run
			// sshd far more often than Macs have Remote Login on.
			s.detail[MacOS] = "or Linux"
			conf = Low
			reasons = append(reasons, "plain OpenSSH banner fits Linux on Apple hardware too")
		} else {
			conf = min(conf, Medium)
		}
	}
	return Result{OS: best, Detail: s.detail[best], Confidence: conf, Reasons: reasons}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
