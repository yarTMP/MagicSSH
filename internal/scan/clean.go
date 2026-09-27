package scan

import (
	"net"
	"strings"
	"unicode"

	"magicssh/internal/osdetect"
)

const (
	maxBannerLen   = 255 // RFC 4253 §4.2 limit for the identification line
	maxHostnameLen = 253 // longest DNS name
)

// Clean makes text that came from the network safe to print in a terminal. It
// drops control characters (which removes the ESC that starts ANSI/OSC escape
// sequences), invisible format characters such as bidi overrides and invalid
// UTF-8, then trims spaces and caps the result at max runes.
func Clean(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range strings.ToValidUTF8(s, "") {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		if n == max {
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// Sanitize validates a host loaded from disk before it is shown or passed to
// ssh. It reports false if the IP address is not a valid IPv4 address.
func (h *Host) Sanitize() bool {
	ip := net.ParseIP(h.IP).To4()
	if ip == nil {
		return false
	}
	h.IP = ip.String()
	if mac, err := net.ParseMAC(h.MAC); err == nil {
		h.MAC = mac.String()
	} else {
		h.MAC = ""
	}
	h.Hostname = Clean(h.Hostname, maxHostnameLen)
	h.Banner = Clean(h.Banner, maxBannerLen)
	h.HostKey = Clean(h.HostKey, 128)
	switch h.KnownHosts {
	case "", "ok", "unknown", "mismatch", "revoked":
	default:
		h.KnownHosts = ""
	}
	h.Vendor = Clean(h.Vendor, 64)
	h.OS.OS = osdetect.OS(Clean(string(h.OS.OS), 32))
	h.OS.Detail = Clean(h.OS.Detail, 64)
	for i, r := range h.OS.Reasons {
		h.OS.Reasons[i] = Clean(r, 2*maxBannerLen)
	}
	return true
}
