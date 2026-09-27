package osdetect

import (
	"bufio"
	"os"
	"strings"
	"sync"
)

// builtinOUI is a small fallback table used when no system OUI database is
// available. Keys are the first 3 bytes of the MAC as 6 uppercase hex digits.
var builtinOUI = map[string]string{
	// Apple
	"000393": "Apple", "000A27": "Apple", "000A95": "Apple", "000D93": "Apple",
	"0010FA": "Apple", "001124": "Apple", "001451": "Apple", "0016CB": "Apple",
	"0017F2": "Apple", "0019E3": "Apple", "001B63": "Apple", "001CB3": "Apple",
	"001D4F": "Apple", "001E52": "Apple", "001EC2": "Apple", "001F5B": "Apple",
	"001FF3": "Apple", "0021E9": "Apple", "002241": "Apple", "002312": "Apple",
	"002332": "Apple", "00236C": "Apple", "0023DF": "Apple", "002436": "Apple",
	"002500": "Apple", "00254B": "Apple", "0025BC": "Apple", "002608": "Apple",
	"00264A": "Apple", "0026B0": "Apple", "0026BB": "Apple", "3C0754": "Apple",
	"406C8F": "Apple", "60FB42": "Apple", "64B9E8": "Apple", "70CD60": "Apple",
	"78CA39": "Apple", "7CC3A1": "Apple", "88665A": "Apple", "8C8590": "Apple",
	"A45E60": "Apple", "ACBC32": "Apple", "F01898": "Apple", "F45C89": "Apple",
	"D0817A": "Apple", "149877": "Apple", "A860B6": "Apple", "3C22FB": "Apple",
	"BCD074": "Apple",
	// Microsoft (incl. Hyper-V virtual NICs)
	"00155D": "Microsoft", "0003FF": "Microsoft", "000D3A": "Microsoft",
	"00125A": "Microsoft", "0017FA": "Microsoft", "001DD8": "Microsoft",
	"0050F2": "Microsoft", "281878": "Microsoft", "7C1E52": "Microsoft",
	"985FD3": "Microsoft",
	// Raspberry Pi
	"B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
	"D83ADD": "Raspberry Pi", "28CDC1": "Raspberry Pi", "2CCF67": "Raspberry Pi",
	// Virtualization
	"000C29": "VMware", "005056": "VMware", "000569": "VMware",
	"080027": "VirtualBox", "525400": "QEMU/KVM", "001C42": "Parallels",
	// Misc
	"00E04C": "Realtek", "001132": "Synology",
}

var systemOUIFiles = []string{
	"/usr/share/nmap/nmap-mac-prefixes", // "000393 Apple"
	"/usr/share/hwdata/oui.txt",         // "00-03-93   (hex)\t\tApple, Inc."
	"/usr/share/ieee-data/oui.txt",
}

var (
	ouiOnce  sync.Once
	ouiTable map[string]string
)

func loadOUI() {
	ouiTable = make(map[string]string, len(builtinOUI))
	for k, v := range builtinOUI {
		ouiTable[k] = v
	}
	for _, path := range systemOUIFiles {
		if n := loadOUIFile(path, ouiTable); n > 0 {
			return
		}
	}
}

func loadOUIFile(path string, dst map[string]string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' || strings.Contains(line, "(base 16)") {
			continue
		}
		var prefix, vendor string
		if i := strings.Index(line, "(hex)"); i > 0 {
			prefix = strings.ReplaceAll(strings.TrimSpace(line[:i]), "-", "")
			vendor = strings.TrimSpace(line[i+len("(hex)"):])
		} else if len(line) > 7 && line[6] == ' ' {
			prefix, vendor = line[:6], strings.TrimSpace(line[7:])
		} else {
			continue
		}
		if len(prefix) != 6 || vendor == "" {
			continue
		}
		dst[strings.ToUpper(prefix)] = shortVendor(vendor)
		n++
	}
	return n
}

// shortVendor trims corporate suffixes: "Apple, Inc." -> "Apple".
func shortVendor(v string) string {
	for _, sep := range []string{",", " Inc", " Corporation", " Corp", " Co.", " Ltd", " Limited", " GmbH"} {
		if i := strings.Index(v, sep); i > 0 {
			v = v[:i]
		}
	}
	return strings.TrimSpace(v)
}

// Vendor returns the NIC vendor for a MAC address such as "aa:bb:cc:dd:ee:ff".
// Randomized (locally administered) addresses return "Private MAC".
func Vendor(mac string) string {
	hex := strings.ToUpper(strings.NewReplacer(":", "", "-", "", ".", "").Replace(mac))
	if len(hex) < 6 {
		return ""
	}
	if isLocallyAdministered(hex) {
		return "Private MAC"
	}
	ouiOnce.Do(loadOUI)
	return ouiTable[hex[:6]]
}

func isLocallyAdministered(hex string) bool {
	var b byte
	for _, c := range hex[:2] {
		b <<= 4
		switch {
		case c >= '0' && c <= '9':
			b |= byte(c - '0')
		case c >= 'A' && c <= 'F':
			b |= byte(c - 'A' + 10)
		}
	}
	return b&0x02 != 0
}
