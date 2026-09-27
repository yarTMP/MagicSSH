package osdetect

import (
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		name     string
		sig      Signals
		wantOS   OS
		wantDet  string
		wantConf Confidence
	}{
		{"windows banner", Signals{Banner: "SSH-2.0-OpenSSH_for_Windows_9.5"}, Windows, "", High},
		{"windows banner + ttl", Signals{Banner: "SSH-2.0-OpenSSH_for_Windows_8.1", TTL: 128, OpenPorts: []int{135, 445}}, Windows, "", High},
		{"ubuntu", Signals{Banner: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", TTL: 64}, Linux, "Ubuntu", High},
		{"debian", Signals{Banner: "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"}, Linux, "Debian", High},
		{"raspbian", Signals{Banner: "SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u2"}, Linux, "Raspbian", High},
		{"dropbear", Signals{Banner: "SSH-2.0-dropbear_2022.83"}, Linux, "embedded", Medium},
		{"freebsd", Signals{Banner: "SSH-2.0-OpenSSH_9.7 FreeBSD-20240318"}, BSD, "", High},
		{"mac by vendor", Signals{Banner: "SSH-2.0-OpenSSH_9.8", Vendor: "Apple", TTL: 64}, MacOS, "", High},
		{"mac by hostname", Signals{Banner: "SSH-2.0-OpenSSH_9.8", Hostname: "Johns-MacBook-Pro.local", TTL: 64}, MacOS, "", Medium},
		{"mac by ports", Signals{Banner: "SSH-2.0-OpenSSH_9.8", OpenPorts: []int{88, 445}, TTL: 64}, MacOS, "", Medium},
		{"windows by ttl+hostname, private MAC", Signals{Banner: "SSH-2.0-OpenSSH_for_Windows_9.5", Vendor: "Private MAC", Hostname: "DESKTOP-4F2K9QX"}, Windows, "", High},
		{"generic openssh", Signals{Banner: "SSH-2.0-OpenSSH_9.8", TTL: 64}, Linux, "or macOS", Low},
		{"nothing", Signals{}, Unknown, "", None},
		{"ttl only", Signals{TTL: 64}, Unknown, "Unix-like", Low},
		{"windows by ttl only", Signals{TTL: 128}, Windows, "", Low},
		{"apple without ssh", Signals{Vendor: "Apple", TTL: 64}, MacOS, "or iOS", High},
		{"iphone", Signals{Vendor: "Apple", Hostname: "Ray-iPhone", TTL: 64}, IOS, "", High},
		{"ipad private mac", Signals{Vendor: "Private MAC", Hostname: "iPad", TTL: 64}, IOS, "", High},
		{"macbook without ssh", Signals{Vendor: "Private MAC", Hostname: "Rays-MacBook-Air.local"}, MacOS, "", Low},
		{"android tablet", Signals{Vendor: "Private MAC", Hostname: "Ray-s-Tab-S9-Ultra", TTL: 64}, Android, "", High},
		{"nmap wins", Signals{Banner: "SSH-2.0-OpenSSH_9.8", NmapOS: "Apple macOS 14 (Sonoma)"}, MacOS, "", High},
		{"arch word not substring", Signals{Banner: "SSH-2.0-OpenSSH_9.8 search"}, Linux, "or macOS", Low},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Classify(tt.sig)
			if got.OS != tt.wantOS || got.Detail != tt.wantDet || got.Confidence != tt.wantConf {
				t.Errorf("Classify() = %s/%q/%s, want %s/%q/%s (reasons %v)",
					got.OS, got.Detail, got.Confidence, tt.wantOS, tt.wantDet, tt.wantConf, got.Reasons)
			}
		})
	}
}

func TestBannerSoftware(t *testing.T) {
	cases := map[string]string{
		"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r": "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
		"SSH-1.99-Cisco-1.25":                        "Cisco-1.25",
		"":                                           "",
	}
	for in, want := range cases {
		if got := BannerSoftware(in); got != want {
			t.Errorf("BannerSoftware(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVendor(t *testing.T) {
	cases := map[string]string{
		"00:15:5d:01:02:03": "Microsoft",
		"b8:27:eb:aa:bb:cc": "Raspberry Pi",
		"00-03-93-11-22-33": "Apple",
		"da:a1:19:00:00:01": "Private MAC",
		"3a:00:00:00:00:00": "Private MAC",
		"xx":                "",
	}
	for mac, want := range cases {
		// System OUI databases may return longer names ("Raspberry Pi Foundation").
		if got := Vendor(mac); !strings.HasPrefix(got, want) || (want == "" && got != "") {
			t.Errorf("Vendor(%q) = %q, want %q", mac, got, want)
		}
	}
}

func TestLoadOUIFileFormats(t *testing.T) {
	dir := t.TempDir()
	nmap := dir + "/nmap"
	ieee := dir + "/ieee"
	writeFile(t, nmap, "# comment\n000393 Apple\n00155D Microsoft\n")
	writeFile(t, ieee, "00-03-93   (hex)\t\tApple, Inc.\n000393     (base 16)\t\tApple, Inc.\n")

	m := map[string]string{}
	if n := loadOUIFile(nmap, m); n != 2 || m["00155D"] != "Microsoft" {
		t.Errorf("nmap format: n=%d m=%v", n, m)
	}
	m = map[string]string{}
	if n := loadOUIFile(ieee, m); n != 1 || m["000393"] != "Apple" {
		t.Errorf("ieee format: n=%d m=%v", n, m)
	}
}
