package scan

import (
	"context"
	"encoding/xml"
	"os/exec"
	"strconv"
	"time"
)

type nmapRun struct {
	Hosts []struct {
		Addresses []struct {
			Addr     string `xml:"addr,attr"`
			AddrType string `xml:"addrtype,attr"`
		} `xml:"address"`
		OSMatches []struct {
			Name     string `xml:"name,attr"`
			Accuracy int    `xml:"accuracy,attr"`
		} `xml:"os>osmatch"`
	} `xml:"host"`
}

// nmapDetect runs "nmap -O" against the given hosts and returns IP -> best OS match.
// It needs root: with useSudo it runs "sudo -n nmap", relying on credentials
// cached before the scan so it never prompts. Returns nil if nmap is missing or fails.
func nmapDetect(ctx context.Context, ips []string, port int, useSudo bool) map[string]string {
	if len(ips) == 0 {
		return nil
	}
	if _, err := exec.LookPath("nmap"); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	// -T4 and a single OS detection try keep a LAN run short; the hosts are
	// already known to be up (-Pn) and nearby.
	args := append([]string{"-O", "--osscan-guess", "--max-os-tries", "1", "-T4", "-Pn",
		"-p", strconv.Itoa(port), "-oX", "-"}, ips...)
	cmd := exec.CommandContext(ctx, "nmap", args...)
	if useSudo {
		cmd = exec.CommandContext(ctx, "sudo", append([]string{"-n", "nmap"}, args...)...)
	}
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	return parseNmapXML(out)
}

func parseNmapXML(data []byte) map[string]string {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil
	}
	res := map[string]string{}
	for _, h := range run.Hosts {
		ip := ""
		for _, a := range h.Addresses {
			if a.AddrType == "ipv4" {
				ip = a.Addr
			}
		}
		if ip == "" || len(h.OSMatches) == 0 {
			continue
		}
		best := h.OSMatches[0]
		for _, m := range h.OSMatches[1:] {
			if m.Accuracy > best.Accuracy {
				best = m
			}
		}
		res[ip] = best.Name
	}
	return res
}
