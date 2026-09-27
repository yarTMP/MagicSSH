package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"magicssh/internal/config"
	"magicssh/internal/scan"
	"magicssh/internal/sshcheck"
)

func TestScanOptionsValidation(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	store, _ := config.Load()
	ok := cliFlags{subnet: "192.168.1.0/24", port: 22, timeout: 500 * time.Millisecond, workers: 256}
	if _, err := scanOptions(ok, store); err != nil {
		t.Fatalf("valid flags rejected: %v", err)
	}
	for name, mod := range map[string]func(*cliFlags){
		"port 0":        func(f *cliFlags) { f.port = 0 },
		"port too big":  func(f *cliFlags) { f.port = 70000 },
		"zero timeout":  func(f *cliFlags) { f.timeout = 0 },
		"huge timeout":  func(f *cliFlags) { f.timeout = time.Minute },
		"no workers":    func(f *cliFlags) { f.workers = 0 },
		"many workers":  func(f *cliFlags) { f.workers = maxWorkers + 1 },
		"public subnet": func(f *cliFlags) { f.subnet = "8.8.8.0/24" },
	} {
		f := ok
		mod(&f)
		if _, err := scanOptions(f, store); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	pub := ok
	pub.subnet, pub.allowPublic = "8.8.8.0/24", true
	if _, err := scanOptions(pub, store); err != nil {
		t.Errorf("--allow-public: %v", err)
	}
}

func TestCheckKnownHostsClearsStaleStatus(t *testing.T) {
	hosts := []scan.Host{
		{IP: "10.0.0.2", SSH: true, KnownHosts: "mismatch"},
		{IP: "10.0.0.3", SSH: true, KnownHosts: "mismatch"},
		{IP: "10.0.0.4", KnownHosts: "mismatch"}, // SSH closed since
	}
	checkKnownHosts(hosts, func(_ context.Context, h scan.Host) sshcheck.Result {
		if h.IP == "10.0.0.2" {
			return sshcheck.Result{Err: errors.New("timeout")}
		}
		return sshcheck.Result{Status: sshcheck.OK}
	})
	if hosts[0].KnownHosts != "" || hosts[1].KnownHosts != "ok" || hosts[2].KnownHosts != "" {
		t.Errorf("statuses = %q %q %q", hosts[0].KnownHosts, hosts[1].KnownHosts, hosts[2].KnownHosts)
	}
}
