package main

import (
	"testing"
	"time"

	"magicssh/internal/config"
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
