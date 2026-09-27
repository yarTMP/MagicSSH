// Package config persists the last scan, per-host usernames and SSH host keys
// in $XDG_CONFIG_HOME/magicssh/hosts.json (default ~/.config/magicssh/hosts.json).
// Under sudo the invoking user's file is used and stays owned by them.
package config

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"magicssh/internal/scan"
)

type Store struct {
	Subnet   string            `json:"subnet,omitempty"`
	ScanTime time.Time         `json:"scan_time,omitempty"`
	Hosts    []scan.Host       `json:"hosts,omitempty"`
	Users    map[string]string `json:"users,omitempty"`     // device ID (see deviceID) -> username
	HostKeys map[string]string `json:"host_keys,omitempty"` // device ID -> SSH host key fingerprint

	path     string
	uid, gid int // owner to give saved files; -1 keeps the current one
}

// SudoUser returns the account that invoked sudo, or nil when not running as
// root through sudo.
func SudoUser() *user.User {
	if os.Geteuid() != 0 || os.Getenv("SUDO_USER") == "" {
		return nil
	}
	u, err := user.Lookup(os.Getenv("SUDO_USER"))
	if err != nil || u.Uid == "0" {
		return nil
	}
	return u
}

func Path() (string, error) {
	if u := SudoUser(); u != nil {
		// sudo points $HOME at root; keep using the invoking user's cache.
		return filepath.Join(u.HomeDir, ".config", "magicssh", "hosts.json"), nil
	}
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "magicssh", "hosts.json"), nil
}

// Load reads the store; a missing file yields an empty store.
func Load() (*Store, error) {
	p, err := Path()
	if err != nil {
		return nil, err
	}
	s := &Store{path: p, uid: -1, gid: -1}
	if u := SudoUser(); u != nil {
		s.uid, _ = strconv.Atoi(u.Uid)
		s.gid, _ = strconv.Atoi(u.Gid)
	}
	defer func() {
		if s.Users == nil {
			s.Users = map[string]string{}
		}
		if s.HostKeys == nil {
			s.HostKeys = map[string]string{}
		}
	}()
	data, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, err
	}
	// The cache feeds the ssh command line and the terminal; don't trust it blindly.
	hosts := s.Hosts[:0]
	for _, h := range s.Hosts {
		if h.Sanitize() {
			hosts = append(hosts, h)
		}
	}
	s.Hosts = hosts
	for k, u := range s.Users {
		s.Users[k] = scan.Clean(u, 64)
	}
	for k, fp := range s.HostKeys {
		s.HostKeys[k] = scan.Clean(fp, 128)
	}
	return s, nil
}

func (s *Store) Save() error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if s.uid >= 0 {
		os.Lchown(filepath.Dir(dir), s.uid, s.gid) // ~/.config, if we just created it
		if err := os.Lchown(dir, s.uid, s.gid); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	// A unique temp file, so two instances saving at once can't write into the
	// same file; the rename then makes each save atomic (last one wins).
	f, err := os.CreateTemp(dir, "hosts-*.json.tmp") // created with mode 0600
	if err != nil {
		return err
	}
	tmp := f.Name()
	if err := writeTemp(f, data, s.uid, s.gid); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func writeTemp(f *os.File, data []byte, uid, gid int) error {
	_, err := f.Write(data)
	if err == nil && uid >= 0 {
		err = f.Chown(uid, gid)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// deviceID keys per-device data by MAC address, which survives DHCP address
// changes. Only devices without a known MAC fall back to their IP, so a device
// never inherits data from whatever used its address before.
func deviceID(h scan.Host) string {
	if h.MAC != "" {
		return "mac:" + strings.ToLower(h.MAC)
	}
	return "ip:" + h.IP
}

// User returns the remembered username for a host.
func (s *Store) User(h scan.Host) string {
	return s.Users[deviceID(h)]
}

func (s *Store) SetUser(h scan.Host, user string) {
	s.Users[deviceID(h)] = user
}

// CheckHostKeys compares each host's SSH host key with the one remembered for
// that device. Keys of devices seen for the first time are remembered; a
// different key sets KeyChanged and is not stored, since it may be another
// machine answering on that address. See TrustHostKey.
func (s *Store) CheckHostKeys(hosts []scan.Host) {
	for i := range hosts {
		h := &hosts[i]
		h.KeyChanged = false
		if h.HostKey == "" {
			continue
		}
		switch known := s.HostKeys[deviceID(*h)]; {
		case known == "":
			s.HostKeys[deviceID(*h)] = h.HostKey
		case known != h.HostKey:
			h.KeyChanged = true
		}
	}
}

// TrustHostKey accepts h's current host key, e.g. after the user confirmed a change.
func (s *Store) TrustHostKey(h *scan.Host) {
	if h.HostKey != "" {
		s.HostKeys[deviceID(*h)] = h.HostKey
		h.KeyChanged = false
	}
}

// KnownHostKey returns the host key remembered for h's device, if any.
func (s *Store) KnownHostKey(h scan.Host) string {
	return s.HostKeys[deviceID(h)]
}
