package scan

import (
	"context"
	"errors"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

// hostKeyAlgorithms is fixed so the same key type is picked on every scan,
// in the order OpenSSH prefers when it has no known_hosts entry.
var hostKeyAlgorithms = []string{
	ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256,
}

var errGotKey = errors.New("host key received")

// hostKey returns the server's host key as "<type> SHA256:<fingerprint>". It
// runs only the key exchange and aborts before authentication.
func hostKey(ctx context.Context, ip string, port int, timeout time.Duration) string {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	var fp string
	ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:              "magicssh",
		HostKeyAlgorithms: hostKeyAlgorithms,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fp = key.Type() + " " + ssh.FingerprintSHA256(key)
			return errGotKey
		},
	})
	return fp
}
