package tls

import (
	"errors"
	"fmt"

	"bytes"
	"io"

	stdtls "crypto/tls"
	"net"

	"time"
)

// errHelloParsed aborts the fake handshake once the ClientHello is read.
var errHelloParsed = errors.New("client hello parsed")

// peekClientHello reads the ClientHello from the connection, returning the
// SNI value and the exact bytes consumed so they can be replayed to the
// backend. Nothing is written back to the client: the handshake is run
// against a read-only shim purely to reuse the standard library's parser.
func peekClientHello(conn net.Conn) (string, []byte, error) {
	var recorded bytes.Buffer

	sni := ""

	config := &stdtls.Config{
		GetConfigForClient: func(hello *stdtls.ClientHelloInfo) (*stdtls.Config, error) {
			sni = hello.ServerName

			return nil, errHelloParsed
		},
	}

	err := stdtls.Server(readOnlyConn{reader: io.TeeReader(conn, &recorded)}, config).
		Handshake()

	if sni == "" && !errors.Is(err, errHelloParsed) {
		return "", nil, fmt.Errorf("invalid ClientHello: %w", err)
	}

	return sni, recorded.Bytes(), nil
}

// readOnlyConn exposes the downstream bytes to the TLS parser while
// discarding anything it tries to write, so no alert ever reaches the
// client before routing decided the connection's fate.
type readOnlyConn struct {
	reader io.Reader
}

var _ net.Conn = readOnlyConn{}

func (c readOnlyConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c readOnlyConn) Write(p []byte) (int, error) { return 0, io.ErrClosedPipe }
func (c readOnlyConn) Close() error                { return nil }

func (c readOnlyConn) LocalAddr() net.Addr  { return nil }
func (c readOnlyConn) RemoteAddr() net.Addr { return nil }

func (c readOnlyConn) SetDeadline(time.Time) error      { return nil }
func (c readOnlyConn) SetReadDeadline(time.Time) error  { return nil }
func (c readOnlyConn) SetWriteDeadline(time.Time) error { return nil }
