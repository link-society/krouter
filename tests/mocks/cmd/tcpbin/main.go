// Command tcpbin is a small TCP echo backend in the spirit of tcpbin.com,
// used by the demo topology (tests/config/mocks/manifest.yml). On connect
// it writes a single greeting line containing the serving pod's hostname
// (so load balancing is observable), then echoes every received byte back
// to the client.
package main

import (
	"errors"
	"fmt"
	"log"

	"os"

	"io"

	"net"

	"time"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "4242"
	}

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("hostname: %v", err)
	}

	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	log.Printf("tcpbin %s listening on :%s", hostname, port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}

			// Transient accept errors (e.g. exhausted descriptors) must
			// not kill the backend.
			log.Printf("accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		go handle(conn, hostname)
	}
}

func handle(conn net.Conn, hostname string) {
	defer conn.Close()

	log.Printf("connection from %s", conn.RemoteAddr())

	if _, err := fmt.Fprintf(conn, "%s\n", hostname); err != nil {
		return
	}

	io.Copy(conn, conn)
}
