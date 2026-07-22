// Command udpbin is a small UDP echo backend used by the demo topology
// (tests/config/mocks/manifest.yml). Every datagram is answered with the
// serving pod's hostname followed by the original payload, so both
// connectivity and load balancing are observable.
package main

import (
	"log"

	"os"

	"net"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "5354"
	}

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("hostname: %v", err)
	}

	pc, err := net.ListenPacket("udp", ":"+port)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	log.Printf("udpbin %s listening on :%s", hostname, port)

	buf := make([]byte, 64*1024)
	prefix := []byte(hostname + " ")

	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			log.Fatalf("read: %v", err)
		}

		reply := append(append([]byte{}, prefix...), buf[:n]...)
		if _, err := pc.WriteTo(reply, addr); err != nil {
			log.Printf("write to %s: %v", addr, err)
		}
	}
}
