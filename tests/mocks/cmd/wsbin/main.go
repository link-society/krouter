// wsbin is a WebSocket echo service for the krouter test suites
// (docs/spec/traffic.md Protocol handling): every accepted connection
// first receives one text message holding the pod identity, then every
// received message is echoed back unchanged until the peer closes.
//
// GET /healthz answers 200 without upgrading, for readiness probes.
package main

import (
	"log"

	"os"

	"net/http"

	"github.com/coder/websocket"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			// Origin enforcement is not under test.
			InsecureSkipVerify: true,
		})
		if err != nil {
			log.Printf("accept from %s: %v", r.RemoteAddr, err)
			return
		}
		defer conn.CloseNow()

		ctx := r.Context()

		greeting := []byte("wsbin " + hostname)
		if err := conn.Write(ctx, websocket.MessageText, greeting); err != nil {
			return
		}

		for {
			kind, payload, err := conn.Read(ctx)
			if err != nil {
				return
			}

			if err := conn.Write(ctx, kind, payload); err != nil {
				return
			}
		}
	})

	log.Printf("wsbin %s listening on :%s", hostname, port)

	server := &http.Server{Addr: ":" + port, Handler: mux}
	log.Fatal(server.ListenAndServe())
}
