// Command httpbin is a small HTTP request-inspection backend in the spirit
// of httpbin.org, used by the demo topology (tests/config/mocks/manifest.yml).
// Every response includes the serving pod's hostname so load balancing is
// observable.
//
// Endpoints:
//
//	GET  /                  index of endpoints
//	ANY  /hostname          {"hostname": ...} (also used as readiness probe)
//	ANY  /headers           request headers
//	ANY  /status/{code}     respond with the given status code
//	ANY  /delay/{seconds}   sleep, then respond like /anything
//	ANY  /anything[/...]    echo method, path, query, headers and body
//	ANY  /graphql           minimal GraphQL introspection stub
package main

import (
	"log"

	"os"

	"strconv"

	"encoding/json"
	"io"

	"net/http"

	"time"
)

const maxBodyBytes = 1 << 20 // echoed request bodies are capped at 1 MiB

const maxDelaySeconds = 60

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("hostname: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/{$}", index)
	mux.HandleFunc("/hostname", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"hostname": hostname})
	})
	mux.HandleFunc("/headers", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"hostname": hostname,
			"headers":  r.Header,
		})
	})
	mux.HandleFunc("/status/{code}", status)
	mux.HandleFunc("/delay/{seconds}", delay(hostname))
	mux.HandleFunc("/anything", anything(hostname))
	mux.HandleFunc("/anything/{rest...}", anything(hostname))
	mux.HandleFunc("/graphql", graphql)

	log.Printf("httpbin %s listening on :%s", hostname, port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

func index(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"service": "httpbin",
		"endpoints": []string{
			"/hostname",
			"/headers",
			"/status/{code}",
			"/delay/{seconds}",
			"/anything[/...]",
			"/graphql",
		},
	})
}

// graphql answers introspection probes with the canonical
// {"data": {"__typename": "Query"}} shape that GraphQL scanners look for,
// so tools like gotestwaf detect a live GraphQL endpoint. Any WAF filter on
// the route still runs before the request reaches this stub, so attack
// payloads are evaluated regardless of the static answer.
func graphql(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"data": map[string]any{"__typename": "Query"},
	})
}

func status(w http.ResponseWriter, r *http.Request) {
	code, err := strconv.Atoi(r.PathValue("code"))
	if err != nil || code < 100 || code > 599 {
		http.Error(w, "invalid status code", http.StatusBadRequest)
		return
	}

	w.WriteHeader(code)
}

func delay(hostname string) http.HandlerFunc {
	echo := anything(hostname)

	return func(w http.ResponseWriter, r *http.Request) {
		seconds, err := strconv.Atoi(r.PathValue("seconds"))
		if err != nil || seconds < 0 || seconds > maxDelaySeconds {
			http.Error(w, "invalid delay", http.StatusBadRequest)
			return
		}

		select {
		case <-time.After(time.Duration(seconds) * time.Second):
		case <-r.Context().Done():
			return
		}

		echo(w, r)
	}
}

func anything(hostname string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"hostname": hostname,
			"method":   r.Method,
			"proto":    r.Proto,
			"host":     r.Host,
			"path":     r.URL.Path,
			"query":    r.URL.Query(),
			"headers":  r.Header,
			"body":     string(body),
		})
	}
}

func writeJSON(w http.ResponseWriter, code int, payload any) {
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		http.Error(w, "encode response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(append(data, '\n'))
}
