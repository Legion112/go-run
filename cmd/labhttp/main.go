package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
)

func main() {
	listen := flag.String("listen", ":8080", "listen address")
	body := flag.String("body", "", "response body for GET / and GET /id")
	flag.Parse()
	if *body == "" {
		fmt.Fprintln(os.Stderr, "labhttp: -body is required")
		os.Exit(2)
	}

	mux := http.NewServeMux()
	h := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(*body))
	}
	mux.HandleFunc("/", h)
	mux.HandleFunc("/id", h)
	mux.HandleFunc("/peer", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		_, _ = w.Write([]byte(host))
	})

	log.Printf("labhttp listening on %s body=%q", *listen, *body)
	if err := http.ListenAndServe(*listen, mux); err != nil {
		log.Fatal(err)
	}
}
