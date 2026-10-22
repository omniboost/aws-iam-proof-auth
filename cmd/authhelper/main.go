// Command authhelper runs a small loopback-only HTTP helper that returns a
// fresh AWS-IAM-PROOF authentication header. It is intended to be called from a
// Postman pre-request script so requests can be authenticated automatically.
//
// Usage:
//
//	go run github.com/omniboost/aws-iam-proof-auth/cmd/authhelper@latest            # serve on 127.0.0.1:7070
//	go run github.com/omniboost/aws-iam-proof-auth/cmd/authhelper@latest -addr :7171
//	go run github.com/omniboost/aws-iam-proof-auth/cmd/authhelper@latest -print     # print one header and exit
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	iamproof "github.com/omniboost/aws-iam-proof-auth"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:7070", "address to listen on (loopback only)")
	printOnce := flag.Bool("print", false, "print a single header to stdout and exit")
	flag.Parse()

	if *printOnce {
		header, err := iamproof.Header(context.Background())
		if err != nil {
			log.Fatalf("failed to generate header: %v", err)
		}
		fmt.Println(header)
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", handleHeader)

	server := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("auth helper listening on http://%s", *addr)
	log.Fatal(server.ListenAndServe())
}

func handleHeader(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	header, err := iamproof.Header(ctx)
	if err != nil {
		log.Printf("failed to generate header: %v", err)
		http.Error(w, "failed to generate authentication header", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"authorization": header}); err != nil {
		log.Printf("failed to encode response: %v", err)
	}
}
