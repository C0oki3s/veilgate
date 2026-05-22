package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"testing"

	"github.com/C0oki3s/veilgate/internal/proxy"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func TestH2CHandlerAcceptsPriorKnowledgeHTTP2(t *testing.T) {
	handler := h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("ProtoMajor = %d, want 2", r.ProtoMajor)
		}
		w.WriteHeader(http.StatusOK)
	}), &http2.Server{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: handler}
	go func() {
		_ = srv.Serve(proxy.NewFramingGuardListener(ln))
	}()
	t.Cleanup(func() {
		_ = srv.Close()
	})

	tr := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(_ context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return net.Dial(network, addr)
		},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get("http://" + ln.Addr().String())
	if err != nil {
		t.Fatalf("h2c GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}
