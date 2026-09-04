package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/http-wasm/http-wasm-host-go/handler"
	wasm "github.com/http-wasm/http-wasm-host-go/handler/nethttp"
)

// Benchmarks for the guest's per-request hot path.
//
// Caveat when reading the results: Go's -benchmem counters (B/op, allocs/op)
// only see allocations made on the host side of the ABI. The guest has its own
// heap inside its linear memory and is invisible to them, so ns/op is the
// signal that matters here; guest allocations show up as time, not as bytes.
//
// The guest module is the one embedded by example_test.go, so `mage build` has
// to have run first.

// benchHandler stands in for the upstream application. It is deliberately
// trivial so the numbers reflect the guest, not the handler.
func benchHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ok"))
}

// newBenchGuest compiles the guest once with the given host config.
func newBenchGuest(b *testing.B, config string) http.Handler {
	b.Helper()

	ctx := context.Background()
	mw, err := wasm.NewMiddleware(ctx, []byte(guest), handler.GuestConfig([]byte(config)))
	if err != nil {
		b.Fatalf("failed to create middleware: %v", err)
	}
	b.Cleanup(func() { _ = mw.Close(ctx) })

	return mw.NewHandler(ctx, http.HandlerFunc(benchHandler))
}

// hostConfig builds a guest config from a directive block.
func hostConfig(includeCRS bool, directives string) string {
	return fmt.Sprintf("{\"includeCRS\": %t, \"directives\": [ %q ]}", includeCRS, directives)
}

func BenchmarkHandle(b *testing.B) {
	body := strings.Repeat("a", 512)

	benchmarks := []struct {
		name   string
		config string
		newReq func() *http.Request
	}{
		{
			// Baseline: engine on, a single rule that never matches, no CRS.
			name: "bare",
			config: hostConfig(false, `
SecRuleEngine On
SecRule REQUEST_URI "@streq /never-matches" "id:1,phase:1,deny,status:403"`),
			newReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/anything", nil)
			},
		},
		{
			// A realistic ruleset: the embedded Core Rule Set.
			name: "crs",
			config: hostConfig(true, `
SecRuleEngine On
Include @crs-setup.conf.example
Include @owasp_crs/*.conf`),
			newReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/anything?q=hello", nil)
			},
		},
		{
			// Every request matches a logging rule, exercising errorCb.
			name: "matching",
			config: hostConfig(false, `
SecRuleEngine On
SecRule REQUEST_URI "@rx ." "id:1,phase:1,pass,log,severity:WARNING,msg:'always matches'"`),
			newReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/anything", nil)
			},
		},
		{
			// A body small enough that a 32KiB copy buffer is pure waste.
			name: "body",
			config: hostConfig(false, `
SecRuleEngine On
SecRequestBodyAccess On
SecRule REQUEST_BODY "@contains never-matches" "id:1,phase:2,deny,status:403"`),
			newReq: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/anything", strings.NewReader(body))
				r.Header.Set("Content-Type", "text/plain")
				r.ContentLength = int64(len(body))
				return r
			},
		},
		{
			// Body access on, but nothing to read: the copy should not happen.
			name: "no-body",
			config: hostConfig(false, `
SecRuleEngine On
SecRequestBodyAccess On
SecRule REQUEST_BODY "@contains never-matches" "id:1,phase:2,deny,status:403"`),
			newReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/anything", nil)
			},
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			h := newBenchGuest(b, bm.config)

			// Fail fast rather than benchmarking a blocked request.
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, bm.newReq())
			if rec.Code != http.StatusOK {
				b.Fatalf("expected the request to pass, got status %d", rec.Code)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				h.ServeHTTP(httptest.NewRecorder(), bm.newReq())
			}
		})
	}
}
