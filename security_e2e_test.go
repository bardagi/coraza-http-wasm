//go:build e2e

package main_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/http-wasm/http-wasm-host-go/handler"
	nethttp "github.com/http-wasm/http-wasm-host-go/handler/nethttp"
	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/wazero"
)

func securityHandler(t *testing.T, cache wazero.CompilationCache, directives string, next http.Handler) http.Handler {
	t.Helper()
	ctx := context.Background()
	mw, err := nethttp.NewMiddleware(ctx, guest,
		handler.Runtime(func(ctx context.Context) (wazero.Runtime, error) {
			return wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCompilationCache(cache)), nil
		}),
		handler.GuestConfig([]byte(fmt.Sprintf(`{"directives":[%q]}`, directives))),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, mw.Close(ctx)) })
	return mw.NewHandler(ctx, next)
}

func assertBlockedResponse(t *testing.T, resp *http.Response, body []byte) {
	t.Helper()
	require.Equal(t, "Request blocked\n", string(body))
	require.Equal(t, int64(len(body)), resp.ContentLength)
	require.Equal(t, "text/plain; charset=utf-8", resp.Header.Get("Content-Type"))
	require.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	for _, name := range []string{"X-Secret", "Set-Cookie", "Content-Encoding", "Etag", "Location", "Trailer"} {
		require.Empty(t, resp.Header.Values(name), name)
	}
}

const responseInspection = `SecRuleEngine On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain
`

func TestE2ESecurityBlocking(t *testing.T) {
	cache := wazero.NewCompilationCache()
	t.Cleanup(func() { require.NoError(t, cache.Close(context.Background())) })
	for _, tc := range []struct {
		name, rules    string
		status         int
		requestBlocked bool
	}{
		{"phase 3", `SecRule RESPONSE_HEADERS:X-Secret "@streq upstream-secret" "id:1,phase:3,deny,status:451"`, 451, false},
		{"phase 4", `SecRule RESPONSE_BODY "@contains upstream-secret" "id:1,phase:4,deny,status:409"`, 409, false},
		{"phase 4 fallback", `SecRule RESPONSE_BODY "@contains upstream-secret" "id:1,phase:4,drop"`, 403, false},
		{"response limit", "SecResponseBodyLimit 8\nSecResponseBodyLimitAction Reject", 413, false},
		{"request limit", "SecRequestBodyAccess On\nSecRequestBodyLimit 8\nSecRequestBodyLimitAction Reject", 413, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			h := securityHandler(t, cache, responseInspection+tc.rules, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "text/plain")
				w.Header().Set("Content-Encoding", "identity")
				w.Header().Set("X-Secret", "upstream-secret")
				w.Header().Add("Set-Cookie", "secret=session")
				w.Header().Set("Etag", "secret-tag")
				w.Header().Set("Location", "/secret")
				body := "upstream-secret response content"
				if r.URL.Path == "/sized" {
					w.Header().Set("Content-Length", strconv.Itoa(len(body)))
				}
				_, _ = io.WriteString(w, body)
			}))
			// Exercise both the host buffer directly and an actual HTTP connection.
			for _, path := range []string{"/sized", "/unsized"} {
				rec := httptest.NewRecorder()
				req := httptest.NewRequest("POST", path, strings.NewReader("large request body"))
				h.ServeHTTP(rec, req)
				resp := rec.Result()
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				require.NoError(t, resp.Body.Close())
				require.Equal(t, tc.status, resp.StatusCode)
				assertBlockedResponse(t, resp, body)
			}
			ts := httptest.NewServer(h)
			defer ts.Close()
			resp, err := ts.Client().Post(ts.URL+"/sized", "text/plain", strings.NewReader("large request body"))
			require.NoError(t, err)
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.Equal(t, tc.status, resp.StatusCode)
			assertBlockedResponse(t, resp, body)
			if tc.requestBlocked {
				require.Zero(t, calls.Load())
			} else {
				require.Equal(t, int32(3), calls.Load())
			}
		})
	}
}

func TestE2ESecurityAllowedBodies(t *testing.T) {
	cache := wazero.NewCompilationCache()
	t.Cleanup(func() { require.NoError(t, cache.Close(context.Background())) })
	for _, mode := range []struct{ name, directives string }{
		{"full", "SecRequestBodyAccess On"},
		{"partial", "SecRequestBodyAccess On\nSecRequestBodyLimit 8\nSecRequestBodyLimitAction ProcessPartial"},
		{"disabled", "SecRequestBodyAccess Off"},
	} {
		t.Run(mode.name, func(t *testing.T) {
			h := securityHandler(t, cache, responseInspection+mode.directives+`
SecRule REQUEST_BODY "@contains forbidden" "id:1,phase:2,deny"
SecRule RESPONSE_BODY "@contains forbidden" "id:2,phase:4,deny"`, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.Header().Add("Set-Cookie", "a=1")
				w.Header().Add("Set-Cookie", "b=2")
				_, _ = io.Copy(w, r.Body)
			}))
			ts := httptest.NewServer(h)
			defer ts.Close()
			for _, chunked := range []bool{false, true} {
				for _, payload := range []string{"", "hello", strings.Repeat("body bytes ", 10000)} {
					t.Run(fmt.Sprintf("chunked=%t/bytes=%d", chunked, len(payload)), func(t *testing.T) {
						req, err := http.NewRequest("POST", ts.URL, strings.NewReader(payload))
						require.NoError(t, err)
						req.Header.Set("Content-Type", "text/plain")
						if chunked {
							req.ContentLength = -1
						}
						resp, err := ts.Client().Do(req)
						require.NoError(t, err)
						defer resp.Body.Close()
						body, err := io.ReadAll(resp.Body)
						require.NoError(t, err)
						require.Equal(t, http.StatusOK, resp.StatusCode)
						require.Equal(t, len(payload), len(body), "forwarded body length")
						require.Equal(t, payload, string(body))
						require.Equal(t, []string{"a=1", "b=2"}, resp.Header.Values("Set-Cookie"))
					})
				}
			}
		})
	}
}

func TestE2ESecurityRuleInputs(t *testing.T) {
	cache := wazero.NewCompilationCache()
	t.Cleanup(func() { require.NoError(t, cache.Close(context.Background())) })
	h := securityHandler(t, cache, `SecRuleEngine On
SecRule &REQUEST_HEADERS:Host "!@eq 1" "id:1,phase:1,deny,status:410"
SecRule &REQUEST_HEADERS:X-Repeat "!@eq 2" "id:2,phase:1,deny,status:411"
SecRule REQUEST_HEADERS:X-Repeat "@streq malicious" "id:3,phase:1,deny,status:412"
SecRule REMOTE_ADDR "!@ipMatch 2001:db8::1" "id:4,phase:1,deny,status:413"
SecRule &RESPONSE_HEADERS:Set-Cookie "!@eq 2" "id:5,phase:3,deny,status:414"
SecRule RESPONSE_HEADERS:Set-Cookie "@streq secret=1" "id:6,phase:3,deny,status:415"`, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "a=1")
		if r.URL.Path == "/secret" {
			w.Header().Add("Set-Cookie", "secret=1")
		} else {
			w.Header().Add("Set-Cookie", "b=2")
		}
		_, _ = io.WriteString(w, "allowed")
	}))
	for _, tc := range []struct {
		path, value string
		status      int
	}{
		{"/", "second", 200}, {"/", "malicious", 412}, {"/secret", "second", 415},
	} {
		t.Run(tc.path+tc.value, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com"+tc.path, nil)
			req.RemoteAddr = "[2001:db8::1]:12345"
			req.Header.Add("X-Repeat", "first")
			req.Header.Add("X-Repeat", tc.value)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			require.Equal(t, tc.status, rec.Code)
			if tc.status == 200 {
				require.Equal(t, "allowed", rec.Body.String())
			} else {
				require.Equal(t, "Request blocked\n", rec.Body.String())
			}
		})
	}
}

func TestE2ESecurityConfiguration(t *testing.T) {
	ctx := context.Background()
	cache := wazero.NewCompilationCache()
	t.Cleanup(func() { require.NoError(t, cache.Close(ctx)) })
	for _, config := range []string{
		``, `{}`, `{"directives":[]}`, `{"directives":[" \n"]}`,
		`{"directives":["SecRuleEngine On",42]}`,
		`{"directives":["SecRuleEngine On"],"includeCRS":"true"}`,
		`{"directives":["SecRuleEngine On"]} trailing`,
	} {
		t.Run(config, func(t *testing.T) {
			mw, err := nethttp.NewMiddleware(ctx, guest,
				handler.Runtime(func(ctx context.Context) (wazero.Runtime, error) {
					return wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCompilationCache(cache)), nil
				}), handler.GuestConfig([]byte(config)),
			)
			if mw != nil {
				require.NoError(t, mw.Close(ctx))
			}
			require.Error(t, err, "invalid configuration must fail guest initialization")
		})
	}
	h := securityHandler(t, cache, "SecRuleEngine Off", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "explicit pass-through")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "explicit pass-through", rec.Body.String())
}

func TestE2ESecurityLongRequestLine(t *testing.T) {
	cache := wazero.NewCompilationCache()
	t.Cleanup(func() { require.NoError(t, cache.Close(context.Background())) })
	h := securityHandler(t, cache, `SecRuleEngine On
SecRule REQUEST_URI "@endsWith attack" "id:1,phase:1,deny,status:418"
SecRule REQUEST_METHOD "@endsWith attack" "id:2,phase:1,deny,status:419"`, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "allowed")
	}))
	// Longer than the guest SDK's 2KiB read buffer.
	long := strings.Repeat("a", 4096)
	for _, tc := range []struct {
		name, method, uri string
		status            int
	}{
		{"uri", "GET", "/?q=" + long, 200},
		{"uri inspected", "GET", "/?q=" + long + "attack", 418},
		{"method", "X" + strings.ToUpper(long), "/", 200},
		{"method inspected", "X" + long + "attack", "/", 419},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(tc.method, "http://example.com"+tc.uri, nil))
			require.Equal(t, tc.status, rec.Code, rec.Body.String())
		})
	}
}
