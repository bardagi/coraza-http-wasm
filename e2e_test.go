//go:build e2e
// +build e2e

package main_test

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/http-wasm/http-wasm-host-go/api"
	"github.com/http-wasm/http-wasm-host-go/handler"
	nethttp "github.com/http-wasm/http-wasm-host-go/handler/nethttp"
	"github.com/mccutchen/go-httpbin/v2/httpbin"
	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/wazero"
)

// testCtx is an arbitrary, non-default context. Non-nil also prevents linter errors.
var testCtx = context.WithValue(context.Background(), struct{}{}, "arbitrary")

//go:embed build/coraza-http-wasm.wasm
var guest []byte

const directives = `
	SecRuleEngine On
	SecResponseBodyAccess On
	SecResponseBodyMimeType application/json
	# Custom rule for Coraza config check (ensuring that these configs are used)
	SecRule &REQUEST_HEADERS:coraza-e2e "@eq 0" "id:100,phase:1,deny,status:424,log,msg:'Coraza E2E - Missing header'"
	# Custom rules for e2e testing
	SecRule REQUEST_URI "@streq /admin" "id:101,phase:1,t:lowercase,log,deny"
	SecRule REQUEST_BODY "@rx maliciouspayload" "id:102,phase:2,t:lowercase,log,deny"
	SecRule RESPONSE_HEADERS:pass "@rx leak" "id:103,phase:3,t:lowercase,log,deny"
	SecRule RESPONSE_BODY "@contains responsebodycode" "id:104,phase:4,t:lowercase,log,deny"
	# Custom rules mimicking the following CRS rules: 941100, 942100, 913100
	SecRule ARGS_NAMES|ARGS "@detectXSS" "id:9411,phase:2,t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,log,deny"
	SecRule ARGS_NAMES|ARGS "@detectSQLi" "id:9421,phase:2,t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,multiMatch,log,deny"
	SecRule REQUEST_HEADERS:User-Agent "@pm grabber masscan" "id:9131,phase:1,t:none,log,deny"
	SecRequestBodyAccess On
`

func TestE2E(t *testing.T) {
	var stdoutBuf, stderrBuf bytes.Buffer
	moduleConfig := wazero.NewModuleConfig().WithStdout(&stdoutBuf).WithStderr(&stderrBuf)

	// Configure and compile the WebAssembly guest binary.
	mw, err := nethttp.NewMiddleware(testCtx, guest,
		handler.Logger(testLogger{t}),
		handler.ModuleConfig(moduleConfig),
		handler.GuestConfig([]byte(fmt.Sprintf("{\"directives\": [ %q ]}", directives))),
	)
	if err != nil {
		t.Fatalf("failed to create middlware: %v", err)
	}
	defer mw.Close(testCtx)

	httpbin := httpbin.New()

	// Wrap the test handler with one implemented in WebAssembly.
	wrapped := mw.NewHandler(testCtx, httpbin)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.Handle("/status/200", httpbin) // Health check
	mux.Handle("/", wrapped)

	// Create the server with the WAF and the reverse proxy.
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Keep the upstream suite's scenarios locally: its runner requires empty
	// denial bodies, whereas this connector now returns a generic message.
	for _, tc := range []struct {
		name, method, path, body, userAgent string
		status                              int
		missingConfigHeader                 bool
	}{
		{name: "health", method: "GET", path: "/status/200", status: 200},
		{name: "configuration", method: "GET", path: "/", status: 424, missingConfigHeader: true},
		{name: "allowed", method: "GET", path: "/?arg=arg_1", status: 200},
		{name: "URI deny", method: "GET", path: "/admin", status: 403},
		{name: "allowed body", method: "POST", path: "/anything", body: "This is a legit payload", status: 200},
		{name: "request body deny", method: "POST", path: "/anything", body: "maliciouspayload", status: 403},
		{name: "response header deny", method: "GET", path: "/response-headers?pass=leak", status: 403},
		{name: "response body deny", method: "POST", path: "/anything", body: "responsebodycode", status: 403},
		{name: "XSS", method: "GET", path: "/anything?arg=%3Cscript%3Ealert(0)%3C/script%3E", status: 403},
		{name: "SQLi", method: "POST", path: "/anything", body: "1%27%20ORDER%20BY%203--%2B", status: 403},
		{name: "scanner", method: "GET", path: "/anything", userAgent: "Grabber/0.1 (X11; U; Linux i686; en-US; rv:1.7)", status: 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, ts.URL+tc.path, strings.NewReader(tc.body))
			require.NoError(t, err)
			if !tc.missingConfigHeader {
				req.Header.Set("coraza-e2e", "ok")
			}
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			if tc.userAgent != "" {
				req.Header.Set("User-Agent", tc.userAgent)
			}
			resp, err := ts.Client().Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.Equal(t, tc.status, resp.StatusCode)
			if tc.status != 200 {
				assertBlockedResponse(t, resp, body)
			}
		})
	}
}

// testLogger is a api.Logger implementation for testing purposes.
type testLogger struct{ t *testing.T }

var _ api.Logger = testLogger{}

func (l testLogger) IsEnabled(_ api.LogLevel) bool { return l.t != nil }

var levels = map[api.LogLevel]string{
	api.LogLevelDebug: "Debug",
	api.LogLevelInfo:  "Info",
	api.LogLevelWarn:  "Warn",
	api.LogLevelError: "Error",
	api.LogLevelNone:  "None",
}

func (l testLogger) Log(_ context.Context, lvl api.LogLevel, msg string) {
	l.t.Log("[" + levels[lvl] + "] " + msg)
}
