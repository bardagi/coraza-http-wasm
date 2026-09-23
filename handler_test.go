package main

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/http-wasm/http-wasm-guest-tinygo/handler/api"
	"github.com/stretchr/testify/require"
)

type testHeaders struct{ http.Header }

func (h testHeaders) Names() []string {
	names := make([]string, 0, len(h.Header))
	for name := range h.Header {
		names = append(names, name)
	}
	return names
}
func (h testHeaders) Get(name string) (string, bool) {
	values := h.Values(name)
	if len(values) == 0 {
		return "", false
	}
	return values[0], true
}
func (h testHeaders) GetAll(name string) []string { return h.Values(name) }
func (h testHeaders) Remove(name string)          { h.Del(name) }

type testRequest struct {
	api.Request
	headers testHeaders
	body    *fakeBody
}

func (r testRequest) Headers() api.Header      { return r.headers }
func (r testRequest) Body() api.Body           { return r.body }
func (testRequest) GetSourceAddr() string      { return "[2001:db8::1]:1234" }
func (testRequest) GetURI() string             { return "/test" }
func (testRequest) GetMethod() string          { return "POST" }
func (testRequest) GetProtocolVersion() string { return "HTTP/1.1" }

type responseBody struct {
	fakeBody
	written string
}

func (b *responseBody) WriteString(s string) { b.written += s }

type testResponse struct {
	api.Response
	headers testHeaders
	body    *responseBody
	status  uint32
}

func (r *testResponse) Headers() api.Header       { return r.headers }
func (r *testResponse) Body() api.Body            { return r.body }
func (r *testResponse) GetStatusCode() uint32     { return r.status }
func (r *testResponse) SetStatusCode(code uint32) { r.status = code }

type transactionWAF struct {
	coraza.WAF
	tx types.Transaction
}

func (w transactionWAF) NewTransaction() types.Transaction { return w.tx }

// Delegate normal processing to Coraza, injecting only the failure under test.
type trackedTransaction struct {
	types.Transaction
	failAt string
	events []string
}

func (tx *trackedTransaction) RequestBodyReader() (io.Reader, error) {
	if tx.failAt == "request restore" {
		return nil, errors.New("private request buffer failure")
	}
	return tx.Transaction.RequestBodyReader()
}

func (tx *trackedTransaction) ReadRequestBodyFrom(r io.Reader) (*types.Interruption, int, error) {
	if tx.failAt == "request read" {
		return nil, 0, errors.New("private request read failure")
	}
	return tx.Transaction.ReadRequestBodyFrom(r)
}
func (tx *trackedTransaction) ProcessRequestBody() (*types.Interruption, error) {
	if tx.failAt == "request process" {
		return nil, errors.New("private request process failure")
	}
	return tx.Transaction.ProcessRequestBody()
}
func (tx *trackedTransaction) ReadResponseBodyFrom(r io.Reader) (*types.Interruption, int, error) {
	if tx.failAt == "response read" {
		return nil, 0, errors.New("private response read failure")
	}
	return tx.Transaction.ReadResponseBodyFrom(r)
}
func (tx *trackedTransaction) ProcessResponseBody() (*types.Interruption, error) {
	if tx.failAt == "response process" {
		return nil, errors.New("private response process failure")
	}
	return tx.Transaction.ProcessResponseBody()
}
func (tx *trackedTransaction) ProcessLogging() {
	tx.events = append(tx.events, "log")
	tx.Transaction.ProcessLogging()
}
func (tx *trackedTransaction) Close() error {
	tx.events = append(tx.events, "close")
	return tx.Transaction.Close()
}

func setupTransaction(t *testing.T, directives string) (*trackedTransaction, testRequest, *testResponse) {
	t.Helper()
	w, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
	require.NoError(t, err)
	tx := &trackedTransaction{Transaction: w.NewTransaction()}
	oldWAF, oldTXs, oldCtx := waf, txs, lastReqCtx
	waf, txs, lastReqCtx = transactionWAF{tx: tx}, map[uint32]types.Transaction{}, 0
	t.Cleanup(func() {
		waf, txs, lastReqCtx = oldWAF, oldTXs, oldCtx
		if len(tx.events) == 0 || tx.events[len(tx.events)-1] != "close" {
			require.NoError(t, tx.Close())
		}
	})
	req := testRequest{
		headers: testHeaders{http.Header{"Host": {"example.com"}, "Content-Type": {"text/plain"}}},
		body:    &fakeBody{remaining: "request body"},
	}
	resp := &testResponse{
		headers: testHeaders{http.Header{
			"Content-Type": {"text/plain"}, "Content-Length": {"999"},
			"Content-Encoding": {"gzip"}, "Set-Cookie": {"secret=session"},
		}},
		body:   &responseBody{fakeBody: fakeBody{remaining: "upstream secret"}},
		status: 200,
	}
	return tx, req, resp
}

const inspectionDirectives = `SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain`

func TestInspectionErrors(t *testing.T) {
	for _, failAt := range []string{"request read", "request process", "request restore", "response read", "response process"} {
		t.Run(failAt, func(t *testing.T) {
			tx, req, resp := setupTransaction(t, inspectionDirectives)
			tx.failAt = failAt
			next, ctx := handleRequest(req, resp)
			if strings.HasPrefix(failAt, "request") {
				require.False(t, next, "failed inspection must not forward the request")
				require.Zero(t, ctx)
			} else {
				require.True(t, next)
				require.Empty(t, tx.events)
				handleResponse(ctx, req, resp, false)
			}
			require.Equal(t, uint32(500), resp.status)
			require.Equal(t, "Internal Server Error\n", resp.body.written)
			require.Equal(t, http.Header{
				"Content-Type":   {"text/plain; charset=utf-8"},
				"Content-Length": {"22"}, "Cache-Control": {"no-store"},
			}, resp.headers.Header)
			require.Equal(t, []string{"log", "close"}, tx.events)
			require.Empty(t, txs)
			handleResponse(ctx, req, resp, false)
			require.Equal(t, []string{"log", "close"}, tx.events)
		})
	}
}

func TestTransactionLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name, directives    string
		next, upstreamError bool
	}{
		{"allowed", inspectionDirectives, true, false},
		{"upstream error", inspectionDirectives, true, true},
		{"engine off", "SecRuleEngine Off", true, false},
		{"request deny", inspectionDirectives + "\nSecAction \"id:1,phase:1,deny,status:401\"", false, false},
		{"response deny", inspectionDirectives + "\nSecAction \"id:1,phase:3,deny,status:401\"", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, req, resp := setupTransaction(t, tc.directives)
			next, ctx := handleRequest(req, resp)
			require.Equal(t, tc.next, next)
			if next {
				if ctx != 0 {
					require.Empty(t, tx.events)
				}
				if tc.upstreamError {
					// The ABI permits cleanup only when the host reports an error.
					handleResponse(ctx, nil, nil, true)
				} else {
					handleResponse(ctx, req, resp, false)
				}
			}
			require.Equal(t, []string{"log", "close"}, tx.events)
			require.Empty(t, txs)
			handleResponse(ctx, nil, nil, true)
			require.Equal(t, []string{"log", "close"}, tx.events)
			if strings.Contains(tc.name, "deny") {
				require.Equal(t, uint32(401), resp.status)
				require.Equal(t, "Request blocked\n", resp.body.written)
			}
		})
	}
}

func TestInterruptionFallback(t *testing.T) {
	for _, interruption := range []*types.Interruption{
		{Action: "deny"}, {Action: "drop"}, {Action: "redirect", Status: 302},
	} {
		_, _, resp := setupTransaction(t, "SecRuleEngine Off")
		handleInterruption(interruption, resp)
		require.Equal(t, uint32(403), resp.status)
		require.Equal(t, "Request blocked\n", resp.body.written)
	}
}
