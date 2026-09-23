package main

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza-http-wasm/operators"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/types"
	httpwasm "github.com/http-wasm/http-wasm-guest-tinygo/handler"
	"github.com/http-wasm/http-wasm-guest-tinygo/handler/api"
	"github.com/jcchavezs/mergefs"
	fsio "github.com/jcchavezs/mergefs/io"
	"github.com/tidwall/gjson"
)

func init() {
	// Registers wasilibs operators before initializing the WAF.
	// See https://github.com/corazawaf/coraza-wasilibs
	operators.Register()
}

// statusInternalServerError avoids pulling net/http into the guest for a
// single constant.
const statusInternalServerError = 500

var waf coraza.WAF
var txs = map[uint32]types.Transaction{}

// lastReqCtx backs newReqCtx. The guest is built with -scheduler=none and wasm
// instances are single threaded, so this needs no synchronisation.
var lastReqCtx uint32

// newReqCtx returns the key a transaction is parked under in txs until
// handleResponse claims it. Zero is reserved by the ABI to mean "no context",
// and a repeat would strand the transaction it displaced (never closed, never
// logged, holding its body buffers), so never return it.
func newReqCtx() uint32 {
	lastReqCtx++
	if lastReqCtx == 0 {
		lastReqCtx = 1
	}

	return lastReqCtx
}

// main ensures buffering is available on the host.
//
// Note: required features does not include api.FeatureTrailers because some
// hosts don't support them, and the impact is minimal for logging.
func main() {
	var err error
	waf, err = initializeWAF(httpwasm.Host)
	if err != nil {
		httpwasm.Host.Log(api.LogLevelError, fmt.Sprintf("Failed to initialize WAF: %v", err))
		os.Exit(1)
	}
	httpwasm.HandleRequestFn = handleRequest
	httpwasm.HandleResponseFn = handleResponse
}

func toHostLevel(lvl debuglog.Level) api.LogLevel {
	switch lvl {
	case debuglog.LevelNoLog:
		return api.LogLevelNone
	case debuglog.LevelError:
		return api.LogLevelError
	case debuglog.LevelWarn:
		return api.LogLevelWarn
	case debuglog.LevelInfo:
		return api.LogLevelInfo
	default:
		return api.LogLevelDebug
	}
}

type config struct {
	includeCRS bool
	directives string
}

func getConfigFromHost(host api.Host) (config, error) {
	cfg := config{includeCRS: true}

	raw := host.GetConfig()
	var directives = strings.Builder{}
	cfgAsJSON := gjson.ParseBytes(raw)
	if !gjson.ValidBytes(raw) || !cfgAsJSON.IsObject() {
		return config{}, errors.New("invalid host config")
	}

	if includeCRSRes := cfgAsJSON.Get("includeCRS"); includeCRSRes.Exists() {
		if includeCRSRes.Type != gjson.True && includeCRSRes.Type != gjson.False {
			return config{}, errors.New("invalid host config, boolean expected for field includeCRS")
		}
		cfg.includeCRS = includeCRSRes.Bool()
	}

	directivesResult := cfgAsJSON.Get("directives")
	if !directivesResult.IsArray() {
		return config{}, errors.New("invalid host config, array expected for field directives")
	}

	for i, value := range directivesResult.Array() {
		if value.Type != gjson.String {
			return config{}, fmt.Errorf("invalid host config, string expected for directives[%d]", i)
		}
		if i > 0 {
			directives.WriteByte('\n')
		}

		directives.WriteString(value.Str)
	}

	if strings.TrimSpace(directives.String()) == "" {
		return config{}, errors.New("empty directives")
	}

	cfg.directives = directives.String()
	return cfg, nil
}

func toHostSeverity(severity types.RuleSeverity) api.LogLevel {
	switch severity {
	case types.RuleSeverityEmergency,
		types.RuleSeverityAlert,
		types.RuleSeverityCritical,
		types.RuleSeverityError:
		return api.LogLevelError
	case types.RuleSeverityWarning:
		return api.LogLevelWarn
	case types.RuleSeverityNotice,
		types.RuleSeverityInfo:
		return api.LogLevelInfo
	default:
		return api.LogLevelDebug
	}
}

func errorCb(host api.Host) func(types.MatchedRule) {
	return func(mr types.MatchedRule) {
		lvl := toHostSeverity(mr.Rule().Severity())
		// Ask the host before formatting: ErrorLog() builds the message with a
		// strings.Builder and several Fprintf calls, and a ruleset doing
		// anomaly scoring matches many rules per request.
		if !host.LogEnabled(lvl) {
			return
		}

		host.Log(lvl, mr.ErrorLog())
	}
}

func initializeWAF(host api.Host) (coraza.WAF, error) {
	requiredFeatures := api.FeatureBufferRequest | api.FeatureBufferResponse
	if have := host.EnableFeatures(requiredFeatures); have&requiredFeatures != requiredFeatures {
		return nil, fmt.Errorf("required buffering unavailable, want: %s, have: %s", requiredFeatures, have)
	}
	wafConfig := coraza.NewWAFConfig()

	if cfg, err := getConfigFromHost(host); err == nil {
		if cfg.includeCRS {
			wafConfig = wafConfig.WithRootFS(mergefs.Merge(coreruleset.FS, fsio.OSFS))
		} else {
			wafConfig = wafConfig.WithRootFS(fsio.OSFS)
		}

		if host.LogEnabled(api.LogLevelDebug) {
			if cfg.includeCRS {
				host.Log(api.LogLevelDebug, "Initializing WAF with CRS embedded and directives:\n"+cfg.directives)
			} else {
				host.Log(api.LogLevelDebug, "Initializing WAF with directives:\n"+cfg.directives)
			}
		}
		wafConfig = wafConfig.WithDirectives(cfg.directives)
	} else {
		return nil, err
	}

	wafConfig = wafConfig.WithDebugLogger(debuglog.DefaultWithPrinterFactory(func(io.Writer) debuglog.Printer {
		return func(lvl debuglog.Level, message, fields string) {
			hostLvl := toHostLevel(lvl)
			// Coraza's default logger emits at Info and above regardless of the
			// host's own level, so check before concatenating.
			if !host.LogEnabled(hostLvl) {
				return
			}

			if fields == "" {
				host.Log(hostLvl, message)
				return
			}

			host.Log(hostLvl, message+" "+fields)
		}
	})).WithErrorCallback(errorCb(host))

	waf, err := coraza.NewWAF(wafConfig)
	if err != nil {
		return nil, err
	}

	return waf, nil
}

func handleRequest(req api.Request, res api.Response) (next bool, reqCtx uint32) {
	tx := waf.NewTransaction()

	// Early return, Coraza is not going to process any rule
	if tx.IsRuleEngineOff() {
		next = true
		finishTransaction(tx)
		return
	}

	defer func() {
		if !next {
			finishTransaction(tx)
		}
	}()

	client, cport := parseSourceAddress(req.GetSourceAddr())

	var it *types.Interruption
	// There is no socket access in the request object, so we neither know the server client nor port.
	tx.ProcessConnection(client, cport, "", 0)
	tx.ProcessURI(req.GetURI(), req.GetMethod(), req.GetProtocolVersion())
	// contentLength is picked up from the loop below rather than with a
	// dedicated Headers().Get call, which would cost an extra host call.
	contentLength, hasContentLength := 0, false

	headers := req.Headers()
	for _, k := range headers.Names() {
		// Read Host separately, including hosts that omit it from Names().
		if strings.EqualFold(k, "host") {
			continue
		}
		if hs := headers.GetAll(k); len(hs) > 0 {
			if len(hs) == 1 && !hasContentLength && strings.EqualFold(k, "content-length") {
				contentLength, hasContentLength = parseContentLength(hs[0])
			}

			for _, value := range hs {
				tx.AddRequestHeader(k, value)
			}
		}
	}

	// Feed the host-provided authority to Coraza exactly once.
	if host, ok := headers.Get("Host"); ok {
		tx.AddRequestHeader("Host", host)
		// This connector relies on the host header (now host field) to populate ServerName
		tx.SetServerName(host)
	}

	it = tx.ProcessRequestHeaders()
	if it != nil {
		handleInterruption(it, res)
		return
	}

	// A body declared empty is skipped outright: Coraza would copy zero bytes
	// but still allocate a copy buffer to do it.
	hasBody := !hasContentLength || contentLength > 0

	// We only do body buffering if the transaction requires request body
	// inspection, otherwise we just let the request follow its regular flow.
	bodyInspected := tx.IsRequestBodyAccessible() && hasBody
	if bodyInspected {
		it, _, err := tx.ReadRequestBodyFrom(newBodyReader(req.Body(), contentLength, hasContentLength))
		if err != nil {
			tx.DebugLogger().Error().Err(err).Msg("Failed to read request body")
			replaceResponse(res, statusInternalServerError, "Internal Server Error\n")
			return
		}

		if it != nil {
			handleInterruption(it, res)
			return
		}
	}

	var err error
	it, err = tx.ProcessRequestBody()
	if err != nil {
		tx.DebugLogger().Error().Err(err).Msg("Failed to process request body")
		replaceResponse(res, statusInternalServerError, "Internal Server Error\n")
		return
	}

	if it != nil {
		handleInterruption(it, res)
		return
	}

	if bodyInspected {
		if err := restoreRequestBody(tx, req.Body()); err != nil {
			tx.DebugLogger().Error().Err(err).Msg("Failed to restore request body")
			replaceResponse(res, statusInternalServerError, "Internal Server Error\n")
			return
		}
	}

	reqCtx = newReqCtx()
	txs[reqCtx] = tx
	return true, reqCtx
}

func handleInterruption(in *types.Interruption, res api.Response) {
	statusCode := obtainStatusCodeFromInterruptionOrDefault(in, 403)
	replaceResponse(res, statusCode, "Request blocked\n")
}

// The first nonempty body write replaces the host's buffered response.
// Empty writes are ignored by the guest SDK and cannot erase upstream data.
func replaceResponse(res api.Response, status uint32, message string) {
	headers := res.Headers()
	for _, name := range headers.Names() {
		headers.Remove(name)
	}
	headers.Set("Content-Type", "text/plain; charset=utf-8")
	headers.Set("Content-Length", strconv.Itoa(len(message)))
	headers.Set("Cache-Control", "no-store")
	res.SetStatusCode(status)
	res.Body().WriteString(message)
}

func finishTransaction(tx types.Transaction) {
	tx.ProcessLogging()
	if err := tx.Close(); err != nil {
		tx.DebugLogger().Error().Err(err).Msg("Failed to close the transaction")
	}
}

func parseSourceAddress(source string) (string, int) {
	if addr, err := netip.ParseAddr(source); err == nil {
		return addr.WithZone("").String(), 0
	}
	if addr, err := netip.ParseAddrPort(source); err == nil {
		return addr.Addr().WithZone("").String(), int(addr.Port())
	}
	// Accept bracketed IPv6 without a port as well.
	if strings.HasPrefix(source, "[") && strings.HasSuffix(source, "]") {
		if addr, err := netip.ParseAddr(source[1 : len(source)-1]); err == nil && addr.Is6() {
			return addr.WithZone("").String(), 0
		}
	}
	return "", 0
}

// obtainStatusCodeFromInterruptionOrDefault returns the desired status code derived from the interruption
// on a "deny" action or a default value.
func obtainStatusCodeFromInterruptionOrDefault(it *types.Interruption, defaultStatusCode uint32) uint32 {
	if it.Action == "deny" {
		statusCode := it.Status
		if statusCode == 0 {
			statusCode = 403
		}

		return uint32(statusCode)
	}

	return defaultStatusCode
}

func handleResponse(reqCtx uint32, req api.Request, resp api.Response, isError bool) {
	if reqCtx == 0 {
		return
	}

	tx, ok := txs[reqCtx]
	if !ok {
		return
	}
	delete(txs, reqCtx)

	defer finishTransaction(tx)

	if isError {
		return
	}

	if tx.IsInterrupted() {
		handleInterruption(tx.Interruption(), resp)
		return
	}

	respHeaders := resp.Headers()
	for _, h := range respHeaders.Names() {
		for _, value := range respHeaders.GetAll(h) {
			tx.AddResponseHeader(h, value)
		}
	}

	statusCode := resp.GetStatusCode()
	it := tx.ProcessResponseHeaders(int(statusCode), req.GetProtocolVersion())
	if it != nil {
		handleInterruption(it, resp)
		return
	}

	// Mirrors the request path: Coraza already returns early when response body
	// access is off, so this only avoids building the reader and calling in.
	//
	// Note the response body is deliberately not read as a sizedBodyReader. A
	// response Content-Length is a header the upstream handler chose; unlike a
	// request's, it does not frame the body the host hands us, so trusting it
	// could bound what the WAF inspects to less than what is actually sent.
	if tx.IsResponseBodyAccessible() {
		it, _, err := tx.ReadResponseBodyFrom(bodyReader{resp.Body()})
		if err != nil {
			tx.DebugLogger().Error().Err(err).Msg("Failed to read response body")
			replaceResponse(resp, statusInternalServerError, "Internal Server Error\n")
			return
		}
		if it != nil {
			handleInterruption(it, resp)
			return
		}
	}

	if tx.IsResponseBodyAccessible() && tx.IsResponseBodyProcessable() {
		if it, err := tx.ProcessResponseBody(); err != nil {
			replaceResponse(resp, statusInternalServerError, "Internal Server Error\n")
			tx.DebugLogger().Error().Err(err).Msg("Failed to process response body")
			return
		} else if it != nil {
			handleInterruption(it, resp)
			return
		}
	}
}
