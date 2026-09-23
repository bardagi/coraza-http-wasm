# coraza-http-wasm

Web Application Firewall WASM middleware built on top of Coraza and implementing the [http-wasm](https://http-wasm.io/) ABI.

## Getting started

`go run mage.go -l` lists all the available commands:

```bash
$ go run mage.go -l
Targets:
  build*    builds the wasm binary.
  e2e       runs e2e tests
  format    formats code in this repository.
  ftw       runs the FTW test suite
  lint      verifies code format.
  test      runs all unit tests.

* default target
```

### Building the binary

```bash
go run mage.go build
```

You will find the WASM plugin under `./build/coraza-http-wasm.wasm`.

### Basic Configuration

```json
{
   "directives": [
    "SecRuleEngine On",
    "SecDebugLog /dev/stdout",
    "SecDebugLogLevel 9",
    "SecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,log,deny,status:403\""
   ]
  }
```

### Configuration and failure behavior

Configuration must be a JSON object with a `directives` array containing only
strings and at least one non-whitespace directive. Missing configuration, empty
directives, malformed JSON, and incorrectly typed fields prevent startup.
Unknown fields are accepted for compatibility.

`includeCRS` is an optional boolean and defaults to `true`. It makes the embedded
CRS files available to `Include` directives; it does not activate the rules by
itself. For example, a configuration using the embedded CRS is:

```json
{
  "includeCRS": true,
  "directives": [
    "Include @coraza.conf-recommended",
    "SecRuleEngine On",
    "Include @crs-setup.conf.example",
    "Include @owasp_crs/*.conf"
  ]
}
```

**Migration:** deployments that previously supplied no configuration must now
provide directives. To intentionally pass traffic through without WAF inspection,
use `{"directives": ["SecRuleEngine Off"]}`.

The HTTP-Wasm host must support both request and response buffering. The plugin
refuses to initialize if either capability is unavailable.

Blocked requests and responses return `Request blocked\n`, preserving the configured
deny status (403 when unspecified, or 413 for Coraza body-limit rejection).
Other interruption actions fall back to 403. Connector inspection errors return
500 with `Internal Server Error\n`; error details remain in logs. These generated
responses replace the upstream body and headers, set `Content-Type: text/plain;
charset=utf-8` and an accurate `Content-Length`, and use `Cache-Control: no-store`.
Clients that previously expected an empty denial body must accept the generic message.

### Test it

```console
curl -I 'http://localhost:8080/admin'    # 403
curl -I 'http://localhost:8080/anything' # 200
```

Rebuild before testing so the integration tests use the current guest code:

```console
go run mage.go build
go run mage.go test
go run mage.go e2e
go run mage.go ftw
```

The E2E suite checks blocking, response replacement, header inspection, and body
preservation using the Go HTTP-Wasm host. It does not establish compatibility with
a particular Traefik version.

The pinned Go HTTP-Wasm host v0.7.0 does not reliably replay inspected request
bodies. The plugin restores the inspected bytes and any unread remainder before
forwarding, including when `SecRequestBodyLimitAction ProcessPartial` is used.
This adds copying for inspected requests, using a bounded copy buffer in the guest.
