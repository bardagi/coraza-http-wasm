//go:build !tinygo.wasm

package main

import "github.com/http-wasm/http-wasm-guest-tinygo/handler/api"

// wrapRequest is a no-op outside wasm, where there is no host to read from.
func wrapRequest(req api.Request) api.Request { return req }
