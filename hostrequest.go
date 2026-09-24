//go:build tinygo.wasm

package main

import (
	"unsafe"

	"github.com/http-wasm/http-wasm-guest-tinygo/handler/api"
)

//go:wasmimport http_handler get_method
func getMethod(ptr, limit uint32) (len uint32)

//go:wasmimport http_handler get_uri
func getURI(ptr, limit uint32) (len uint32)

//go:wasmimport http_handler get_protocol_version
func getProtocolVersion(ptr, limit uint32) (len uint32)

//go:wasmimport http_handler get_source_addr
func getSourceAddr(ptr, limit uint32) (len uint32)

// hostRequest works around a bug in http-wasm-guest-tinygo v0.4.0: when a
// request field is longer than the SDK's 2KiB read buffer, its GetString
// reinterprets the field's first bytes as a string header. A URI over 2KiB
// therefore becomes a string with an attacker-chosen pointer and length, and
// reading it traps the guest.
type hostRequest struct {
	api.Request
}

func wrapRequest(req api.Request) api.Request { return hostRequest{req} }

// Host imports cannot be used as values, hence the wrapping closures.

func (hostRequest) GetMethod() string {
	return readHostString(func(ptr, limit uint32) uint32 { return getMethod(ptr, limit) })
}

func (hostRequest) GetURI() string {
	return readHostString(func(ptr, limit uint32) uint32 { return getURI(ptr, limit) })
}

func (hostRequest) GetProtocolVersion() string {
	return readHostString(func(ptr, limit uint32) uint32 { return getProtocolVersion(ptr, limit) })
}

func (hostRequest) GetSourceAddr() string {
	return readHostString(func(ptr, limit uint32) uint32 { return getSourceAddr(ptr, limit) })
}

// readBuf is shared because wasm instances are single threaded.
var readBuf = make([]byte, 2048)

// readHostString reads a field through a host function that writes it into
// [ptr, ptr+limit) only if it fits, and always returns its full length.
func readHostString(fn func(ptr, limit uint32) uint32) string {
	size := fn(uint32(uintptr(unsafe.Pointer(&readBuf[0]))), uint32(len(readBuf)))
	if size <= uint32(len(readBuf)) {
		return string(readBuf[:size])
	}

	buf := make([]byte, size)
	if n := fn(uint32(uintptr(unsafe.Pointer(&buf[0]))), size); n < size {
		buf = buf[:n]
	}

	return string(buf)
}
