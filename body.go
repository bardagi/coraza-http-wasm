package main

import (
	"io"
	"strconv"

	"github.com/http-wasm/http-wasm-guest-tinygo/handler/api"
)

// bodyReader adapts api.Body to io.Reader so Coraza can read a body into its
// transaction buffer.
//
// It deliberately does not implement io.WriterTo. Coraza reads bodies through
// io.CopyN, which wraps the reader in an *io.LimitedReader and hides WriterTo
// from io.Copy regardless; and api.Body.WriteTo copies through the guest's
// shared 2KiB buffer, which would cost 16x the host calls of the 32KiB
// io.Copy path. (api.Body.WriteTo returns uint64, not int64, so embedding it
// does not accidentally satisfy io.WriterTo either.)
type bodyReader struct {
	api.Body
}

func (r bodyReader) Read(p []byte) (n int, err error) {
	size, eof := r.Body.Read(p)
	if eof {
		err = io.EOF
	}
	n = int(size)
	return
}

// sizedBodyReader is a bodyReader whose length is known up front, from the
// Content-Length header. It satisfies Coraza's ByteLenger, which lets Coraza
// size its copy buffer to the actual body rather than to the body limit
// (128MiB by default), and reject an oversized body without reading it.
//
// Only use it when Content-Length is present: for a chunked body the length is
// unknown and plain bodyReader is the correct choice.
type sizedBodyReader struct {
	bodyReader
	length int
}

func (r sizedBodyReader) Len() int { return r.length }

var (
	_ io.Reader = bodyReader{}
	_ io.Reader = sizedBodyReader{}
)

// parseContentLength reports the body size a Content-Length header declares.
// It reports false for anything it cannot trust, in which case the body is
// read as if the length were unknown.
func parseContentLength(v string) (int, bool) {
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, false
	}

	return n, true
}

// newBodyReader wraps a body for Coraza, declaring its length when we know it
// so Coraza can size its copy buffer to the body instead of to the body limit.
func newBodyReader(body api.Body, length int, known bool) io.Reader {
	if known {
		return sizedBodyReader{bodyReader{body}, length}
	}

	return bodyReader{body}
}
