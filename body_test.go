package main

import (
	"io"
	"testing"

	"github.com/http-wasm/http-wasm-guest-tinygo/handler/api"
	"github.com/stretchr/testify/require"
)

// byteLenger mirrors the unexported interface Coraza type-asserts a body reader
// against (corazawaf.ByteLenger) to decide how large a copy to make.
type byteLenger interface {
	Len() int
}

// fakeBody is an api.Body backed by a string, for exercising bodyReader.
type fakeBody struct {
	api.Body
	remaining string
}

func (b *fakeBody) Read(p []byte) (uint32, bool) {
	n := copy(p, b.remaining)
	b.remaining = b.remaining[n:]
	return uint32(n), b.remaining == ""
}

func TestBodyReaderRead(t *testing.T) {
	body := &fakeBody{remaining: "hello world"}

	read, err := io.ReadAll(bodyReader{body})
	require.NoError(t, err)
	require.Equal(t, "hello world", string(read))
}

// A body reader must only claim a length when we actually know one. Coraza uses
// Len() as the number of bytes to copy, so a wrong or absent-but-guessed value
// would bound what the WAF inspects.
func TestNewBodyReaderOnlyDeclaresKnownLengths(t *testing.T) {
	t.Run("length known", func(t *testing.T) {
		r := newBodyReader(&fakeBody{remaining: "hello"}, 5, true)

		l, ok := r.(byteLenger)
		require.True(t, ok, "a reader with a known length must satisfy ByteLenger")
		require.Equal(t, 5, l.Len())
	})

	t.Run("length unknown", func(t *testing.T) {
		// E.g. a chunked body: Coraza must fall back to reading up to its limit.
		r := newBodyReader(&fakeBody{remaining: "hello"}, 0, false)

		_, ok := r.(byteLenger)
		require.False(t, ok, "a reader with no known length must not satisfy ByteLenger")
	})
}

// Coraza reads bodies through io.CopyN, which wraps the reader in an
// *io.LimitedReader and hides io.WriterTo. Implementing WriterTo here is
// therefore dead code, and api.Body.WriteTo copies through the guest's shared
// 2KiB buffer, so reaching it would cost 16x the host calls of the 32KiB
// io.Copy path. Keep it unimplemented.
func TestBodyReaderIsNotAWriterTo(t *testing.T) {
	var r io.Reader = bodyReader{&fakeBody{}}
	_, ok := r.(io.WriterTo)
	require.False(t, ok, "bodyReader must not implement io.WriterTo")

	r = sizedBodyReader{bodyReader{&fakeBody{}}, 0}
	_, ok = r.(io.WriterTo)
	require.False(t, ok, "sizedBodyReader must not implement io.WriterTo")
}

func TestParseContentLength(t *testing.T) {
	for _, tc := range []struct {
		value    string
		expected int
		ok       bool
	}{
		{value: "0", expected: 0, ok: true},
		{value: "512", expected: 512, ok: true},
		{value: "", ok: false},
		{value: "-1", ok: false},
		{value: "abc", ok: false},
		// A duplicated header the host folded into one value.
		{value: "10, 10", ok: false},
	} {
		t.Run("value "+tc.value, func(t *testing.T) {
			n, ok := parseContentLength(tc.value)
			require.Equal(t, tc.ok, ok)
			require.Equal(t, tc.expected, n)
		})
	}
}

func TestNewReqCtxNeverReturnsZero(t *testing.T) {
	// Zero means "no context" to the host, so handleResponse would never claim
	// the transaction and it would leak out of txs.
	lastReqCtx = 0
	require.Equal(t, uint32(1), newReqCtx())
	require.Equal(t, uint32(2), newReqCtx())

	lastReqCtx = ^uint32(0) // about to wrap
	require.Equal(t, uint32(1), newReqCtx())
}

func TestNewReqCtxIsUniquePerRequest(t *testing.T) {
	lastReqCtx = 0

	seen := map[uint32]bool{}
	for i := 0; i < 1000; i++ {
		ctx := newReqCtx()
		require.False(t, seen[ctx], "reqCtx %d handed out twice", ctx)
		seen[ctx] = true
	}
}
