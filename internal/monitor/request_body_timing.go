package monitor

import (
	"context"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

// bodyTimer records how long it takes to receive a request body off the wire.
// This is the phase that was previously invisible: for large/slow uploads the
// body can take tens of seconds to arrive over a degraded (high-RTT / lossy)
// client connection, and CPA sits idle in io.ReadAll waiting for it — either
// before the monitor registers the request (so it's not shown at all yet) or
// afterwards (so it inflates the "waiting"/TTFB). Timing the body read at the
// earliest middleware captures that duration in both cases.
//
// arrival is set once at wrap time; firstReadAt/doneAt/bytes are updated by the
// wrapped reader as the handler chain consumes the body. Only the goroutine
// serving the request reads the body, so the atomics never contend.
type bodyTimer struct {
	arrival     time.Time
	firstReadAt atomic.Int64
	doneAt      atomic.Int64
	bytes       atomic.Int64
}

// receiveMillis reports how long the body took to arrive. done is false while
// the body is still being received (no EOF yet), in which case ms is the
// elapsed-so-far.
func (b *bodyTimer) receiveMillis(now time.Time) (ms int64, done bool) {
	if b == nil {
		return 0, true
	}
	if d := b.doneAt.Load(); d > 0 {
		return time.Unix(0, d).Sub(b.arrival).Milliseconds(), true
	}
	return now.Sub(b.arrival).Milliseconds(), false
}

// received returns the number of body bytes read off the wire so far.
func (b *bodyTimer) received() int64 {
	if b == nil {
		return 0
	}
	return b.bytes.Load()
}

// done reports whether the body has been fully received (EOF seen).
func (b *bodyTimer) done() bool {
	return b != nil && b.doneAt.Load() > 0
}

// timingBodyReader wraps the request body so the first full read off the wire
// is timed. It delegates to the inner reader and marks completion on EOF.
type timingBodyReader struct {
	inner io.ReadCloser
	timer *bodyTimer
}

func (r *timingBodyReader) Read(p []byte) (int, error) {
	n, err := r.inner.Read(p)
	if n > 0 {
		r.timer.firstReadAt.CompareAndSwap(0, time.Now().UnixNano())
		r.timer.bytes.Add(int64(n))
	}
	if err == io.EOF {
		r.timer.doneAt.CompareAndSwap(0, time.Now().UnixNano())
	}
	return n, err
}

func (r *timingBodyReader) Close() error { return r.inner.Close() }

type bodyTimingCtxKey struct{}

func withBodyTiming(ctx context.Context, b *bodyTimer) context.Context {
	return context.WithValue(ctx, bodyTimingCtxKey{}, b)
}

func bodyTimingFromContext(ctx context.Context) *bodyTimer {
	if ctx == nil {
		return nil
	}
	if b, ok := ctx.Value(bodyTimingCtxKey{}).(*bodyTimer); ok {
		return b
	}
	return nil
}

// RequestBodyTimingMiddleware must be registered BEFORE the request-logging
// middleware (which eagerly reads the body) and before Middleware (which
// registers the request in the monitor). It wraps the request body with a
// timing reader and stashes the timer on the context so Middleware can attach
// it to the tracked entry. Bodies-less requests (GET, etc.) are left untouched.
func RequestBodyTimingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request != nil && c.Request.Body != nil && c.Request.Body != http.NoBody {
			timer := &bodyTimer{arrival: time.Now()}
			c.Request.Body = &timingBodyReader{inner: c.Request.Body, timer: timer}
			c.Request = c.Request.WithContext(withBodyTiming(c.Request.Context(), timer))
		}
		c.Next()
	}
}
