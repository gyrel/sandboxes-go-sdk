package sandboxes

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Watch resume policy. The daemon Watch stream is a state-diff poller keyed
// by sandbox generation, so resuming with the last observed revision as
// AfterRevision never duplicates lifecycle state and never misses a
// transition that happened while the transport was down (generation is
// durable). Backoff is exponential and capped so a restarting daemon is
// polled gently.
const (
	watchResumeInitialBackoff = 100 * time.Millisecond
	watchResumeMaxBackoff     = 2 * time.Second
)

// errWatchClosed is returned by a resumable stream after the caller closed it.
var errWatchClosed = errors.New("sandboxes: watch stream closed")

// WatchResilient opens a Watch stream that transparently re-establishes the
// underlying transport after transient errors (daemon restart, dropped
// connection, deadline on the inner call) and resumes from the last observed
// revision. It satisfies the same EventStream contract; Recv only returns a
// terminal error when ctx is canceled or Close is called, at which point it
// yields errWatchClosed or the context error. Event delivery semantics match
// the raw stream: events carry the same Type/Sandbox/Operation fields, and
// callers keep keying lifecycle off state, not arrival counts.
func WatchResilient(ctx context.Context, c Client, opts WatchOptions) (EventStream, error) {
	inner, err := c.Sandboxes().Watch(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &resumableStream{
		ctx: ctx, client: c, sandboxID: opts.SandboxID,
		after: opts.AfterRevision, inner: inner,
		backoff: watchResumeInitialBackoff, sleep: sleepContext(ctx),
	}, nil
}

type resumableStream struct {
	ctx       context.Context
	client    Client
	sandboxID string

	mu      sync.Mutex
	after   int64
	inner   EventStream
	backoff time.Duration
	closed  bool
	sleep   func(time.Duration) error
}

func (r *resumableStream) Recv() (*Event, error) {
	for {
		r.mu.Lock()
		inner, closed := r.inner, r.closed
		r.mu.Unlock()
		if closed {
			return nil, errWatchClosed
		}
		event, err := inner.Recv()
		if err == nil {
			r.accept(event)
			return event, nil
		}
		if r.ctx.Err() != nil {
			return nil, r.ctx.Err()
		}
		if resumeErr := r.reconnect(); resumeErr != nil {
			return nil, resumeErr
		}
	}
}

// accept records delivery progress and resets the resume backoff.
func (r *resumableStream) accept(event *Event) {
	r.mu.Lock()
	if event.Revision > r.after {
		r.after = event.Revision
	}
	r.backoff = watchResumeInitialBackoff
	r.mu.Unlock()
}

// reconnect backs off and installs a freshly dialed stream resuming from the
// last delivered revision. A nil return means "retry Recv": either a new
// stream is installed, or the dial failed and the dead inner stream will
// raise the next error (the backoff grows per attempt). A non-nil return is
// terminal for the caller.
func (r *resumableStream) reconnect() error {
	wait := r.nextBackoff()
	if err := r.sleep(wait); err != nil {
		return err
	}
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return errWatchClosed
	}
	stream, err := r.client.Sandboxes().Watch(r.ctx, WatchOptions{SandboxID: r.sandboxID, AfterRevision: r.resumePoint()})
	if err != nil {
		if r.ctx.Err() != nil {
			return r.ctx.Err()
		}
		return nil
	}
	if !r.swapInner(stream) {
		_ = stream.Close()
		return errWatchClosed
	}
	return nil
}

func (r *resumableStream) nextBackoff() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	wait := r.backoff
	if r.backoff *= 2; r.backoff > watchResumeMaxBackoff {
		r.backoff = watchResumeMaxBackoff
	}
	return wait
}

func (r *resumableStream) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	if r.inner == nil {
		return nil
	}
	return r.inner.Close()
}

func (r *resumableStream) resumePoint() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.after
}

// swapInner installs a freshly dialed stream and retires the previous one.
// It reports false when the caller closed the resumable stream meanwhile.
func (r *resumableStream) swapInner(stream EventStream) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false
	}
	old := r.inner
	r.inner = stream
	if old != nil {
		_ = old.Close()
	}
	return true
}

// sleepContext waits dur unless ctx ends first.
func sleepContext(ctx context.Context) func(time.Duration) error {
	return func(d time.Duration) error {
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	}
}
