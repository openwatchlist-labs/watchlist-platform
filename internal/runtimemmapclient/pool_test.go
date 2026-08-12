package runtimemmapclient

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"testing"
	"time"
)

// newPipeWorker builds a *Worker whose stdin/stdout are in-process pipes
// instead of a real subprocess, so tests can control exactly when the
// simulated Rust worker responds without needing a real runtime binary.
// The returned respond function writes the query's response once called;
// the caller decides when that happens relative to Pool.Close().
func newPipeWorker(t *testing.T, queryReceived chan<- struct{}) (*Worker, func(requestID string)) {
	t.Helper()
	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()

	go func() {
		reader := bufio.NewReader(stdinR)
		if _, err := reader.ReadString('\n'); err != nil {
			return
		}
		close(queryReceived)
	}()

	worker := &Worker{stdin: stdinW, scanner: bufio.NewScanner(stdoutR)}
	worker.scanner.Buffer(make([]byte, 4096), 4<<20)

	respond := func(requestID string) {
		fmt.Fprintf(stdoutW, "B\t%s\t0\n", requestID)
		fmt.Fprintf(stdoutW, "E\t%s\n", requestID)
	}
	return worker, respond
}

// TestPoolCloseDuringInFlightLookupDoesNotPanic reproduces the Phase 2
// audit finding: Pool.Close() closes pool.workers while a Lookup is still
// in flight. The deferred `select { case pool.workers <- worker: default:
// }` in Lookup only guards against a FULL channel, not a CLOSED one --
// sending on a closed channel panics unconditionally in Go.
//
// The worker is pulled from the pool and blocked mid-request. Close() is
// then started concurrently with the in-flight lookup: a correct fix is
// allowed to have Close() block until the in-flight lookup finishes
// (e.g. draining via a WaitGroup before closing the channel), so this
// test must not wait for Close() to return before letting the lookup's
// response arrive -- doing so would deadlock against exactly that kind
// of correct fix. Instead it gives Close() a head start to reach its
// closing/draining point and then unblocks the response, which is enough
// to reproduce the original panic against the buggy implementation while
// remaining deadlock-free against a fix that drains first.
func TestPoolCloseDuringInFlightLookupDoesNotPanic(t *testing.T) {
	queryReceived := make(chan struct{})
	worker, respond := newPipeWorker(t, queryReceived)

	pool := &Pool{workers: make(chan *Worker, 1)}
	pool.workers <- worker

	lookupDone := make(chan error, 1)
	panicked := make(chan any, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				panicked <- r
			}
		}()
		_, err := pool.Lookup(context.Background(), Query{
			RequestID: "req-1",
			Kind:      QueryName,
			Value:     "TEST",
			Limit:     1,
		})
		lookupDone <- err
	}()

	select {
	case <-queryReceived:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for worker to receive query")
	}

	// The lookup now holds the worker and is blocked reading the
	// response. Start closing the pool while it is still in flight.
	closeDone := make(chan error, 1)
	go func() { closeDone <- pool.Close() }()

	// Give Close() a head start: against the buggy implementation this
	// is more than enough time for it to run to completion (there is no
	// blocking work in it); against a fix that drains in-flight requests
	// first, Close() will instead be parked waiting for this very
	// lookup, which is fine -- we do not wait for it here.
	time.Sleep(50 * time.Millisecond)
	respond("req-1")

	select {
	case r := <-panicked:
		t.Fatalf("Pool.Lookup panicked returning a worker to a closed pool: %v", r)
	case err := <-lookupDone:
		if err != nil {
			t.Fatalf("Pool.Lookup returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Pool.Lookup to return")
	}

	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Pool.Close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Pool.Close to return")
	}
}
