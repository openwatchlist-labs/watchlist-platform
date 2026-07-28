package runtimemmapclient

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

type Worker struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	scanner *bufio.Scanner
	info    PackageInfo
	closed  bool
}

func Start(ctx context.Context, binaryPath, packagePath string) (*Worker, error) {
	if binaryPath == "" || packagePath == "" {
		return nil, fmt.Errorf("runtime binary and package paths are required")
	}
	cmd := exec.CommandContext(ctx, binaryPath, "worker", "--package", packagePath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("open worker stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("open worker stdout: %w", err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("start Rust runtime worker: %w", err)
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), 4<<20)
	if !scanner.Scan() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if scanner.Err() != nil {
			return nil, fmt.Errorf("read worker hello: %w", scanner.Err())
		}
		return nil, fmt.Errorf("worker exited before hello: %s", strings.TrimSpace(stderr.String()))
	}
	info, err := parseHello(scanner.Text())
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, err
	}
	if info.ProtocolVersion != ProtocolVersion {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("worker protocol version %q, expected %q", info.ProtocolVersion, ProtocolVersion)
	}
	return &Worker{cmd: cmd, stdin: stdin, scanner: scanner, info: info}, nil
}

func (worker *Worker) Info() PackageInfo { return worker.info }

func (worker *Worker) Lookup(ctx context.Context, query Query) ([]Candidate, error) {
	type result struct {
		values []Candidate
		err    error
	}
	channel := make(chan result, 1)
	go func() {
		values, err := worker.lookup(query)
		channel <- result{values: values, err: err}
	}()
	select {
	case value := <-channel:
		return value.values, value.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (worker *Worker) lookup(query Query) ([]Candidate, error) {
	worker.mu.Lock()
	defer worker.mu.Unlock()
	if worker.closed {
		return nil, fmt.Errorf("runtime worker is closed")
	}
	line, err := encodeQuery(query)
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(worker.stdin, line+"\n"); err != nil {
		return nil, fmt.Errorf("write worker request: %w", err)
	}
	if !worker.scanner.Scan() {
		return nil, worker.scanError("read worker response")
	}
	first := worker.scanner.Text()
	if strings.HasPrefix(first, "X\t") {
		return nil, parseWorkerError(first, query.RequestID)
	}
	fields := strings.Split(first, "\t")
	if len(fields) != 3 || fields[0] != "B" || fields[1] != query.RequestID {
		return nil, fmt.Errorf("invalid worker response begin framing")
	}
	count, err := strconv.Atoi(fields[2])
	if err != nil || count < 0 || count > query.Limit {
		return nil, fmt.Errorf("invalid worker candidate count %q", fields[2])
	}
	candidates := make([]Candidate, 0, count)
	for index := 0; index < count; index++ {
		if !worker.scanner.Scan() {
			return nil, worker.scanError("read worker candidate")
		}
		candidate, err := parseCandidate(worker.scanner.Text(), query.RequestID)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, candidate)
	}
	if !worker.scanner.Scan() {
		return nil, worker.scanError("read worker response end")
	}
	if worker.scanner.Text() != "E\t"+query.RequestID {
		return nil, fmt.Errorf("invalid worker response end framing")
	}
	return candidates, nil
}

func (worker *Worker) scanError(operation string) error {
	if err := worker.scanner.Err(); err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	return fmt.Errorf("%s: worker exited", operation)
}

func (worker *Worker) Close() error {
	worker.mu.Lock()
	defer worker.mu.Unlock()
	if worker.closed {
		return nil
	}
	worker.closed = true
	_ = worker.stdin.Close()
	if worker.cmd.Process != nil {
		_ = worker.cmd.Process.Kill()
	}
	err := worker.cmd.Wait()
	if err != nil && !errors.Is(err, context.Canceled) {
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) {
			return err
		}
	}
	return nil
}
