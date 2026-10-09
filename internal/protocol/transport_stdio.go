package protocol

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/HUA503/mcprism/internal/config"
)

type callResult struct {
	raw json.RawMessage
	err error
}

// cappedBuffer 只保留最后 64KiB，避免异常 server 刷爆内存。
type cappedBuffer struct {
	buf []byte
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	c.buf = append(c.buf, p...)
	if len(c.buf) > 65536 {
		c.buf = c.buf[len(c.buf)-65536:]
	}
	return len(p), nil
}

func (c *cappedBuffer) String() string { return string(c.buf) }

type stdioTransport struct {
	cmd     *exec.Cmd
	cancel  context.CancelFunc
	stdin   io.WriteCloser
	stderr  cappedBuffer
	writeMu sync.Mutex
	mu      sync.Mutex
	pending map[int64]chan callResult
	closed  chan struct{}
}

// InheritChildEnv controls whether a dynamically launched stdio server inherits
// the full parent environment. It defaults to false so that probing an
// untrusted server does not hand it every host credential (API tokens, cloud
// keys). When false, only a minimal runtime allowlist plus the server's own
// env block is passed. Set it from a CLI flag when a server genuinely needs
// extra variables.
var InheritChildEnv = false

// probeEnvAllowlist lists non-secret variables a launched toolchain typically
// needs (resolving node/python, temp dirs, locale). Secret-bearing names are
// intentionally absent.
var probeEnvAllowlist = []string{
	"PATH", "PATHEXT", "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
	"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR",
	"LANG", "LC_ALL", "LC_CTYPE", "TERM", "COLORTERM", "SHELL",
	"APPDATA", "LOCALAPPDATA", "XDG_CACHE_HOME", "XDG_CONFIG_HOME",
}

func childEnv(srv *config.Server) []string {
	if InheritChildEnv {
		env := os.Environ()
		for k, v := range srv.Env {
			env = append(env, k+"="+v)
		}
		return env
	}
	allowed := make(map[string]bool, len(probeEnvAllowlist))
	for _, k := range probeEnvAllowlist {
		allowed[k] = true
	}
	env := make([]string, 0, len(probeEnvAllowlist)+len(srv.Env))
	for _, kv := range os.Environ() {
		k := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			k = kv[:i]
		}
		if allowed[k] {
			env = append(env, kv)
		}
	}
	for k, v := range srv.Env {
		env = append(env, k+"="+v)
	}
	return env
}

func newStdioTransport(parent context.Context, srv *config.Server) (*stdioTransport, error) {
	if srv.Command == "" {
		return nil, fmt.Errorf("stdio server %q has no command", srv.Name)
	}
	ctx, cancel := context.WithCancel(parent)
	t := &stdioTransport{
		cancel:  cancel,
		pending: map[int64]chan callResult{},
		closed:  make(chan struct{}),
	}
	cmd := exec.CommandContext(ctx, srv.Command, srv.Args...)
	cmd.Env = childEnv(srv)
	if srv.Cwd != "" {
		cmd.Dir = srv.Cwd
	}
	// Put the child in its own process group/job so cleanup kills the whole
	// tree (npx -> node, uvx -> python), not just the wrapper process.
	setNewProcessGroup(cmd)
	cmd.Cancel = func() error { return killProcessTree(cmd) }
	cmd.WaitDelay = 3 * time.Second
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	cmd.Stderr = &t.stderr

	t.cmd = cmd
	t.stdin = stdin

	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("start %q: %w", srv.Command, err)
	}

	go t.readLoop(stdout)
	go func() {
		_ = cmd.Wait()
		select {
		case <-t.closed:
		default:
			close(t.closed)
		}
		t.failAll(fmt.Errorf("mcp server process exited; stderr: %s", t.stderr.String()))
	}()

	return t, nil
}

func (t *stdioTransport) readLoop(r io.Reader) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var resp RPCResponse
		if err := json.Unmarshal(line, &resp); err != nil {
			continue // 非 JSON-RPC 行，忽略
		}
		if len(resp.ID) == 0 || bytes.Equal(resp.ID, []byte("null")) {
			continue // 服务端通知，暂不处理
		}
		var id int64
		if err := json.Unmarshal(resp.ID, &id); err != nil {
			continue
		}
		t.deliver(id, resp)
	}
}

func (t *stdioTransport) deliver(id int64, resp RPCResponse) {
	t.mu.Lock()
	ch, ok := t.pending[id]
	if ok {
		delete(t.pending, id)
	}
	t.mu.Unlock()
	if !ok {
		return
	}
	if resp.Error != nil {
		ch <- callResult{err: resp.Error}
	} else {
		ch <- callResult{raw: resp.Result}
	}
}

func (t *stdioTransport) write(req RPCRequest) error {
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	t.writeMu.Lock()
	_, err = t.stdin.Write(data)
	t.writeMu.Unlock()
	return err
}

func (t *stdioTransport) call(ctx context.Context, id int64, method string, params any) (json.RawMessage, error) {
	ch := make(chan callResult, 1)
	t.mu.Lock()
	t.pending[id] = ch
	t.mu.Unlock()

	if err := t.write(RPCRequest{JSONRPC: "2.0", ID: id, Method: method, Params: params}); err != nil {
		t.remove(id)
		return nil, err
	}

	select {
	case r := <-ch:
		return r.raw, r.err
	case <-ctx.Done():
		t.remove(id)
		return nil, ctx.Err()
	case <-t.closed:
		t.remove(id)
		return nil, fmt.Errorf("connection closed; %s", t.stderr.String())
	}
}

func (t *stdioTransport) notify(_ context.Context, method string, params any) error {
	return t.write(RPCRequest{JSONRPC: "2.0", Method: method, Params: params})
}

func (t *stdioTransport) remove(id int64) {
	t.mu.Lock()
	delete(t.pending, id)
	t.mu.Unlock()
}

func (t *stdioTransport) failAll(err error) {
	t.mu.Lock()
	chans := t.pending
	t.pending = map[int64]chan callResult{}
	t.mu.Unlock()
	for _, ch := range chans {
		select {
		case ch <- callResult{err: err}:
		default:
		}
	}
}

func (t *stdioTransport) close() error {
	_ = t.stdin.Close()
	// Canceling the context fires cmd.Cancel (kill the whole process tree);
	// WaitDelay then reaps anything that ignores the first signal.
	if t.cancel != nil {
		t.cancel()
	}
	select {
	case <-t.closed:
	case <-time.After(4 * time.Second):
		_ = killProcessTree(t.cmd)
	}
	return nil
}
