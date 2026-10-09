//go:build !windows

package protocol

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// groupHasLive reports whether any non-zombie process still belongs to pgid.
// Killed children may linger as zombies until init reaps them (common in
// containers), which still counts as "stopped" since they hold no resources.
func groupHasLive(pgid int) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			continue
		}
		idx := strings.LastIndex(string(data), ")")
		if idx < 0 {
			continue
		}
		fields := strings.Fields(string(data)[idx+2:])
		if len(fields) < 4 {
			continue
		}
		// fields: state ppid pgrp session ...
		pgrp, _ := strconv.Atoi(fields[2])
		if pgrp == pgid && fields[0] != "Z" {
			return true
		}
	}
	return false
}

// Killing the transport must signal the whole process group, not just the
// wrapper shell, so a forked child (npx -> node style) does not keep running.
func TestKillProcessTreeReapsGroup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process-group semantics are POSIX-only")
	}
	cmd := exec.Command("sh", "-c", "sleep 30 & sleep 30")
	setNewProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start sh: %v", err)
	}
	pid := cmd.Process.Pid

	if err := killProcessTree(cmd); err != nil {
		t.Fatalf("killProcessTree: %v", err)
	}
	go func() { _ = cmd.Wait() }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !groupHasLive(pid) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("live process(es) still in group %d after tree kill", pid)
}
