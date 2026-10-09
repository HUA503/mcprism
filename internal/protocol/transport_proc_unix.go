//go:build !windows

package protocol

import (
	"os/exec"
	"syscall"
)

// setNewProcessGroup puts the child in a new process group (pgid == its pid)
// so the whole tree launched by a wrapper such as npx/uvx can be signaled at
// once via a negative pid.
func setNewProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// killProcessTree signals the entire process group. A negative pid targets the
// whole group rather than only the wrapper process, preventing orphaned
// node/python children from lingering after a probe.
func killProcessTree(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
