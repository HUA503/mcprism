//go:build windows

package protocol

import (
	"os/exec"
	"strconv"
	"syscall"
)

// setNewProcessGroup starts the child in a new process group so it can be
// addressed as the root of a tree during cleanup.
func setNewProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= syscall.CREATE_NEW_PROCESS_GROUP
}

// killProcessTree terminates the process and all of its descendants using
// taskkill /T (the standard-kernel equivalent of killing a POSIX process
// group). Job Objects would be more direct but require x/sys/windows.
func killProcessTree(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	killer := exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(cmd.Process.Pid))
	return killer.Run()
}
