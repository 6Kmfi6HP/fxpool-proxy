//go:build !windows

package token

import (
	"os"
	"syscall"
)

func lockFile(f *os.File, block bool) error {
	how := syscall.LOCK_EX
	if !block {
		how |= syscall.LOCK_NB
	}
	return syscall.Flock(int(f.Fd()), how)
}

func unlockFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
