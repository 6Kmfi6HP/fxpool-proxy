//go:build !windows

package store

import (
	"fmt"
	"os"
	"syscall"
)

// checkOwner verifies that the database file is owned by the current user.
func checkOwner(fi os.FileInfo) error {
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if ok && sys.Uid != uint32(os.Getuid()) {
		return fmt.Errorf("store: database owned by uid %d, current uid %d", sys.Uid, os.Getuid())
	}
	return nil
}
