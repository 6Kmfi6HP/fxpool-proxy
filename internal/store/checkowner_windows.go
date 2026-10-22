//go:build windows

package store

import "os"

// checkOwner is a no-op on Windows, where the uid-based ownership check
// (via syscall.Stat_t) is not available.
func checkOwner(_ os.FileInfo) error { return nil }
