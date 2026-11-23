//go:build !windows

package kernel

import (
	"os"
	"syscall"
)

func fileUID(info os.FileInfo) int {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return int(stat.Uid)
}
