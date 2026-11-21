//go:build windows

package kernel

import "os"

func fileUID(os.FileInfo) int { return 0 }
