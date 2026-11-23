//go:build !windows

package main

import "context"

// runAsService is a no-op outside Windows: there is no Service Control Manager,
// so the agent always runs as a console process (systemd on Linux).
func runAsService(_ func(context.Context) error) (bool, error) {
	return false, nil
}
