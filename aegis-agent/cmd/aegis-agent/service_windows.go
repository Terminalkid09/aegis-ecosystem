//go:build windows

package main

import (
	"context"
	"time"

	"golang.org/x/sys/windows/svc"
)

// runAsService reports whether this process was started by the Service Control
// Manager, and if so runs the agent inside the service dispatcher. It returns
// handled=false for a normal console invocation.
func runAsService(run func(context.Context) error) (bool, error) {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return false, err
	}
	return true, svc.Run("AegisAgent", &serviceHandler{run: run})
}

type serviceHandler struct {
	run func(context.Context) error
}

func (h *serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown

	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case err := <-done:
			if err != nil {
				return false, 1
			}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				status <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				// Give the agent a bounded window to release the pid lock and
				// finish in-flight work before the SCM kills the process.
				select {
				case <-done:
				case <-time.After(20 * time.Second):
				}
				return false, 0
			}
		}
	}
}
