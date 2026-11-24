//go:build !linux && !windows

package telemetry

import (
	"context"
	"fmt"
	"runtime"
)

type unsupportedCollector struct{}

func NewCollector() Collector { return unsupportedCollector{} }

func (unsupportedCollector) Collect(ctx context.Context) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	return Snapshot{}, fmt.Errorf("collector not supported on %s", runtime.GOOS)
}
