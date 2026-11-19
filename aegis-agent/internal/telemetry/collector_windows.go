//go:build windows

package telemetry

import (
	"context"
	"os"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
	gonet "github.com/shirou/gopsutil/v4/net"
)

type windowsCollector struct{}

func NewCollector() Collector { return windowsCollector{} }

func (windowsCollector) Collect(ctx context.Context) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	snap := Snapshot{
		IPLocal:      LocalIPv4(),
		Processes:    []Process{},
		Users:        []User{},
		NetworkFlows: []Flow{},
		Anomalies:    []any{},
	}
	if percents, err := cpu.Percent(0, false); err == nil && len(percents) > 0 {
		snap.CPUUsage = round1(percents[0])
	}
	if vm, err := mem.VirtualMemory(); err == nil {
		snap.RAMUsage = round1(vm.UsedPercent)
	}
	drive := os.Getenv("SystemDrive")
	if drive == "" {
		drive = "C:"
	}
	if usage, err := disk.Usage(drive + `\`); err == nil {
		snap.DiskFree = int64(usage.Free / (1024 * 1024))
		snap.DiskTotal = int64(usage.Total / (1024 * 1024))
	}
	if counters, err := gonet.IOCounters(false); err == nil && len(counters) > 0 {
		snap.NetworkSent = int64(counters[0].BytesSent)
		snap.NetworkReceived = int64(counters[0].BytesRecv)
	}
	enrichSnapshot(ctx, &snap)
	return snap, nil
}
