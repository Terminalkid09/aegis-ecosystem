//go:build linux || windows

package telemetry

import (
	"net"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
)

func SystemInfo() map[string]any {
	osName := ""
	osVersion := ""
	if info, err := host.Info(); err == nil {
		osName = info.Platform
		osVersion = info.PlatformVersion
	}
	cpuModel := ""
	if infos, err := cpu.Info(); err == nil && len(infos) > 0 {
		cpuModel = infos[0].ModelName
	}
	var totalRAM int64
	if virtual, err := mem.VirtualMemory(); err == nil {
		totalRAM = int64(virtual.Total / (1024 * 1024))
	}
	return map[string]any{
		"os":         osName,
		"os_version": osVersion,
		"cpu_model":  cpuModel,
		"total_ram":  totalRAM,
	}
}

// LocalMAC returns the first non-loopback hardware address, best effort.
func LocalMAC() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) == 0 {
			continue
		}
		return iface.HardwareAddr.String()
	}
	return ""
}
