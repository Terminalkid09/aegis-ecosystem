//go:build windows

package telemetry

import "math"

func round1(value float64) float64 {
	return math.Round(value*10) / 10
}
