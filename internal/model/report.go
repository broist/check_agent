package model

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

const (
	MaxFilesystems = 128
	MaxAgentIDLen  = 128
)

type Report struct {
	AgentID     string       `json:"agent_id"`
	Timestamp   time.Time    `json:"timestamp"`
	Sequence    uint64       `json:"sequence"`
	Version     string       `json:"version"`
	Hostname    string       `json:"hostname"`
	CPUPercent  float64      `json:"cpu_percent"`
	Load1       float64      `json:"load_1"`
	Load5       float64      `json:"load_5"`
	Load15      float64      `json:"load_15"`
	Memory      Memory       `json:"memory"`
	Filesystems []Filesystem `json:"filesystems"`
	Uptime      uint64       `json:"uptime_seconds"`
	BootTime    time.Time    `json:"boot_time"`
	Kernel      string       `json:"kernel"`
}

type Memory struct {
	TotalBytes     uint64  `json:"total_bytes"`
	UsedBytes      uint64  `json:"used_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	UsedPercent    float64 `json:"used_percent"`
	SwapTotalBytes uint64  `json:"swap_total_bytes"`
	SwapUsedBytes  uint64  `json:"swap_used_bytes"`
	SwapPercent    float64 `json:"swap_percent"`
}

type Filesystem struct {
	Mountpoint  string  `json:"mountpoint"`
	Device      string  `json:"device"`
	FSType      string  `json:"fs_type"`
	TotalBytes  uint64  `json:"total_bytes"`
	UsedBytes   uint64  `json:"used_bytes"`
	AvailBytes  uint64  `json:"available_bytes"`
	UsedPercent float64 `json:"used_percent"`
}

func (r Report) Validate(now time.Time, maxSkew time.Duration) error {
	if r.AgentID == "" || len(r.AgentID) > MaxAgentIDLen {
		return errors.New("agent_id is missing or too long")
	}
	if !safeLabel(r.AgentID) {
		return errors.New("agent_id contains unsupported characters")
	}
	if r.Sequence == 0 {
		return errors.New("sequence must be greater than zero")
	}
	if r.Sequence > math.MaxInt64 {
		return errors.New("sequence is too large")
	}
	if r.Timestamp.IsZero() || r.Timestamp.Before(now.Add(-maxSkew)) || r.Timestamp.After(now.Add(maxSkew)) {
		return errors.New("timestamp is outside the accepted clock skew")
	}
	if r.CPUPercent < 0 || r.CPUPercent > 100 {
		return errors.New("cpu_percent must be between 0 and 100")
	}
	if r.Memory.UsedPercent < 0 || r.Memory.UsedPercent > 100 ||
		r.Memory.SwapPercent < 0 || r.Memory.SwapPercent > 100 {
		return errors.New("memory percentages must be between 0 and 100")
	}
	if len(r.Filesystems) > MaxFilesystems {
		return fmt.Errorf("too many filesystems: maximum is %d", MaxFilesystems)
	}
	for _, fs := range r.Filesystems {
		if fs.Mountpoint == "" || len(fs.Mountpoint) > 1024 || len(fs.Device) > 1024 || len(fs.FSType) > 128 {
			return errors.New("invalid filesystem metadata")
		}
		if fs.UsedPercent < 0 || fs.UsedPercent > 100 {
			return errors.New("filesystem percentage must be between 0 and 100")
		}
	}
	return nil
}

func safeLabel(value string) bool {
	return strings.IndexFunc(value, func(r rune) bool {
		return !(r == '-' || r == '_' || r == '.' ||
			r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
	}) == -1
}
