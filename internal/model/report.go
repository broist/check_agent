package model

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"strings"
	"time"
)

const (
	MaxFilesystems = 128
	MaxDiskDevices = 128
	MaxInterfaces  = 128
	MaxChecks      = 32
	MaxAgentIDLen  = 128
)

type Report struct {
	AgentID     string          `json:"agent_id"`
	Timestamp   time.Time       `json:"timestamp"`
	Sequence    uint64          `json:"sequence"`
	Version     string          `json:"version"`
	Hostname    string          `json:"hostname"`
	CPUPercent  float64         `json:"cpu_percent"`
	Load1       float64         `json:"load_1"`
	Load5       float64         `json:"load_5"`
	Load15      float64         `json:"load_15"`
	Memory      Memory          `json:"memory"`
	Filesystems []Filesystem    `json:"filesystems"`
	DiskIO      []DiskIO        `json:"disk_io"`
	Networks    []NetworkIO     `json:"networks"`
	Services    []ServiceStatus `json:"services,omitempty"`
	Docker      DockerStatus    `json:"docker,omitempty"`
	HTTPChecks  []HTTPStatus    `json:"http_checks,omitempty"`
	TCPChecks   []TCPStatus     `json:"tcp_checks,omitempty"`
	Uptime      uint64          `json:"uptime_seconds"`
	BootTime    time.Time       `json:"boot_time"`
	Kernel      string          `json:"kernel"`
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

type DiskIO struct {
	Device              string  `json:"device"`
	ReadBytes           uint64  `json:"read_bytes"`
	WriteBytes          uint64  `json:"write_bytes"`
	ReadOperations      uint64  `json:"read_operations"`
	WriteOperations     uint64  `json:"write_operations"`
	ReadBytesPerSecond  float64 `json:"read_bytes_per_second"`
	WriteBytesPerSecond float64 `json:"write_bytes_per_second"`
	ReadOpsPerSecond    float64 `json:"read_ops_per_second"`
	WriteOpsPerSecond   float64 `json:"write_ops_per_second"`
}

type NetworkIO struct {
	Interface          string  `json:"interface"`
	ReceiveBytes       uint64  `json:"receive_bytes"`
	TransmitBytes      uint64  `json:"transmit_bytes"`
	ReceivePackets     uint64  `json:"receive_packets"`
	TransmitPackets    uint64  `json:"transmit_packets"`
	ReceiveBytesRate   float64 `json:"receive_bytes_per_second"`
	TransmitBytesRate  float64 `json:"transmit_bytes_per_second"`
	ReceivePacketRate  float64 `json:"receive_packets_per_second"`
	TransmitPacketRate float64 `json:"transmit_packets_per_second"`
}

type ServiceStatus struct {
	Name        string `json:"name"`
	ActiveState string `json:"active_state"`
	SubState    string `json:"sub_state"`
	Error       string `json:"error,omitempty"`
}

type DockerStatus struct {
	Enabled    bool              `json:"enabled"`
	Available  bool              `json:"available"`
	Error      string            `json:"error,omitempty"`
	Containers []ContainerStatus `json:"containers,omitempty"`
}

type ContainerStatus struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	State  string `json:"state"`
	Health string `json:"health,omitempty"`
}

type HTTPStatus struct {
	Name        string   `json:"name"`
	URL         string   `json:"url"`
	StatusCode  int      `json:"status_code"`
	ResponseMS  float64  `json:"response_ms"`
	OK          bool     `json:"ok"`
	Error       string   `json:"error,omitempty"`
	TLSDaysLeft *float64 `json:"tls_days_left,omitempty"`
}

func (status HTTPStatus) TLSDays() float64 {
	if status.TLSDaysLeft == nil {
		return 0
	}
	return *status.TLSDaysLeft
}

type TCPStatus struct {
	Name       string  `json:"name"`
	Address    string  `json:"address"`
	Reachable  bool    `json:"reachable"`
	ResponseMS float64 `json:"response_ms"`
	Error      string  `json:"error,omitempty"`
}

func (r Report) Validate(now time.Time, maxFutureSkew, maxAge time.Duration) error {
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
	if r.Timestamp.IsZero() || r.Timestamp.Before(now.Add(-maxAge)) ||
		r.Timestamp.After(now.Add(maxFutureSkew)) {
		return errors.New("timestamp is outside the accepted report age or clock skew")
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
	if len(r.DiskIO) > MaxDiskDevices {
		return fmt.Errorf("too many disk devices: maximum is %d", MaxDiskDevices)
	}
	for _, disk := range r.DiskIO {
		if disk.Device == "" || len(disk.Device) > 128 ||
			!validRate(disk.ReadBytesPerSecond) || !validRate(disk.WriteBytesPerSecond) ||
			!validRate(disk.ReadOpsPerSecond) || !validRate(disk.WriteOpsPerSecond) {
			return errors.New("invalid disk I/O data")
		}
	}
	if len(r.Networks) > MaxInterfaces {
		return fmt.Errorf("too many network interfaces: maximum is %d", MaxInterfaces)
	}
	for _, network := range r.Networks {
		if network.Interface == "" || len(network.Interface) > 128 ||
			!validRate(network.ReceiveBytesRate) || !validRate(network.TransmitBytesRate) ||
			!validRate(network.ReceivePacketRate) || !validRate(network.TransmitPacketRate) {
			return errors.New("invalid network I/O data")
		}
	}
	if len(r.Services) > MaxChecks || len(r.HTTPChecks) > MaxChecks ||
		len(r.TCPChecks) > MaxChecks || len(r.Docker.Containers) > MaxChecks {
		return fmt.Errorf("too many optional check results: maximum is %d per type", MaxChecks)
	}
	for _, service := range r.Services {
		if !validCheckName(service.Name) || len(service.ActiveState) > 64 ||
			len(service.SubState) > 64 || len(service.Error) > 512 {
			return errors.New("invalid systemd service status")
		}
	}
	if len(r.Docker.Error) > 512 {
		return errors.New("invalid Docker status")
	}
	for _, container := range r.Docker.Containers {
		if !validCheckName(container.Name) || len(container.ID) > 128 ||
			len(container.State) > 64 || len(container.Health) > 64 {
			return errors.New("invalid Docker container status")
		}
	}
	for _, check := range r.HTTPChecks {
		if !validCheckName(check.Name) || len(check.URL) > 2048 ||
			check.StatusCode < 0 || check.StatusCode > 999 ||
			!validRate(check.ResponseMS) || len(check.Error) > 512 {
			return errors.New("invalid HTTP check status")
		}
		parsed, err := url.ParseRequestURI(check.URL)
		if err != nil || parsed.Host == "" ||
			(parsed.Scheme != "http" && parsed.Scheme != "https") ||
			parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return errors.New("HTTP check URL must be a redacted http(s) URL")
		}
		if check.TLSDaysLeft != nil && (math.IsNaN(*check.TLSDaysLeft) ||
			math.IsInf(*check.TLSDaysLeft, 0)) {
			return errors.New("invalid TLS certificate lifetime")
		}
	}
	for _, check := range r.TCPChecks {
		if !validCheckName(check.Name) || len(check.Address) > 512 ||
			!validRate(check.ResponseMS) || len(check.Error) > 512 {
			return errors.New("invalid TCP check status")
		}
		if _, _, err := net.SplitHostPort(check.Address); err != nil {
			return errors.New("invalid TCP check address")
		}
	}
	return nil
}

func validRate(value float64) bool {
	return value >= 0 && !math.IsNaN(value) && !math.IsInf(value, 0)
}

func safeLabel(value string) bool {
	return strings.IndexFunc(value, func(r rune) bool {
		return !(r == '-' || r == '_' || r == '.' || r == '@' ||
			r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
	}) == -1
}

func validCheckName(value string) bool {
	return value != "" && len(value) <= 128 && safeLabel(value)
}
