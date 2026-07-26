//go:build linux

package collector

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/broist/check_agent/internal/model"
	"github.com/broist/check_agent/internal/version"
	"golang.org/x/sys/unix"
)

type Collector struct {
	mu              sync.Mutex
	previousCPU     cpuTimes
	previousDisk    map[string]diskCounters
	previousNetwork map[string]networkCounters
	previousAt      time.Time
	fsTypes         map[string]bool
	paths           Paths
}

type Paths struct {
	ProcRoot      string
	SysRoot       string
	HostRoot      string
	MountInfoPath string
}

func New(includeFSTypes []string) (*Collector, error) {
	return NewWithPaths(includeFSTypes, Paths{})
}

func NewWithPaths(includeFSTypes []string, paths Paths) (*Collector, error) {
	if paths.ProcRoot == "" {
		paths.ProcRoot = "/proc"
	}
	if paths.SysRoot == "" {
		paths.SysRoot = "/sys"
	}
	if paths.HostRoot == "" {
		paths.HostRoot = "/"
	}
	if paths.MountInfoPath == "" {
		paths.MountInfoPath = filepath.Join(paths.ProcRoot, "self/mountinfo")
	}
	c := &Collector{fsTypes: make(map[string]bool), paths: paths}
	for _, value := range includeFSTypes {
		c.fsTypes[value] = true
	}
	currentCPU, err := c.readCPU()
	if err != nil {
		return nil, err
	}
	currentDisk, err := c.readDiskCounters()
	if err != nil {
		return nil, err
	}
	currentNetwork, err := c.readNetworkCounters()
	if err != nil {
		return nil, err
	}
	c.previousCPU = currentCPU
	c.previousDisk = currentDisk
	c.previousNetwork = currentNetwork
	c.previousAt = time.Now().UTC()
	return c, nil
}

func (c *Collector) Collect() (model.Report, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	currentCPU, err := c.readCPU()
	if err != nil {
		return model.Report{}, err
	}
	currentDisk, err := c.readDiskCounters()
	if err != nil {
		return model.Report{}, err
	}
	currentNetwork, err := c.readNetworkCounters()
	if err != nil {
		return model.Report{}, err
	}
	sampledAt := time.Now().UTC()
	elapsed := sampledAt.Sub(c.previousAt).Seconds()
	if elapsed < 1 {
		elapsed = 1
	}
	cpu := cpuPercent(c.previousCPU, currentCPU)
	diskIO := calculateDiskIO(c.previousDisk, currentDisk, elapsed)
	networkIO := calculateNetworkIO(c.previousNetwork, currentNetwork, elapsed)

	memoryFile, err := os.Open(filepath.Join(c.paths.ProcRoot, "meminfo"))
	if err != nil {
		return model.Report{}, fmt.Errorf("open meminfo: %w", err)
	}
	memory, parseErr := parseMemory(memoryFile)
	closeErr := memoryFile.Close()
	if parseErr != nil {
		return model.Report{}, parseErr
	}
	if closeErr != nil {
		return model.Report{}, closeErr
	}

	uptime, err := c.readUptime()
	if err != nil {
		return model.Report{}, err
	}
	load1, load5, load15, err := c.readLoad()
	if err != nil {
		return model.Report{}, err
	}
	filesystems, err := c.readFilesystems()
	if err != nil {
		return model.Report{}, err
	}
	hostname, err := os.Hostname()
	if err != nil {
		return model.Report{}, fmt.Errorf("hostname: %w", err)
	}
	c.previousCPU = currentCPU
	c.previousDisk = currentDisk
	c.previousNetwork = currentNetwork
	c.previousAt = sampledAt
	return model.Report{
		Timestamp: sampledAt, Version: version.Version, Hostname: hostname,
		CPUPercent: cpu, Load1: load1, Load5: load5, Load15: load15,
		Memory: memory, Filesystems: filesystems, DiskIO: diskIO, Networks: networkIO,
		Uptime:   uint64(uptime),
		BootTime: sampledAt.Add(-time.Duration(uptime) * time.Second),
		Kernel:   kernelVersion(),
	}, nil
}

func (c *Collector) readCPU() (cpuTimes, error) {
	file, err := os.Open(filepath.Join(c.paths.ProcRoot, "stat"))
	if err != nil {
		return cpuTimes{}, fmt.Errorf("open proc stat: %w", err)
	}
	defer file.Close()
	return parseCPU(file)
}

func (c *Collector) readDiskCounters() (map[string]diskCounters, error) {
	file, err := os.Open(filepath.Join(c.paths.ProcRoot, "diskstats"))
	if err != nil {
		return nil, fmt.Errorf("open diskstats: %w", err)
	}
	defer file.Close()
	values, err := parseDiskStats(file)
	if err != nil {
		return nil, err
	}
	for name := range values {
		if !c.trackBlockDevice(name) {
			delete(values, name)
		}
	}
	return values, nil
}

func (c *Collector) readNetworkCounters() (map[string]networkCounters, error) {
	file, err := os.Open(filepath.Join(c.paths.ProcRoot, "net/dev"))
	if err != nil {
		return nil, fmt.Errorf("open network stats: %w", err)
	}
	defer file.Close()
	return parseNetworkStats(file)
}

func (c *Collector) trackBlockDevice(name string) bool {
	for _, prefix := range []string{"loop", "ram", "fd"} {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	_, err := os.Stat(filepath.Join(c.paths.SysRoot, "class/block", name, "partition"))
	return os.IsNotExist(err)
}

func (c *Collector) readUptime() (float64, error) {
	data, err := os.ReadFile(filepath.Join(c.paths.ProcRoot, "uptime"))
	if err != nil {
		return 0, fmt.Errorf("read uptime: %w", err)
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, fmt.Errorf("invalid uptime")
	}
	value, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, fmt.Errorf("parse uptime: %w", err)
	}
	return value, nil
}

func (c *Collector) readLoad() (float64, float64, float64, error) {
	data, err := os.ReadFile(filepath.Join(c.paths.ProcRoot, "loadavg"))
	if err != nil {
		return 0, 0, 0, fmt.Errorf("read loadavg: %w", err)
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return 0, 0, 0, fmt.Errorf("invalid loadavg")
	}
	values := make([]float64, 3)
	for i := range values {
		values[i], err = strconv.ParseFloat(fields[i], 64)
		if err != nil {
			return 0, 0, 0, fmt.Errorf("parse loadavg: %w", err)
		}
	}
	return values[0], values[1], values[2], nil
}

func (c *Collector) readFilesystems() ([]model.Filesystem, error) {
	file, err := os.Open(c.paths.MountInfoPath)
	if err != nil {
		return nil, fmt.Errorf("open mountinfo: %w", err)
	}
	defer file.Close()
	seen := make(map[string]bool)
	var result []model.Filesystem
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		separator := -1
		for i, field := range fields {
			if field == "-" {
				separator = i
				break
			}
		}
		if separator < 0 || separator+2 >= len(fields) || len(fields) < 6 {
			continue
		}
		mountpoint, fsType, device := unescapeMount(fields[4]), fields[separator+1], unescapeMount(fields[separator+2])
		if seen[mountpoint] || !c.includeFilesystem(fsType) {
			continue
		}
		seen[mountpoint] = true
		statTarget, ok := c.statTarget(mountpoint)
		if !ok {
			continue
		}
		var stat unix.Statfs_t
		if err := unix.Statfs(statTarget, &stat); err != nil {
			continue
		}
		total := stat.Blocks * uint64(stat.Bsize)
		available := stat.Bavail * uint64(stat.Bsize)
		used := (stat.Blocks - stat.Bfree) * uint64(stat.Bsize)
		result = append(result, model.Filesystem{
			Mountpoint: mountpoint, Device: device, FSType: fsType,
			TotalBytes: total, UsedBytes: used, AvailBytes: available,
			UsedPercent: percent(used, total),
		})
		if len(result) == model.MaxFilesystems {
			break
		}
	}
	return result, scanner.Err()
}

func (c *Collector) statTarget(mountpoint string) (string, bool) {
	if c.paths.HostRoot == "/" {
		return mountpoint, true
	}
	target := filepath.Join(c.paths.HostRoot, strings.TrimPrefix(mountpoint, "/"))
	relative, err := filepath.Rel(c.paths.HostRoot, target)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", false
	}
	return target, true
}

func (c *Collector) includeFilesystem(fsType string) bool {
	if len(c.fsTypes) > 0 {
		return c.fsTypes[fsType]
	}
	switch fsType {
	case "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup", "cgroup2",
		"securityfs", "pstore", "debugfs", "tracefs", "configfs", "fusectl",
		"mqueue", "hugetlbfs", "autofs", "binfmt_misc":
		return false
	default:
		return true
	}
}

func kernelVersion() string {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return "unknown"
	}
	bytes := make([]byte, 0, len(uts.Release))
	for _, value := range uts.Release {
		if value == 0 {
			break
		}
		bytes = append(bytes, byte(value))
	}
	return string(bytes)
}
