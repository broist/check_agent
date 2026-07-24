//go:build linux

package collector

import (
	"bufio"
	"fmt"
	"os"
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
}

func New(includeFSTypes []string) (*Collector, error) {
	c := &Collector{fsTypes: make(map[string]bool)}
	for _, value := range includeFSTypes {
		c.fsTypes[value] = true
	}
	currentCPU, err := readCPU()
	if err != nil {
		return nil, err
	}
	currentDisk, err := readDiskCounters()
	if err != nil {
		return nil, err
	}
	currentNetwork, err := readNetworkCounters()
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

	currentCPU, err := readCPU()
	if err != nil {
		return model.Report{}, err
	}
	currentDisk, err := readDiskCounters()
	if err != nil {
		return model.Report{}, err
	}
	currentNetwork, err := readNetworkCounters()
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

	memoryFile, err := os.Open("/proc/meminfo")
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

	uptime, err := readUptime()
	if err != nil {
		return model.Report{}, err
	}
	load1, load5, load15, err := readLoad()
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

func readCPU() (cpuTimes, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return cpuTimes{}, fmt.Errorf("open proc stat: %w", err)
	}
	defer file.Close()
	return parseCPU(file)
}

func readDiskCounters() (map[string]diskCounters, error) {
	file, err := os.Open("/proc/diskstats")
	if err != nil {
		return nil, fmt.Errorf("open diskstats: %w", err)
	}
	defer file.Close()
	values, err := parseDiskStats(file)
	if err != nil {
		return nil, err
	}
	for name := range values {
		if !trackBlockDevice(name) {
			delete(values, name)
		}
	}
	return values, nil
}

func readNetworkCounters() (map[string]networkCounters, error) {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil, fmt.Errorf("open network stats: %w", err)
	}
	defer file.Close()
	return parseNetworkStats(file)
}

func trackBlockDevice(name string) bool {
	for _, prefix := range []string{"loop", "ram", "fd"} {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	_, err := os.Stat("/sys/class/block/" + name + "/partition")
	return os.IsNotExist(err)
}

func readUptime() (float64, error) {
	data, err := os.ReadFile("/proc/uptime")
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

func readLoad() (float64, float64, float64, error) {
	data, err := os.ReadFile("/proc/loadavg")
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
	file, err := os.Open("/proc/self/mountinfo")
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
		var stat unix.Statfs_t
		if err := unix.Statfs(mountpoint, &stat); err != nil {
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
