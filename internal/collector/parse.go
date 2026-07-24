package collector

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/example/monitorozo/internal/model"
)

type cpuTimes struct {
	total uint64
	idle  uint64
}

func parseCPU(r io.Reader) (cpuTimes, error) {
	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		return cpuTimes{}, errors.New("missing cpu line")
	}
	fields := strings.Fields(scanner.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuTimes{}, errors.New("invalid cpu line")
	}
	var result cpuTimes
	for i, value := range fields[1:] {
		n, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return cpuTimes{}, fmt.Errorf("parse cpu field: %w", err)
		}
		result.total += n
		if i == 3 || i == 4 {
			result.idle += n
		}
	}
	return result, nil
}

func cpuPercent(previous, current cpuTimes) float64 {
	totalDelta := current.total - previous.total
	if totalDelta == 0 || current.total < previous.total || current.idle < previous.idle {
		return 0
	}
	idleDelta := current.idle - previous.idle
	return clampPercent(float64(totalDelta-idleDelta) * 100 / float64(totalDelta))
}

func parseMemory(r io.Reader) (model.Memory, error) {
	values := make(map[string]uint64)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return model.Memory{}, fmt.Errorf("parse memory field: %w", err)
		}
		values[strings.TrimSuffix(fields[0], ":")] = value * 1024
	}
	if err := scanner.Err(); err != nil {
		return model.Memory{}, err
	}
	total, available := values["MemTotal"], values["MemAvailable"]
	if total == 0 {
		return model.Memory{}, errors.New("MemTotal missing from meminfo")
	}
	if available == 0 {
		available = values["MemFree"] + values["Buffers"] + values["Cached"]
	}
	used := subtractFloor(total, available)
	swapTotal, swapFree := values["SwapTotal"], values["SwapFree"]
	swapUsed := subtractFloor(swapTotal, swapFree)
	return model.Memory{
		TotalBytes: total, UsedBytes: used, AvailableBytes: available,
		UsedPercent: percent(used, total), SwapTotalBytes: swapTotal,
		SwapUsedBytes: swapUsed, SwapPercent: percent(swapUsed, swapTotal),
	}, nil
}

func subtractFloor(total, free uint64) uint64 {
	if free > total {
		return 0
	}
	return total - free
}

func percent(value, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return clampPercent(float64(value) * 100 / float64(total))
}

func clampPercent(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

func unescapeMount(value string) string {
	replacer := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return replacer.Replace(value)
}
