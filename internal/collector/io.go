package collector

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/broist/check_agent/internal/model"
)

const diskSectorBytes = 512

type diskCounters struct {
	readIOs      uint64
	readSectors  uint64
	writeIOs     uint64
	writeSectors uint64
}

type networkCounters struct {
	receiveBytes    uint64
	receivePackets  uint64
	transmitBytes   uint64
	transmitPackets uint64
}

func parseDiskStats(reader io.Reader) (map[string]diskCounters, error) {
	result := make(map[string]diskCounters)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 14 {
			continue
		}
		values := make([]uint64, 4)
		for index, fieldIndex := range []int{3, 5, 7, 9} {
			value, err := strconv.ParseUint(fields[fieldIndex], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("parse diskstats field for %s: %w", fields[2], err)
			}
			values[index] = value
		}
		result[fields[2]] = diskCounters{
			readIOs: values[0], readSectors: values[1],
			writeIOs: values[2], writeSectors: values[3],
		}
	}
	return result, scanner.Err()
}

func parseNetworkStats(reader io.Reader) (map[string]networkCounters, error) {
	result := make(map[string]networkCounters)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		separator := strings.IndexByte(line, ':')
		if separator < 0 {
			continue
		}
		name := strings.TrimSpace(line[:separator])
		fields := strings.Fields(line[separator+1:])
		if name == "" || len(fields) < 16 {
			continue
		}
		values := make([]uint64, 4)
		for index, fieldIndex := range []int{0, 1, 8, 9} {
			value, err := strconv.ParseUint(fields[fieldIndex], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("parse network field for %s: %w", name, err)
			}
			values[index] = value
		}
		result[name] = networkCounters{
			receiveBytes: values[0], receivePackets: values[1],
			transmitBytes: values[2], transmitPackets: values[3],
		}
	}
	return result, scanner.Err()
}

func calculateDiskIO(previous, current map[string]diskCounters, elapsed float64) []model.DiskIO {
	if elapsed <= 0 {
		elapsed = 1
	}
	names := sortedKeys(current)
	result := make([]model.DiskIO, 0, min(len(names), model.MaxDiskDevices))
	for _, name := range names {
		if len(result) == model.MaxDiskDevices {
			break
		}
		value := current[name]
		before := previous[name]
		readBytes := value.readSectors * diskSectorBytes
		writeBytes := value.writeSectors * diskSectorBytes
		result = append(result, model.DiskIO{
			Device: name, ReadBytes: readBytes, WriteBytes: writeBytes,
			ReadOperations: value.readIOs, WriteOperations: value.writeIOs,
			ReadBytesPerSecond:  float64(counterDelta(value.readSectors, before.readSectors)*diskSectorBytes) / elapsed,
			WriteBytesPerSecond: float64(counterDelta(value.writeSectors, before.writeSectors)*diskSectorBytes) / elapsed,
			ReadOpsPerSecond:    float64(counterDelta(value.readIOs, before.readIOs)) / elapsed,
			WriteOpsPerSecond:   float64(counterDelta(value.writeIOs, before.writeIOs)) / elapsed,
		})
	}
	return result
}

func calculateNetworkIO(previous, current map[string]networkCounters, elapsed float64) []model.NetworkIO {
	if elapsed <= 0 {
		elapsed = 1
	}
	names := sortedKeys(current)
	result := make([]model.NetworkIO, 0, min(len(names), model.MaxInterfaces))
	for _, name := range names {
		if len(result) == model.MaxInterfaces {
			break
		}
		value := current[name]
		before := previous[name]
		result = append(result, model.NetworkIO{
			Interface: name, ReceiveBytes: value.receiveBytes, TransmitBytes: value.transmitBytes,
			ReceivePackets: value.receivePackets, TransmitPackets: value.transmitPackets,
			ReceiveBytesRate:   float64(counterDelta(value.receiveBytes, before.receiveBytes)) / elapsed,
			TransmitBytesRate:  float64(counterDelta(value.transmitBytes, before.transmitBytes)) / elapsed,
			ReceivePacketRate:  float64(counterDelta(value.receivePackets, before.receivePackets)) / elapsed,
			TransmitPacketRate: float64(counterDelta(value.transmitPackets, before.transmitPackets)) / elapsed,
		})
	}
	return result
}

func counterDelta(current, previous uint64) uint64 {
	if current < previous {
		return 0
	}
	return current - previous
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
