package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/broist/check_agent/internal/model"
)

const maxSpoolReportBytes = 256 << 10

var ErrSpoolReportTooLarge = errors.New("encoded report exceeds spool size limit")

type Spool struct {
	mu      sync.Mutex
	dir     string
	maximum int
	wake    chan struct{}
}

type spoolFile struct {
	name     string
	sequence uint64
	size     int64
}

func NewSpool(directory string, maximum int) (*Spool, error) {
	if directory == "" || maximum < 1 {
		return nil, errors.New("spool directory and positive capacity are required")
	}
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return nil, fmt.Errorf("create spool directory: %w", err)
	}
	if err := os.Chmod(directory, 0o750); err != nil {
		return nil, fmt.Errorf("protect spool directory: %w", err)
	}
	spool := &Spool{
		dir: directory, maximum: maximum, wake: make(chan struct{}, 1),
	}
	if err := spool.cleanTemporaryFiles(); err != nil {
		return nil, err
	}
	spool.mu.Lock()
	_, err := spool.trimLocked()
	spool.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return spool, nil
}

func (s *Spool) Enqueue(report model.Report) (int, error) {
	if report.Sequence == 0 || report.AgentID == "" {
		return 0, errors.New("spool report requires agent ID and positive sequence")
	}
	payload, err := json.Marshal(report)
	if err != nil {
		return 0, fmt.Errorf("encode spool report: %w", err)
	}
	if len(payload) > maxSpoolReportBytes {
		return 0, ErrSpoolReportTooLarge
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	name := reportFilename(report.Sequence)
	target := filepath.Join(s.dir, name)
	if _, err := os.Stat(target); err == nil {
		return 0, fmt.Errorf("spool report %d already exists", report.Sequence)
	} else if !os.IsNotExist(err) {
		return 0, fmt.Errorf("inspect spool report: %w", err)
	}
	temp, err := os.CreateTemp(s.dir, ".tmp-*")
	if err != nil {
		return 0, fmt.Errorf("create spool report: %w", err)
	}
	tempName := temp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tempName)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return 0, fmt.Errorf("protect spool report: %w", err)
	}
	if _, err := temp.Write(payload); err != nil {
		_ = temp.Close()
		return 0, fmt.Errorf("write spool report: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return 0, fmt.Errorf("sync spool report: %w", err)
	}
	if err := temp.Close(); err != nil {
		return 0, fmt.Errorf("close spool report: %w", err)
	}
	if err := os.Rename(tempName, target); err != nil {
		return 0, fmt.Errorf("commit spool report: %w", err)
	}
	committed = true
	select {
	case s.wake <- struct{}{}:
	default:
	}
	if err := syncDirectory(s.dir); err != nil {
		return 0, fmt.Errorf("sync spool directory: %w", err)
	}
	dropped, err := s.trimLocked()
	if err != nil {
		return dropped, err
	}
	return dropped, nil
}

func (s *Spool) Peek() (model.Report, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	files, err := s.listLocked()
	if err != nil {
		return model.Report{}, false, err
	}
	if len(files) == 0 {
		return model.Report{}, false, nil
	}
	path := filepath.Join(s.dir, files[0].name)
	if files[0].size > maxSpoolReportBytes {
		return model.Report{}, false, ErrSpoolReportTooLarge
	}
	handle, err := os.Open(path)
	if err != nil {
		return model.Report{}, false, fmt.Errorf("read spool report: %w", err)
	}
	payload, readErr := io.ReadAll(io.LimitReader(handle, maxSpoolReportBytes+1))
	closeErr := handle.Close()
	if readErr != nil {
		return model.Report{}, false, fmt.Errorf("read spool report: %w", readErr)
	}
	if closeErr != nil {
		return model.Report{}, false, fmt.Errorf("close spool report: %w", closeErr)
	}
	if len(payload) > maxSpoolReportBytes {
		return model.Report{}, false, ErrSpoolReportTooLarge
	}
	var report model.Report
	if err := json.Unmarshal(payload, &report); err != nil {
		return model.Report{}, false, fmt.Errorf("decode spool report %s: %w", files[0].name, err)
	}
	if report.Sequence != files[0].sequence || report.Sequence == 0 || report.AgentID == "" {
		return model.Report{}, false, fmt.Errorf("spool report %s metadata mismatch", files[0].name)
	}
	return report, true, nil
}

func (s *Spool) Acknowledge(sequence uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := filepath.Join(s.dir, reportFilename(sequence))
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove spool report: %w", err)
	}
	if err := syncDirectory(s.dir); err != nil {
		return fmt.Errorf("sync spool directory: %w", err)
	}
	return nil
}

func (s *Spool) Len() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	files, err := s.listLocked()
	return len(files), err
}

func (s *Spool) Wake() <-chan struct{} {
	return s.wake
}

func (s *Spool) trimLocked() (int, error) {
	files, err := s.listLocked()
	if err != nil {
		return 0, err
	}
	dropped := 0
	for len(files) > s.maximum {
		if err := os.Remove(filepath.Join(s.dir, files[0].name)); err != nil {
			return dropped, fmt.Errorf("evict spool report: %w", err)
		}
		files = files[1:]
		dropped++
	}
	if dropped > 0 {
		if err := syncDirectory(s.dir); err != nil {
			return dropped, fmt.Errorf("sync spool eviction: %w", err)
		}
	}
	return dropped, nil
}

func (s *Spool) listLocked() ([]spoolFile, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("list spool directory: %w", err)
	}
	files := make([]spoolFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".tmp-") {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".json") {
			return nil, fmt.Errorf("unexpected file in spool directory: %s", entry.Name())
		}
		raw := strings.TrimSuffix(entry.Name(), ".json")
		sequence, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || sequence == 0 || entry.Name() != reportFilename(sequence) {
			return nil, fmt.Errorf("invalid spool filename: %s", entry.Name())
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect spool file %s: %w", entry.Name(), err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("spool entry is not a regular file: %s", entry.Name())
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("spool file has unsafe permissions: %s", entry.Name())
		}
		files = append(files, spoolFile{
			name: entry.Name(), sequence: sequence, size: info.Size(),
		})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].sequence < files[j].sequence })
	return files, nil
}

func (s *Spool) cleanTemporaryFiles() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("list spool temporary files: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), ".tmp-") {
			continue
		}
		if err := os.Remove(filepath.Join(s.dir, entry.Name())); err != nil {
			return fmt.Errorf("remove incomplete spool report: %w", err)
		}
	}
	return syncDirectory(s.dir)
}

func reportFilename(sequence uint64) string {
	return fmt.Sprintf("%020d.json", sequence)
}

func syncDirectory(directory string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	handle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}

func atomicReplace(source, target string) error {
	if runtime.GOOS == "windows" {
		if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return os.Rename(source, target)
}
