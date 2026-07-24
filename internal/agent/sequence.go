package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

type Sequence struct {
	mu    sync.Mutex
	path  string
	value uint64
}

func NewSequence(path string) (*Sequence, error) {
	s := &Sequence{path: path}
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read sequence: %w", err)
	}
	if err == nil {
		s.value, err = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse sequence: %w", err)
		}
	}
	return s, nil
}

func (s *Sequence) Next() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.value + 1
	if next == 0 {
		return 0, fmt.Errorf("sequence exhausted")
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return 0, fmt.Errorf("create state directory: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(s.path), ".sequence-*")
	if err != nil {
		return 0, fmt.Errorf("create sequence state: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return 0, fmt.Errorf("protect sequence state: %w", err)
	}
	if _, err := temp.WriteString(strconv.FormatUint(next, 10) + "\n"); err != nil {
		_ = temp.Close()
		return 0, fmt.Errorf("write sequence: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return 0, fmt.Errorf("sync sequence: %w", err)
	}
	if err := temp.Close(); err != nil {
		return 0, fmt.Errorf("close sequence: %w", err)
	}
	if err := atomicReplace(tempName, s.path); err != nil {
		return 0, fmt.Errorf("commit sequence: %w", err)
	}
	if err := syncDirectory(filepath.Dir(s.path)); err != nil {
		return 0, fmt.Errorf("sync sequence directory: %w", err)
	}
	s.value = next
	return next, nil
}
