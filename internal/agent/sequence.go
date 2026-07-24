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
	temp := s.path + ".tmp"
	if err := os.WriteFile(temp, []byte(strconv.FormatUint(next, 10)+"\n"), 0o600); err != nil {
		return 0, fmt.Errorf("write sequence: %w", err)
	}
	if err := os.Rename(temp, s.path); err != nil {
		return 0, fmt.Errorf("commit sequence: %w", err)
	}
	s.value = next
	return next, nil
}
