package agent

import (
	"path/filepath"
	"testing"
)

func TestSequencePersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sequence")
	sequence, err := NewSequence(path)
	if err != nil {
		t.Fatal(err)
	}
	if value, err := sequence.Next(); err != nil || value != 1 {
		t.Fatalf("first sequence=%d err=%v", value, err)
	}
	reopened, err := NewSequence(path)
	if err != nil {
		t.Fatal(err)
	}
	if value, err := reopened.Next(); err != nil || value != 2 {
		t.Fatalf("reopened sequence=%d err=%v", value, err)
	}
}
