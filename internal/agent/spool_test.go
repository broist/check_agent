package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/broist/check_agent/internal/model"
)

func TestSpoolPersistsOrdersAndEvictsOldest(t *testing.T) {
	directory := t.TempDir()
	spool, err := NewSpool(directory, 2)
	if err != nil {
		t.Fatal(err)
	}
	for sequence := uint64(1); sequence <= 2; sequence++ {
		if dropped, err := spool.Enqueue(testReport(sequence)); err != nil || dropped != 0 {
			t.Fatalf("enqueue %d: dropped=%d err=%v", sequence, dropped, err)
		}
	}
	reopened, err := NewSpool(directory, 2)
	if err != nil {
		t.Fatal(err)
	}
	if length, err := reopened.Len(); err != nil || length != 2 {
		t.Fatalf("reopened length=%d err=%v", length, err)
	}
	if dropped, err := reopened.Enqueue(testReport(3)); err != nil || dropped != 1 {
		t.Fatalf("bounded enqueue dropped=%d err=%v", dropped, err)
	}
	report, available, err := reopened.Peek()
	if err != nil || !available || report.Sequence != 2 {
		t.Fatalf("peek=%+v available=%v err=%v", report, available, err)
	}
	if err := reopened.Acknowledge(2); err != nil {
		t.Fatal(err)
	}
	report, available, err = reopened.Peek()
	if err != nil || !available || report.Sequence != 3 {
		t.Fatalf("second peek=%+v available=%v err=%v", report, available, err)
	}
}

func TestSpoolCleansIncompleteFileAndRejectsOversize(t *testing.T) {
	directory := t.TempDir()
	temporary := filepath.Join(directory, ".tmp-incomplete")
	if err := os.WriteFile(temporary, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	spool, err := NewSpool(directory, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(temporary); !os.IsNotExist(err) {
		t.Fatalf("incomplete file was not removed: %v", err)
	}
	report := testReport(1)
	report.Kernel = string(make([]byte, maxSpoolReportBytes))
	if _, err := spool.Enqueue(report); err != ErrSpoolReportTooLarge {
		t.Fatalf("oversized report error=%v", err)
	}
}

func TestSenderRetriesAndDrainsDurableSpool(t *testing.T) {
	var mu sync.Mutex
	attempts := 0
	sequences := make([]uint64, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/reports" {
			http.NotFound(response, request)
			return
		}
		var report model.Report
		if err := json.NewDecoder(request.Body).Decode(&report); err != nil {
			http.Error(response, "bad body", http.StatusBadRequest)
			return
		}
		mu.Lock()
		attempts++
		attempt := attempts
		if attempt > 1 {
			sequences = append(sequences, report.Sequence)
		}
		mu.Unlock()
		if attempt == 1 {
			http.Error(response, "temporary", http.StatusServiceUnavailable)
			return
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	spool, err := NewSpool(t.TempDir(), 10)
	if err != nil {
		t.Fatal(err)
	}
	for sequence := uint64(1); sequence <= 2; sequence++ {
		if _, err := spool.Enqueue(testReport(sequence)); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sender := NewSender(server.URL, "test-token", time.Second)
	go sender.Run(ctx, spool, func(error) {})
	for {
		length, err := spool.Len()
		if err != nil {
			t.Fatal(err)
		}
		if length == 0 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("sender did not drain spool: %v", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	cancel()
	mu.Lock()
	defer mu.Unlock()
	if attempts < 3 || len(sequences) != 2 || sequences[0] != 1 || sequences[1] != 2 {
		t.Fatalf("attempts=%d delivered=%v", attempts, sequences)
	}
}

func testReport(sequence uint64) model.Report {
	return model.Report{
		AgentID: "node-01", Sequence: sequence, Timestamp: time.Now().UTC(),
		Memory: model.Memory{},
	}
}
