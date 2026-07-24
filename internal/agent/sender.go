package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"time"

	"github.com/example/monitorozo/internal/model"
)

type Sender struct {
	url    string
	token  string
	client *http.Client
}

func NewSender(url, token string, timeout time.Duration) *Sender {
	return &Sender{
		url: url, token: token,
		client: &http.Client{Timeout: timeout},
	}
}

func (s *Sender) Run(ctx context.Context, queue <-chan model.Report, onError func(error)) {
	for {
		select {
		case <-ctx.Done():
			return
		case report := <-queue:
			if err := s.sendWithRetry(ctx, report); err != nil && !errors.Is(err, context.Canceled) {
				onError(err)
			}
		}
	}
}

func (s *Sender) sendWithRetry(ctx context.Context, report model.Report) error {
	delay := time.Second
	for {
		retry, err := s.send(ctx, report)
		if err == nil {
			return nil
		}
		if !retry {
			return err
		}
		jitter := time.Duration(rand.IntN(500)) * time.Millisecond
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay + jitter):
		}
		if delay < 30*time.Second {
			delay *= 2
		}
		if delay > 30*time.Second {
			delay = 30 * time.Second
		}
	}
}

func (s *Sender) send(ctx context.Context, report model.Report) (bool, error) {
	body, err := json.Marshal(report)
	if err != nil {
		return false, fmt.Errorf("encode report: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url+"/api/v1/reports", bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+s.token)
	request.Header.Set("Content-Type", "application/json")
	response, err := s.client.Do(request)
	if err != nil {
		return true, fmt.Errorf("send report: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return false, nil
	}
	retry := response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500
	return retry, fmt.Errorf("server returned status %d", response.StatusCode)
}
