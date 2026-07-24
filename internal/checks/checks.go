package checks

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/broist/check_agent/internal/config"
	"github.com/broist/check_agent/internal/model"
)

const maxErrorLength = 512

var errorURLPattern = regexp.MustCompile(`https?://[^\s"]+`)

type Checker struct {
	cfg config.Agent
}

func New(cfg config.Agent) *Checker {
	return &Checker{cfg: cfg}
}

func (c *Checker) Collect(ctx context.Context) (
	[]model.ServiceStatus, model.DockerStatus, []model.HTTPStatus, []model.TCPStatus,
) {
	var services []model.ServiceStatus
	var docker model.DockerStatus
	var httpChecks []model.HTTPStatus
	var tcpChecks []model.TCPStatus
	var wait sync.WaitGroup
	wait.Add(4)
	go func() {
		defer wait.Done()
		services = c.collectSystemd(ctx)
	}()
	go func() {
		defer wait.Done()
		docker = c.collectDocker(ctx)
	}()
	go func() {
		defer wait.Done()
		httpChecks = c.collectHTTP(ctx)
	}()
	go func() {
		defer wait.Done()
		tcpChecks = c.collectTCP(ctx)
	}()
	wait.Wait()
	return services, docker, httpChecks, tcpChecks
}

func (c *Checker) collectSystemd(ctx context.Context) []model.ServiceStatus {
	result := make([]model.ServiceStatus, len(c.cfg.SystemdServices))
	var wait sync.WaitGroup
	for index, service := range c.cfg.SystemdServices {
		wait.Add(1)
		go func(index int, service string) {
			defer wait.Done()
			checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			command := exec.CommandContext(checkCtx, "systemctl", "show", service,
				"--property=ActiveState", "--property=SubState", "--no-pager")
			command.Stdin = nil
			output, err := command.Output()
			item := model.ServiceStatus{Name: service}
			if err != nil {
				item.ActiveState = "unknown"
				item.SubState = "unknown"
				item.Error = cleanError(err)
				result[index] = item
				return
			}
			scanner := bufio.NewScanner(strings.NewReader(string(output)))
			for scanner.Scan() {
				key, value, ok := strings.Cut(scanner.Text(), "=")
				if !ok {
					continue
				}
				switch key {
				case "ActiveState":
					item.ActiveState = value
				case "SubState":
					item.SubState = value
				}
			}
			if item.ActiveState == "" {
				item.ActiveState = "unknown"
			}
			if item.SubState == "" {
				item.SubState = "unknown"
			}
			if err := scanner.Err(); err != nil {
				item.Error = cleanError(err)
			}
			result[index] = item
		}(index, service)
	}
	wait.Wait()
	return result
}

func (c *Checker) collectHTTP(ctx context.Context) []model.HTTPStatus {
	result := make([]model.HTTPStatus, len(c.cfg.HTTPChecks))
	var wait sync.WaitGroup
	for index, definition := range c.cfg.HTTPChecks {
		wait.Add(1)
		go func(index int, definition config.HTTPCheck) {
			defer wait.Done()
			result[index] = checkHTTP(ctx, definition)
		}(index, definition)
	}
	wait.Wait()
	return result
}

func checkHTTP(ctx context.Context, definition config.HTTPCheck) model.HTTPStatus {
	safeURL := sanitizedURL(definition.URL)
	item := model.HTTPStatus{Name: definition.Name, URL: safeURL}
	checkCtx, cancel := context.WithTimeout(ctx, definition.Timeout)
	defer cancel()
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: definition.Timeout}).DialContext,
		TLSHandshakeTimeout:   definition.Timeout,
		ResponseHeaderTimeout: definition.Timeout,
		IdleConnTimeout:       30 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		DisableKeepAlives:     true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   definition.Timeout,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			if request.URL.Scheme != "http" && request.URL.Scheme != "https" {
				return errors.New("redirect uses unsupported scheme")
			}
			return nil
		},
	}
	request, err := http.NewRequestWithContext(checkCtx, http.MethodGet, definition.URL, nil)
	if err != nil {
		item.Error = cleanHTTPError(err, definition.URL, safeURL)
		return item
	}
	request.Header.Set("User-Agent", "monitorozo-agent")
	started := time.Now()
	response, err := client.Do(request)
	item.ResponseMS = float64(time.Since(started).Microseconds()) / 1000
	if err != nil {
		item.Error = cleanHTTPError(err, definition.URL, safeURL)
		return item
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	item.StatusCode = response.StatusCode
	item.OK = response.StatusCode >= 200 && response.StatusCode < 400
	if response.TLS != nil && len(response.TLS.PeerCertificates) > 0 {
		days := time.Until(response.TLS.PeerCertificates[0].NotAfter).Hours() / 24
		item.TLSDaysLeft = &days
	}
	return item
}

func (c *Checker) collectTCP(ctx context.Context) []model.TCPStatus {
	result := make([]model.TCPStatus, len(c.cfg.TCPChecks))
	var wait sync.WaitGroup
	for index, definition := range c.cfg.TCPChecks {
		wait.Add(1)
		go func(index int, definition config.TCPCheck) {
			defer wait.Done()
			checkCtx, cancel := context.WithTimeout(ctx, definition.Timeout)
			defer cancel()
			item := model.TCPStatus{Name: definition.Name, Address: definition.Address}
			started := time.Now()
			connection, err := (&net.Dialer{Timeout: definition.Timeout}).
				DialContext(checkCtx, "tcp", definition.Address)
			item.ResponseMS = float64(time.Since(started).Microseconds()) / 1000
			if err != nil {
				item.Error = cleanError(err)
			} else {
				item.Reachable = true
				_ = connection.Close()
			}
			result[index] = item
		}(index, definition)
	}
	wait.Wait()
	return result
}

func (c *Checker) collectDocker(ctx context.Context) model.DockerStatus {
	result := model.DockerStatus{Enabled: c.cfg.Docker.Enabled}
	if !c.cfg.Docker.Enabled {
		return result
	}
	checkCtx, cancel := context.WithTimeout(ctx, c.cfg.Docker.Timeout)
	defer cancel()
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: c.cfg.Docker.Timeout}).
				DialContext(ctx, "unix", c.cfg.Docker.Socket)
		},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(checkCtx, http.MethodGet,
		"http://docker/containers/json?all=1", nil)
	if err != nil {
		result.Error = cleanError(err)
		return result
	}
	response, err := (&http.Client{Transport: transport, Timeout: c.cfg.Docker.Timeout}).Do(request)
	if err != nil {
		result.Error = cleanError(err)
		return result
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		result.Error = fmt.Sprintf("Docker API returned HTTP %d", response.StatusCode)
		return result
	}
	var payload []struct {
		ID     string   `json:"Id"`
		Names  []string `json:"Names"`
		State  string   `json:"State"`
		Status string   `json:"Status"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 4<<20))
	if err := decoder.Decode(&payload); err != nil {
		result.Error = cleanError(err)
		return result
	}
	if len(payload) > model.MaxChecks {
		payload = payload[:model.MaxChecks]
	}
	for _, container := range payload {
		name := shortID(container.ID)
		if len(container.Names) > 0 {
			name = strings.TrimPrefix(container.Names[0], "/")
		}
		result.Containers = append(result.Containers, model.ContainerStatus{
			ID: shortID(container.ID), Name: name, State: container.State,
			Health: dockerHealth(container.Status),
		})
	}
	result.Available = true
	return result
}

func dockerHealth(status string) string {
	open := strings.LastIndex(status, "(")
	close := strings.LastIndex(status, ")")
	if open >= 0 && close > open {
		value := status[open+1 : close]
		switch value {
		case "healthy", "unhealthy", "health: starting":
			return strings.TrimPrefix(value, "health: ")
		}
	}
	return ""
}

func shortID(value string) string {
	if len(value) > 12 {
		return value[:12]
	}
	return value
}

func sanitizedURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func cleanError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.ReplaceAll(err.Error(), "\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	if len(value) > maxErrorLength {
		value = value[:maxErrorLength]
	}
	return value
}

func cleanHTTPError(err error, rawURL, safeURL string) string {
	value := cleanError(err)
	if rawURL != safeURL {
		value = strings.ReplaceAll(value, rawURL, safeURL)
	}
	value = errorURLPattern.ReplaceAllStringFunc(value, sanitizedURL)
	return value
}
