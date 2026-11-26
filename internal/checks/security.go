package checks

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/broist/check_agent/internal/config"
	"github.com/broist/check_agent/internal/model"
)

const (
	packageCommandTimeout = 60 * time.Second
	maxCommandOutput      = 64 << 10
	maxSummaryBytes       = 1 << 20

	// User-facing messages shown on the dashboard (Hungarian UI copy).
	msgPackagesPending     = "Az első csomagellenőrzés folyamatban."
	MsgNoVulnerabilityScan = "Még nem készült CVE-vizsgálat."
)

var (
	// DefaultRebootPaths lists the reboot marker locations in lookup order.
	DefaultRebootPaths = []string{"/run/reboot-required", "/var/run/reboot-required"}
	aptCheckLine       = regexp.MustCompile(`^\s*(\d+);(\d+)\s*$`)
)

// CommandRunner executes a command and returns its stdout and stderr.
type CommandRunner func(ctx context.Context, argv []string) (stdout, stderr []byte, err error)

// Security collects package-update state in the background and reads the
// CVE summary written by the root-owned monitorozo-cvescan job. Neither path
// needs Docker socket access.
type Security struct {
	packages    config.PackageChecks
	vulnPath    string
	rebootPaths []string
	run         CommandRunner
	now         func() time.Time

	mu       sync.Mutex
	pkg      model.PackageStatus
	vulnKey  fileKey
	vulnLast *model.VulnerabilityStatus
}

type fileKey struct {
	modTime time.Time
	size    int64
}

func NewSecurity(cfg config.Agent) *Security {
	return &Security{
		packages:    cfg.Packages,
		vulnPath:    cfg.VulnerabilityReport.Path,
		rebootPaths: DefaultRebootPaths,
		run:         execCommand,
		now:         time.Now,
		pkg:         model.PackageStatus{Error: msgPackagesPending},
	}
}

// SetRebootPaths overrides the reboot marker locations (tests).
func (s *Security) SetRebootPaths(paths []string) { s.rebootPaths = paths }

// SetRunner overrides the command runner (tests).
func (s *Security) SetRunner(run CommandRunner) { s.run = run }

// Run refreshes the package status immediately and then every interval until
// ctx is cancelled. It never blocks report collection.
func (s *Security) Run(ctx context.Context) {
	if !s.packages.Enabled {
		return
	}
	ticker := time.NewTicker(s.packages.Interval)
	defer ticker.Stop()
	for {
		s.RefreshPackages(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// RefreshPackages runs the configured apt-check command once.
func (s *Security) RefreshPackages(ctx context.Context) {
	argv := strings.Fields(s.packages.Command)
	if len(argv) == 0 {
		return
	}
	checkCtx, cancel := context.WithTimeout(ctx, packageCommandTimeout)
	defer cancel()
	stdout, stderr, err := s.run(checkCtx, argv)
	if ctx.Err() != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.pkg.Error = describeCommandError(checkCtx, argv[0], err, stderr)
		return
	}
	upgradable, security, parseErr := ParseAptCheck(stderr, stdout)
	if parseErr != nil {
		s.pkg.Error = truncateUTF8(parseErr.Error(), model.MaxSecurityError)
		return
	}
	s.pkg.Upgradable, s.pkg.Security = upgradable, security
	s.pkg.CheckedAt = s.now().UTC()
	s.pkg.Error = ""
}

// Packages returns the latest package status with the current reboot state,
// or nil when package checks are disabled.
func (s *Security) Packages() *model.PackageStatus {
	if !s.packages.Enabled {
		return nil
	}
	s.mu.Lock()
	status := s.pkg
	s.mu.Unlock()
	status.RebootRequired, status.RebootPackages = ReadRebootRequired(s.rebootPaths)
	return &status
}

// Vulnerabilities returns the cached CVE summary, re-reading the file only when
// its modification time or size changed. It returns nil when disabled.
func (s *Security) Vulnerabilities() *model.VulnerabilityStatus {
	if s.vulnPath == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	info, err := os.Stat(s.vulnPath)
	if errors.Is(err, fs.ErrNotExist) {
		s.vulnKey, s.vulnLast = fileKey{}, nil
		return &model.VulnerabilityStatus{Error: MsgNoVulnerabilityScan}
	}
	if err != nil {
		return s.vulnerabilityError("A CVE-összesítő nem olvasható: " + cleanError(err))
	}
	key := fileKey{modTime: info.ModTime(), size: info.Size()}
	if s.vulnLast != nil && key == s.vulnKey {
		return copyVulnerabilities(s.vulnLast)
	}
	status, err := ReadVulnerabilitySummary(s.vulnPath)
	if err != nil {
		return s.vulnerabilityError("A CVE-összesítő érvénytelen: " + cleanError(err))
	}
	s.vulnKey, s.vulnLast = key, &status
	return copyVulnerabilities(&status)
}

// vulnerabilityError keeps the last good scan result visible and adds an error.
func (s *Security) vulnerabilityError(message string) *model.VulnerabilityStatus {
	result := &model.VulnerabilityStatus{}
	if s.vulnLast != nil {
		result = copyVulnerabilities(s.vulnLast)
	}
	result.Error = truncateUTF8(message, model.MaxSecurityError)
	return result
}

// ReadVulnerabilitySummary loads and validates a trivy-summary output file.
func ReadVulnerabilitySummary(path string) (model.VulnerabilityStatus, error) {
	var status model.VulnerabilityStatus
	file, err := os.Open(path)
	if err != nil {
		return status, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxSummaryBytes+1))
	if err != nil {
		return status, err
	}
	if len(data) > maxSummaryBytes {
		return status, errors.New("the summary file is larger than 1 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&status); err != nil {
		return model.VulnerabilityStatus{}, err
	}
	if err := status.Validate(); err != nil {
		return model.VulnerabilityStatus{}, err
	}
	return status, nil
}

func copyVulnerabilities(source *model.VulnerabilityStatus) *model.VulnerabilityStatus {
	result := *source
	result.Images = append([]model.ImageVulnerabilities(nil), source.Images...)
	return &result
}

// ParseAptCheck extracts "UPGRADABLE;SECURITY" from apt-check output. The
// helper writes it to stderr, but every stream is accepted.
func ParseAptCheck(streams ...[]byte) (upgradable, security int, err error) {
	var sample string
	for _, stream := range streams {
		scanner := bufio.NewScanner(bytes.NewReader(stream))
		for scanner.Scan() {
			line := scanner.Text()
			if sample == "" && strings.TrimSpace(line) != "" {
				sample = strings.TrimSpace(line)
			}
			match := aptCheckLine.FindStringSubmatch(line)
			if match == nil {
				continue
			}
			upgradable, errA := strconv.Atoi(match[1])
			security, errB := strconv.Atoi(match[2])
			if errA != nil || errB != nil || upgradable > model.MaxPackageCount ||
				security > upgradable {
				return 0, 0, fmt.Errorf("Az apt-check kimenete nem értelmezhető: %q", line)
			}
			return upgradable, security, nil
		}
	}
	if sample == "" {
		return 0, 0, errors.New("Az apt-check nem adott kimenetet (várt forma: FRISSÍTHETŐ;BIZTONSÁGI).")
	}
	return 0, 0, fmt.Errorf("Az apt-check kimenete nem értelmezhető: %q", truncateUTF8(sample, 200))
}

// ReadRebootRequired reports whether the first existing marker is present and
// the unique, sorted packages from the matching ".pkgs" file (at most 32).
func ReadRebootRequired(paths []string) (bool, []string) {
	for _, marker := range paths {
		if _, err := os.Stat(marker); err != nil {
			continue
		}
		return true, readRebootPackages(marker + ".pkgs")
	}
	return false, nil
}

func readRebootPackages(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(io.LimitReader(file, maxCommandOutput))
	for scanner.Scan() {
		name := strings.TrimSpace(scanner.Text())
		if model.ValidPackageName(name) {
			seen[name] = true
		}
	}
	packages := make([]string, 0, len(seen))
	for name := range seen {
		packages = append(packages, name)
	}
	sort.Strings(packages)
	if len(packages) > model.MaxRebootPackages {
		packages = packages[:model.MaxRebootPackages]
	}
	if len(packages) == 0 {
		return nil
	}
	return packages
}

func describeCommandError(ctx context.Context, path string, err error, stderr []byte) string {
	var message string
	switch {
	case errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist):
		message = "Az apt-check nem található: " + path +
			" (Ubuntun az update-notifier-common csomag tartalmazza)."
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		message = fmt.Sprintf("Az apt-check %d másodperc alatt nem futott le.",
			int(packageCommandTimeout/time.Second))
	default:
		message = "Az apt-check hibával állt le: " + cleanError(err)
		if detail := lastLine(stderr); detail != "" {
			message += " · " + detail
		}
	}
	return truncateUTF8(message, model.MaxSecurityError)
}

func lastLine(output []byte) string {
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

func execCommand(ctx context.Context, argv []string) ([]byte, []byte, error) {
	if !filepath.IsAbs(argv[0]) {
		return nil, nil, exec.ErrNotFound
	}
	if _, err := os.Stat(argv[0]); err != nil {
		return nil, nil, err
	}
	command := exec.CommandContext(ctx, argv[0], argv[1:]...)
	command.Stdin = nil
	command.WaitDelay = 5 * time.Second
	stdout := &limitedBuffer{limit: maxCommandOutput}
	stderr := &limitedBuffer{limit: maxCommandOutput}
	command.Stdout, command.Stderr = stdout, stderr
	err := command.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.limit - b.Len(); room > 0 {
		if len(p) > room {
			b.Buffer.Write(p[:room])
		} else {
			b.Buffer.Write(p)
		}
	}
	return len(p), nil
}

// truncateUTF8 shortens value to at most limit bytes without splitting a rune
// and removes line breaks, so the result always passes report validation.
func truncateUTF8(value string, limit int) string {
	value = strings.ToValidUTF8(value, "")
	value = strings.NewReplacer("\r", " ", "\n", " ").Replace(value)
	if len(value) <= limit {
		return value
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return value[:cut]
}
