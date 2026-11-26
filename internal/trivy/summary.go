// Package trivy condenses Trivy "--format json" image reports into the
// model.VulnerabilityStatus summary that the agent reads and reports.
package trivy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/broist/check_agent/internal/model"
)

// Trivy JSON reports of large images can be tens of megabytes.
const maxReportBytes = 512 << 20

// Input pairs an image reference with the Trivy JSON report produced for it.
type Input struct {
	Image string
	Path  string
}

// ParseInputs parses IMAGE=FILE arguments. Image references never contain
// "=", so the first "=" separates the two parts unambiguously.
func ParseInputs(args []string) ([]Input, error) {
	inputs := make([]Input, 0, len(args))
	for _, arg := range args {
		image, path, ok := strings.Cut(arg, "=")
		if !ok || image == "" || path == "" {
			return nil, fmt.Errorf("invalid argument %q: expected IMAGE=FILE", arg)
		}
		inputs = append(inputs, Input{Image: image, Path: path})
	}
	return inputs, nil
}

type report struct {
	ArtifactName string `json:"ArtifactName"`
	Results      []struct {
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			PkgPath          string `json:"PkgPath"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// Summarize builds the status from the inputs. A missing, empty or invalid
// report marks only that image with an error. Invalid or duplicate image
// names are skipped and returned as warnings.
func Summarize(inputs []Input, scanner, scanError string, now time.Time) (model.VulnerabilityStatus, []string) {
	status := model.VulnerabilityStatus{ScannedAt: now.UTC(), Scanner: truncate(scanner, model.MaxScannerLen)}
	var warnings []string
	var problems []string
	if scanError != "" {
		problems = append(problems, scanError)
	}
	seen := make(map[string]bool)
	for _, input := range inputs {
		if !model.ValidImageName(input.Image) {
			warnings = append(warnings, fmt.Sprintf("skipping invalid image name %q", input.Image))
			continue
		}
		if seen[input.Image] {
			warnings = append(warnings, fmt.Sprintf("skipping duplicate image %q", input.Image))
			continue
		}
		seen[input.Image] = true
		item, err := SummarizeFile(input.Path)
		item.Image = input.Image
		if err != nil {
			item = model.ImageVulnerabilities{Image: input.Image, Error: truncate(err.Error(), model.MaxSecurityError)}
		}
		status.Images = append(status.Images, item)
	}
	sort.Slice(status.Images, func(i, j int) bool { return status.Images[i].Image < status.Images[j].Image })
	if len(status.Images) > model.MaxScannedImages {
		problems = append(problems, fmt.Sprintf("Csak az első %d kép eredménye fér el az összesítőben (összesen %d).",
			model.MaxScannedImages, len(status.Images)))
		status.Images = status.Images[:model.MaxScannedImages]
	}
	status.Error = truncate(strings.Join(problems, " "), model.MaxSecurityError)
	return status, warnings
}

// SummarizeFile counts CRITICAL, HIGH and MEDIUM findings in one Trivy JSON
// report. A finding is fixable when Trivy reports a FixedVersion.
func SummarizeFile(path string) (model.ImageVulnerabilities, error) {
	var result model.ImageVulnerabilities
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return result, errors.New("A vizsgálat nem készített eredményt (lásd: journalctl -u monitorozo-cvescan).")
	}
	if err != nil {
		return result, fmt.Errorf("A Trivy-eredmény nem olvasható: %v", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return result, fmt.Errorf("A Trivy-eredmény nem olvasható: %v", err)
	}
	if info.Size() == 0 {
		return result, errors.New("A vizsgálat üres eredményt adott (lásd: journalctl -u monitorozo-cvescan).")
	}
	var parsed report
	decoder := json.NewDecoder(io.LimitReader(file, maxReportBytes))
	if err := decoder.Decode(&parsed); err != nil {
		return result, errors.New("A Trivy-eredmény nem érvényes JSON (lásd: journalctl -u monitorozo-cvescan).")
	}
	seen := make(map[string]bool)
	for _, target := range parsed.Results {
		for _, finding := range target.Vulnerabilities {
			key := strings.Join([]string{finding.VulnerabilityID, finding.PkgName,
				finding.InstalledVersion, finding.PkgPath}, "\x00")
			if seen[key] {
				continue
			}
			seen[key] = true
			fixable := strings.TrimSpace(finding.FixedVersion) != ""
			switch strings.ToUpper(finding.Severity) {
			case "CRITICAL":
				result.Critical++
				if fixable {
					result.FixableCritical++
				}
			case "HIGH":
				result.High++
				if fixable {
					result.FixableHigh++
				}
			case "MEDIUM":
				result.Medium++
				if fixable {
					result.FixableMedium++
				}
			}
		}
	}
	clamp(&result.Critical, &result.FixableCritical)
	clamp(&result.High, &result.FixableHigh)
	clamp(&result.Medium, &result.FixableMedium)
	return result, nil
}

func clamp(total, fixable *int) {
	if *total > model.MaxFindingCount {
		*total = model.MaxFindingCount
	}
	if *fixable > *total {
		*fixable = *total
	}
}

// WriteAtomic validates status and replaces path with a world-readable file
// (0644) through a temporary file and rename in the same directory.
func WriteAtomic(path string, status model.VulnerabilityStatus) error {
	if err := status.Validate(); err != nil {
		return fmt.Errorf("refusing to write invalid summary: %w", err)
	}
	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".summary-*.json")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func truncate(value string, limit int) string {
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
