package model

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	MaxPackageCount     = 100000
	MaxRebootPackages   = 32
	MaxRebootPackageLen = 128
	MaxScannedImages    = 64
	MaxImageNameLen     = 256
	MaxSecurityError    = 512
	MaxScannerLen       = 64
	MaxFindingCount     = 100000
)

// PackageStatus is the host package-update state reported by the agent.
type PackageStatus struct {
	CheckedAt      time.Time `json:"checked_at"`
	Upgradable     int       `json:"upgradable"`
	Security       int       `json:"security"`
	RebootRequired bool      `json:"reboot_required"`
	RebootPackages []string  `json:"reboot_packages,omitempty"`
	Error          string    `json:"error,omitempty"`
}

// VulnerabilityStatus is the latest container image CVE scan summary.
type VulnerabilityStatus struct {
	ScannedAt time.Time              `json:"scanned_at"`
	Scanner   string                 `json:"scanner,omitempty"`
	Images    []ImageVulnerabilities `json:"images,omitempty"`
	Error     string                 `json:"error,omitempty"`
}

type ImageVulnerabilities struct {
	Image           string `json:"image"`
	Critical        int    `json:"critical"`
	High            int    `json:"high"`
	Medium          int    `json:"medium"`
	FixableCritical int    `json:"fixable_critical"`
	FixableHigh     int    `json:"fixable_high"`
	FixableMedium   int    `json:"fixable_medium"`
	Error           string `json:"error,omitempty"`
}

func (p PackageStatus) Validate() error {
	if !validCount(p.Upgradable, MaxPackageCount) || !validCount(p.Security, MaxPackageCount) ||
		p.Security > p.Upgradable {
		return errors.New("invalid package update counts")
	}
	if len(p.Error) > MaxSecurityError {
		return errors.New("package status error is too long")
	}
	if len(p.RebootPackages) > MaxRebootPackages {
		return fmt.Errorf("too many reboot packages: maximum is %d", MaxRebootPackages)
	}
	for _, name := range p.RebootPackages {
		if !ValidPackageName(name) {
			return errors.New("invalid reboot package name")
		}
	}
	return nil
}

func (v VulnerabilityStatus) Validate() error {
	if len(v.Error) > MaxSecurityError || len(v.Scanner) > MaxScannerLen ||
		!printable(v.Scanner) {
		return errors.New("invalid vulnerability scan metadata")
	}
	if len(v.Images) > MaxScannedImages {
		return fmt.Errorf("too many scanned images: maximum is %d", MaxScannedImages)
	}
	seen := make(map[string]bool, len(v.Images))
	for _, image := range v.Images {
		if !ValidImageName(image.Image) {
			return errors.New("invalid scanned image name")
		}
		if seen[image.Image] {
			return errors.New("duplicate scanned image")
		}
		seen[image.Image] = true
		if len(image.Error) > MaxSecurityError {
			return errors.New("image scan error is too long")
		}
		for _, pair := range [][2]int{
			{image.Critical, image.FixableCritical},
			{image.High, image.FixableHigh},
			{image.Medium, image.FixableMedium},
		} {
			if !validCount(pair[0], MaxFindingCount) || !validCount(pair[1], MaxFindingCount) ||
				pair[1] > pair[0] {
				return errors.New("invalid vulnerability counts")
			}
		}
	}
	return nil
}

// ValidImageName accepts container image references (repository, tag, digest
// or bare image ID) and rejects anything that could not be one.
func ValidImageName(value string) bool {
	if value == "" || len(value) > MaxImageNameLen {
		return false
	}
	return strings.IndexFunc(value, func(r rune) bool {
		return !(r == '-' || r == '_' || r == '.' || r == '/' || r == ':' || r == '@' || r == '+' ||
			r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
	}) == -1
}

// ValidPackageName accepts Debian package names (optionally with :arch).
func ValidPackageName(value string) bool {
	if value == "" || len(value) > MaxRebootPackageLen {
		return false
	}
	return strings.IndexFunc(value, func(r rune) bool {
		return !(r == '-' || r == '_' || r == '.' || r == '+' || r == ':' ||
			r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
	}) == -1
}

func validCount(value, limit int) bool {
	return value >= 0 && value <= limit
}

func printable(value string) bool {
	return strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) == -1
}
