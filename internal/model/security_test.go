package model

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func validSecurityReport(now time.Time) Report {
	return Report{
		AgentID: "web-01", Timestamp: now, Sequence: 1,
		Packages: &PackageStatus{
			CheckedAt: now, Upgradable: 12, Security: 3,
			RebootRequired: true, RebootPackages: []string{"libc6", "linux-image-6.8.0-45-generic"},
		},
		Vulnerabilities: &VulnerabilityStatus{
			ScannedAt: now, Scanner: "trivy 0.65.0",
			Images: []ImageVulnerabilities{{
				Image:    "ghcr.io/example/app:1.2.3@sha256:0123abcd",
				Critical: 2, High: 5, Medium: 9, FixableCritical: 1, FixableHigh: 5, FixableMedium: 0,
			}},
		},
	}
}

func TestReportValidateSecuritySections(t *testing.T) {
	now := time.Now().UTC()
	validate := func(r Report) error { return r.Validate(now, 2*time.Minute, 24*time.Hour) }
	if err := validate(validSecurityReport(now)); err != nil {
		t.Fatalf("valid security report rejected: %v", err)
	}
	legacy := validSecurityReport(now)
	legacy.Packages, legacy.Vulnerabilities = nil, nil
	if err := validate(legacy); err != nil {
		t.Fatalf("report without security sections rejected: %v", err)
	}
	cases := map[string]func(*Report){
		"negative upgradable":    func(r *Report) { r.Packages.Upgradable = -1 },
		"security > upgradable":  func(r *Report) { r.Packages.Security = 13 },
		"too many upgradable":    func(r *Report) { r.Packages.Upgradable = MaxPackageCount + 1 },
		"long package error":     func(r *Report) { r.Packages.Error = strings.Repeat("x", 513) },
		"invalid reboot package": func(r *Report) { r.Packages.RebootPackages = []string{"libc6; rm -rf /"} },
		"long reboot package":    func(r *Report) { r.Packages.RebootPackages = []string{strings.Repeat("a", 129)} },
		"too many reboot packages": func(r *Report) {
			r.Packages.RebootPackages = nil
			for i := 0; i <= MaxRebootPackages; i++ {
				r.Packages.RebootPackages = append(r.Packages.RebootPackages, fmt.Sprintf("pkg%d", i))
			}
		},
		"long scanner":       func(r *Report) { r.Vulnerabilities.Scanner = strings.Repeat("t", 65) },
		"control in scanner": func(r *Report) { r.Vulnerabilities.Scanner = "trivy\n0.65" },
		"long scan error":    func(r *Report) { r.Vulnerabilities.Error = strings.Repeat("x", 513) },
		"empty image":        func(r *Report) { r.Vulnerabilities.Images[0].Image = "" },
		"long image":         func(r *Report) { r.Vulnerabilities.Images[0].Image = strings.Repeat("a", 257) },
		"image with space":   func(r *Report) { r.Vulnerabilities.Images[0].Image = "nginx latest" },
		"image with markup":  func(r *Report) { r.Vulnerabilities.Images[0].Image = "<script>" },
		"negative critical":  func(r *Report) { r.Vulnerabilities.Images[0].Critical = -1 },
		"fixable over total": func(r *Report) { r.Vulnerabilities.Images[0].FixableHigh = 6 },
		"too many findings":  func(r *Report) { r.Vulnerabilities.Images[0].Medium = MaxFindingCount + 1 },
		"long image error":   func(r *Report) { r.Vulnerabilities.Images[0].Error = strings.Repeat("x", 513) },
		"duplicate image": func(r *Report) {
			r.Vulnerabilities.Images = append(r.Vulnerabilities.Images, r.Vulnerabilities.Images[0])
		},
		"too many images": func(r *Report) {
			r.Vulnerabilities.Images = nil
			for i := 0; i <= MaxScannedImages; i++ {
				r.Vulnerabilities.Images = append(r.Vulnerabilities.Images, ImageVulnerabilities{Image: fmt.Sprintf("app%d:1", i)})
			}
		},
	}
	for name, mutate := range cases {
		report := validSecurityReport(now)
		mutate(&report)
		if err := validate(report); err == nil {
			t.Errorf("%s: invalid report accepted", name)
		}
	}
}

func TestValidImageAndPackageNames(t *testing.T) {
	for _, image := range []string{"nginx", "nginx:1.27-alpine", "registry.example.com:5000/team/app:v1",
		"postgres@sha256:abc123", "sha256:0123456789ab", "a1b2c3d4e5f6"} {
		if !ValidImageName(image) {
			t.Errorf("image %q rejected", image)
		}
	}
	for _, name := range []string{"libc6", "linux-image-6.8.0-45-generic", "libstdc++6:amd64"} {
		if !ValidPackageName(name) {
			t.Errorf("package %q rejected", name)
		}
	}
	if ValidPackageName("pkg name") || ValidImageName("img\"x") {
		t.Fatal("unsafe names accepted")
	}
}
