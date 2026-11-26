package main

import (
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/broist/check_agent/internal/trivy"
)

const trivySummaryUsage = `usage: monitorozo-agent trivy-summary -out FILE [-scanner NAME] [-error MESSAGE] IMAGE=TRIVY.json...

Summarizes Trivy "--format json" image reports into the CVE summary read by
the agent (vulnerability_report.path). Each IMAGE=FILE argument names the
scanned image and its Trivy report; a missing, empty or invalid report marks
only that image as failed. The output is replaced atomically with mode 0644.
`

func runTrivySummary(args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("trivy-summary", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		_, _ = io.WriteString(stderr, trivySummaryUsage)
		flags.PrintDefaults()
	}
	out := flags.String("out", "", "summary file to write (required)")
	scanner := flags.String("scanner", "trivy", "scanner name and version shown on the dashboard")
	scanError := flags.String("error", "", "scan-wide error message (for example a failed database update)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *out == "" {
		_, _ = fmt.Fprintln(stderr, "trivy-summary: -out is required")
		flags.Usage()
		return 2
	}
	inputs, err := trivy.ParseInputs(flags.Args())
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "trivy-summary:", err)
		return 2
	}
	status, warnings := trivy.Summarize(inputs, *scanner, *scanError, time.Now())
	for _, warning := range warnings {
		_, _ = fmt.Fprintln(stderr, "trivy-summary: warning:", warning)
	}
	if err := trivy.WriteAtomic(*out, status); err != nil {
		_, _ = fmt.Fprintln(stderr, "trivy-summary:", err)
		return 1
	}
	return 0
}
