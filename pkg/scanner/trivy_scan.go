package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	trivyCmd "github.com/aquasecurity/trivy/pkg/commands"
)

type TrivyScanner struct{}

// Scan scans a container image using trivy
func (t *TrivyScanner) Scan(image string) (ScanResult, error) {
	reportFile, err := os.CreateTemp("/tmp", "vex8s.*.json")
	if err != nil {
		return ScanResult{}, fmt.Errorf("failed to create temporary report file: %w", err)
	}
	defer func() {
		if err = reportFile.Close(); err != nil {
			fmt.Printf("failed to close temporary report file: %v\n", err)
		}

		if err = os.Remove(reportFile.Name()); err != nil {
			fmt.Printf("failed to remove temporary repoort file: %v\n", err)
		}
	}()

	trivy := trivyCmd.NewApp()
	trivy.SetArgs([]string{
		"image",
		"--format", "json",
		"--output", reportFile.Name(),
		"--quiet",
		image,
	})
	if err := trivy.Execute(); err != nil {
		return ScanResult{}, fmt.Errorf("scan failed: %w", err)
	}

	reportBytes, err := io.ReadAll(reportFile)
	if err != nil {
		return ScanResult{}, fmt.Errorf("failed to read output: %w", err)
	}

	report := ScanResult{}
	var trivyReport TrivyReport
	err = json.Unmarshal(reportBytes, &trivyReport.Report)
	if err != nil {
		return ScanResult{}, fmt.Errorf("failed to unmarshal report: %w", err)
	}
	report.Report = trivyReport

	return report, nil
}
