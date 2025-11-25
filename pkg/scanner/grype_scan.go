package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/anchore/clio"
	grypeCmd "github.com/anchore/grype/cmd/grype/cli/commands"
)

type GrypeScanner struct{}

// Scan scans a container image using grype
func (g *GrypeScanner) Scan(image string) (ScanResult, error) {
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

	cfg := clio.NewSetupConfig(clio.Identification{})
	app := clio.New(*cfg)
	grype := grypeCmd.Root(app)
	grype.SetArgs([]string{
		"--output", "json",
		"--file", reportFile.Name(),
		image,
	})
	if err := grype.Execute(); err != nil {
		return ScanResult{}, fmt.Errorf("scan failed: %w", err)
	}

	reportBytes, err := io.ReadAll(reportFile)
	if err != nil {
		return ScanResult{}, fmt.Errorf("failed to read output: %w", err)
	}

	report := ScanResult{}
	var grypeReport GrypeReport
	err = json.Unmarshal(reportBytes, &grypeReport.Document)
	if err != nil {
		return ScanResult{}, fmt.Errorf("failed to unmarshal report: %w", err)
	}
	report.Report = grypeReport

	return report, nil
}
