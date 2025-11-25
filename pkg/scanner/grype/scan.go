package grype

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/alegrey91/vex8s/pkg/scanner"
	"github.com/anchore/clio"
	grypeCmd "github.com/anchore/grype/cmd/grype/cli/commands"
	grypeTypes "github.com/anchore/grype/grype/presenter/models"
)

func Scan(image string) (grypeTypes.Document, error) {
	reportFile, err := os.CreateTemp("/tmp", "vex8s.*.json")
	if err != nil {
		return grypeTypes.Document{}, fmt.Errorf("failed to create temporary report file: %w", err)
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
		"--quiet",
		image,
	})
	if err := grype.Execute(); err != nil {
		return grypeTypes.Document{}, fmt.Errorf("trivy scan failed: %w", err)
	}

	reportBytes, err := io.ReadAll(reportFile)
	if err != nil {
		return grypeTypes.Document{}, fmt.Errorf("failed to read output: %w", err)
	}

	report := grypeTypes.Document{}
	err = json.Unmarshal(reportBytes, &report)
	if err != nil {
		return grypeTypes.Document{}, fmt.Errorf("failed to unmarshal report: %w", err)
	}

	return report, nil
}

func ReadFromReport(reportFile string) (grypeTypes.Document, error) {
	reportBytes, err := os.ReadFile(reportFile)
	if err != nil {
		return grypeTypes.Document{}, fmt.Errorf("failed to read output: %w", err)
	}

	report := grypeTypes.Document{}
	err = json.Unmarshal(reportBytes, &report)
	if err != nil {
		return grypeTypes.Document{}, fmt.Errorf("failed to unmarshal report: %w", err)
	}

	return report, nil
}

func ConvertReport(report grypeTypes.Document) []scanner.CVE {
	var cves []scanner.CVE
	for _, vuln := range report.Matches {
		var cweList []string
		for _, cwe := range vuln.Vulnerability.CWEs {
			cweList = append(cweList, cwe.CWE)
		}
		cves = append(cves, scanner.CVE{
			ID:   vuln.Vulnerability.ID,
			PURL: vuln.Artifact.PURL,
			CWEs: cweList,
		})
	}

	return cves
}
