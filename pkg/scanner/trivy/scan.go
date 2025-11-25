package trivy

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/alegrey91/vex8s/pkg/scanner"
	trivyCmd "github.com/aquasecurity/trivy/pkg/commands"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
)

// Scan scans a container image using Trivy
func Scan(image string) (trivyTypes.Report, error) {
	reportFile, err := os.CreateTemp("/tmp", "vex8s.*.json")
	if err != nil {
		return trivyTypes.Report{}, fmt.Errorf("failed to create temporary report file: %w", err)
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
		return trivyTypes.Report{}, fmt.Errorf("trivy scan failed: %w", err)
	}

	reportBytes, err := io.ReadAll(reportFile)
	if err != nil {
		return trivyTypes.Report{}, fmt.Errorf("failed to read output: %w", err)
	}

	report := trivyTypes.Report{}
	err = json.Unmarshal(reportBytes, &report)
	if err != nil {
		return trivyTypes.Report{}, fmt.Errorf("failed to unmarshal report: %w", err)
	}

	return report, nil
}

func ReadFromReport(reportFile string) (trivyTypes.Report, error) {
	reportBytes, err := os.ReadFile(reportFile)
	if err != nil {
		return trivyTypes.Report{}, fmt.Errorf("failed to read output: %w", err)
	}

	report := trivyTypes.Report{}
	err = json.Unmarshal(reportBytes, &report)
	if err != nil {
		return trivyTypes.Report{}, fmt.Errorf("failed to unmarshal report: %w", err)
	}

	return report, nil
}

func ConvertReport(report trivyTypes.Report) []scanner.CVE {
	var cves []scanner.CVE
	for _, res := range report.Results {
		for _, vuln := range res.Vulnerabilities {
			cves = append(cves, scanner.CVE{
				ID:   vuln.VulnerabilityID,
				PURL: vuln.PkgIdentifier.PURL.String(),
				CWEs: vuln.CweIDs,
			})
		}
	}

	return cves
}
