package trivy

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	trivyCmd "github.com/aquasecurity/trivy/pkg/commands"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
)

// CVE represents a vulnerability
type CVE struct {
	ID               string   `json:"id"`
	Severity         string   `json:"severity"`
	Title            string   `json:"title"`
	Description      string   `json:"description"`
	PkgName          string   `json:"pkgName"`
	PURL             string   `json:"purl"`
	InstalledVersion string   `json:"installedVersion"`
	FixedVersion     string   `json:"fixedVersion"`
	CWEs             []string `json:"cwes"`
}

// Scan scans a container image using Trivy
func Scan(image string) ([]CVE, error) {
	reportFile, err := os.CreateTemp("/tmp", "vex8s.*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary report file: %w", err)
	}
	defer func() {
		if err = reportFile.Close(); err != nil {
			fmt.Printf("failed to close temporary report file: %v\n", err)
		}

		if err = os.Remove(reportFile.Name()); err != nil {
			fmt.Printf("failed to remove temporary repoort file: %v\n", err)
		}
	}()

	app := trivyCmd.NewApp()
	app.SetArgs([]string{
		"image",
		"--format", "json",
		"--output", reportFile.Name(),
		"--quiet",
		image,
	})
	if err := app.Execute(); err != nil {
		return nil, fmt.Errorf("trivy scan failed: %w", err)
	}

	reportBytes, err := io.ReadAll(reportFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read output: %w", err)
	}

	report := trivyTypes.Report{}
	err = json.Unmarshal(reportBytes, &report)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal report: %w", err)
	}

	var cves []CVE
	for _, res := range report.Results {
		for _, vuln := range res.Vulnerabilities {
			cves = append(cves, CVE{
				ID:               vuln.VulnerabilityID,
				Severity:         vuln.Severity,
				Title:            vuln.Title,
				Description:      vuln.Description,
				PkgName:          vuln.PkgName,
				PURL:             vuln.PkgIdentifier.PURL.String(),
				InstalledVersion: vuln.InstalledVersion,
				FixedVersion:     vuln.FixedVersion,
				CWEs:             vuln.CweIDs,
			})
		}
	}

	return cves, nil
}
