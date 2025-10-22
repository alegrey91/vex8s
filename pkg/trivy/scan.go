package trivy

import (
	"encoding/json"
	"fmt"
	"os/exec"
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

// TrivyResult represents Trivy scan output
type TrivyResult struct {
	Results []struct {
		Vulnerabilities []struct {
			VulnerabilityID string `json:"VulnerabilityID"`
			Severity        string `json:"Severity"`
			Title           string `json:"Title"`
			Description     string `json:"Description"`
			PkgName         string `json:"PkgName"`
			PkgIdentifier   struct {
				PURL string `json:"PURL"`
			} `json:"PkgIdentifier"`
			InstalledVersion string   `json:"InstalledVersion"`
			FixedVersion     string   `json:"FixedVersion"`
			CweIDs           []string `json:"CweIDs`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// ScanImage scans a container image using Trivy
func ScanImage(image string) ([]CVE, error) {
	cmd := exec.Command("trivy", "image", "--format", "json", image)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("trivy scan failed: %w", err)
	}

	var result TrivyResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	var cves []CVE
	for _, res := range result.Results {
		for _, vuln := range res.Vulnerabilities {
			cves = append(cves, CVE{
				ID:               vuln.VulnerabilityID,
				Severity:         vuln.Severity,
				Title:            vuln.Title,
				Description:      vuln.Description,
				PkgName:          vuln.PkgName,
				PURL:             vuln.PkgIdentifier.PURL,
				InstalledVersion: vuln.InstalledVersion,
				FixedVersion:     vuln.FixedVersion,
				CWEs:             vuln.CweIDs,
			})
		}
	}

	return cves, nil
}
