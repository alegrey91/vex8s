package scanner

import (
	"fmt"
)

// CVE represents a vulnerability
type CVE struct {
	ID   string   `json:"id"`
	PURL string   `json:"purl"`
	CWEs []string `json:"cwes"`
}

// ConvertReport converts a ScanResult to a normalized CVE slice
func ConvertReport(scanResult ScanResult) ([]CVE, error) {
	// Use type switch to handle different report types
	switch report := scanResult.Report.(type) {
	case GrypeReport:
		return convertGrypeReport(report), nil
	case TrivyReport:
		return convertTrivyReport(report), nil
	default:
		return nil, fmt.Errorf("unsupported report type: %T", report)
	}
}

// convertGrypeReport converts Grype report to CVE slice
func convertGrypeReport(report GrypeReport) []CVE {
	var cves []CVE
	for _, vuln := range report.Document.Matches {
		var cweList []string
		for _, cwe := range vuln.Vulnerability.CWEs {
			cweList = append(cweList, cwe.CWE)
		}
		cves = append(cves, CVE{
			ID:   vuln.Vulnerability.ID,
			PURL: vuln.Artifact.PURL,
			CWEs: cweList,
		})
	}

	return cves
}

// convertTrivyReport converts Trivy report to CVE slice
func convertTrivyReport(report TrivyReport) []CVE {
	var cves []CVE
	for _, res := range report.Report.Results {
		for _, vuln := range res.Vulnerabilities {
			cves = append(cves, CVE{
				ID:   vuln.VulnerabilityID,
				PURL: vuln.PkgIdentifier.PURL.String(),
				CWEs: vuln.CweIDs,
			})
		}
	}

	return cves
}
