package scanner

import (
	"fmt"

	"github.com/alegrey91/vex8s/pkg/mitigation"
)

// ConvertReport converts a ScanResult to a normalized CVE slice
func ConvertReport(scanResult ScanResult) ([]mitigation.CVE, error) {
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

// convertGrypeReport converts grype report to CVE slice
func convertGrypeReport(report GrypeReport) []mitigation.CVE {
	var cves []mitigation.CVE
	for _, vuln := range report.Document.Matches {
		var cweList []string
		for _, cwe := range vuln.Vulnerability.CWEs {
			cweList = append(cweList, cwe.CWE)
		}
		cves = append(cves, mitigation.CVE{
			ID:   vuln.Vulnerability.ID,
			PURL: vuln.Artifact.PURL,
			CWEs: cweList,
		})
	}

	return cves
}

// convertTrivyReport converts trivy report to CVE slice
func convertTrivyReport(report TrivyReport) []mitigation.CVE {
	var cves []mitigation.CVE
	for _, res := range report.Report.Results {
		for _, vuln := range res.Vulnerabilities {
			cves = append(cves, mitigation.CVE{
				ID:          vuln.VulnerabilityID,
				Description: vuln.Description,
				PURL:        vuln.PkgIdentifier.PURL.String(),
				CWEs:        vuln.CweIDs,
			})
		}
	}

	return cves
}
