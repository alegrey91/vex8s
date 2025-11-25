package scanner

import (
	"encoding/json"
	"fmt"
	"os"

	grypeTypes "github.com/anchore/grype/grype/presenter/models"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
)

// ScanEngine type for identifying the scanner
type ScanEngine string

const (
	Grype ScanEngine = "grype"
	Trivy ScanEngine = "trivy"
)

// ScanResult contains the scan engine type and the report
type ScanResult struct {
	Engine ScanEngine `json:"type"`
	Report any        `json:"report"`
}

type GrypeReport struct {
	Document grypeTypes.Document `json:"matches"`
}

type TrivyReport struct {
	Report trivyTypes.Report `json:"results"`
}

// ReadFromReport reads a report file and returns a ScanResult
func ReadFromReport(reportFile string) (ScanResult, error) {
	// read file content
	data, err := os.ReadFile(reportFile)
	if err != nil {
		return ScanResult{}, fmt.Errorf("failed to read file: %w", err)
	}

	// first unmarshal into a map to detect the type
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return ScanResult{}, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	var result ScanResult

	// detect type based on discriminator fields
	if _, hasMatches := raw["matches"]; hasMatches {
		// grype report
		var grypeReport GrypeReport
		if err := json.Unmarshal(data, &grypeReport.Document); err != nil {
			return ScanResult{}, fmt.Errorf("failed to unmarshal Grype report: %w", err)
		}
		result.Engine = Grype
		result.Report = grypeReport
	} else if _, hasResults := raw["Results"]; hasResults {
		// trivy report
		var trivyReport TrivyReport
		if err := json.Unmarshal(data, &trivyReport.Report); err != nil {
			return ScanResult{}, fmt.Errorf("failed to unmarshal Trivy report: %w", err)
		}
		result.Engine = Trivy
		result.Report = trivyReport
	} else {
		return ScanResult{}, fmt.Errorf("unknown report type")
	}

	return result, nil
}
