package scanner

// CVE represents a vulnerability
type CVE struct {
	ID   string   `json:"id"`
	PURL string   `json:"purl"`
	CWEs []string `json:"cwes"`
}

type ScanEngine string

type ScanResult struct {
	Engine ScanEngine `json:"type"`
	Report interface{}
}

//
//func ReadFromReport(reportFile string) (grypeTypes.Document, error) {
//	reportBytes, err := os.ReadFile(reportFile)
//	if err != nil {
//		return grypeTypes.Document{}, fmt.Errorf("failed to read output: %w", err)
//	}
//
//	report, err := unmarshalWithDiscriminator(reportBytes)
//	if err != nil {
//		return err
//	}
//
//	// Type switch to handle the result
//	switch r := report.(type) {
//	case GrypeReport:
//		fmt.Printf("Grype Report - Tool: %s, Matches: %v\n", r.Tool, r.Matches)
//	case TrivyReport:
//		fmt.Printf("Trivy Report - Scanner: %s, Results: %v\n", r.Scanner, r.Results)
//	default:
//		return fmt.Errorf("unexpected type: %T", r)
//	}
//
//	return report, nil
//}
//
