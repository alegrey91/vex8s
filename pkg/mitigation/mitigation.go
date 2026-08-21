package mitigation

// CVE represents a vulnerability normalized from a scanner report.
type CVE struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	PURL        string   `json:"purl"`
	CWEs        []string `json:"cwes"`
	Labels      []string `json:"labels,omitempty"`
}
