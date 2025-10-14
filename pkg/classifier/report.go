package classifier

import (
	"github.com/alegrey91/vex8s/pkg/trivy"
)

type ClassifiedCVE struct {
	CVE     *trivy.CVE
	Classes []Class
}

// Report is the expected output from the llm.
// example:
// {"cve_id": ["class_name_1", "class_name_2"], "cve_id": ["class_name_2"], "cve_id": ["class_name_1"]}
type Report struct {
	Classification []ClassifiedCVE `json:"classification"`
}

func (r *Report) Enrich(cves []trivy.CVE) {
	for i := range r.Classification {
		classifiedCVE := &r.Classification[i]
		for _, cve := range cves {
			if classifiedCVE.CVE.ID == cve.ID {
				classifiedCVE.CVE.PURL = cve.PURL
			}
		}
	}
}
