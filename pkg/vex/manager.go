package vex

import (
	"fmt"

	"github.com/alegrey91/vex8s/pkg/trivy"
	"github.com/openvex/go-vex/pkg/vex"

	govex "github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"
)

// GenerateVEX generates a VEX document
func GenerateVEX(mitigated []trivy.CVE, author string) (govex.VEX, error) {
	doc := govex.New()

	doc.Author = author

	// Add mitigated CVEs
	for _, m := range mitigated {
		purl, err := packageurl.FromString(m.PURL)
		if err != nil {
			return doc, fmt.Errorf("failed parsing PURL: %w", err)
		}

		doc.Statements = append(doc.Statements, govex.Statement{
			Vulnerability: govex.Vulnerability{
				Name: govex.VulnerabilityID(m.ID),
			},
			Products: []govex.Product{
				{
					Component: govex.Component{
						ID: purl.ToString(),
						Identifiers: map[govex.IdentifierType]string{
							vex.PURL: purl.ToString(),
						},
					},
				},
			},
			Status:          govex.StatusNotAffected,
			Justification:   govex.InlineMitigationsAlreadyExist,
			ImpactStatement: "Mitigated by Kubernetes securityContext",
		})
	}
	doc.GenerateCanonicalID()

	return doc, nil
}
