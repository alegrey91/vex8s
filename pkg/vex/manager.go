package vex

import (
	"fmt"
	"strings"

	"github.com/alegrey91/vex8s/pkg/mitigation"
	govex "github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"
)

type VEXInfo struct {
	Author     string
	AuthorRole string
	Tooling    string
}

// GenerateVEX generates a VEX document
func GenerateVEX(mitigated []mitigation.CVE, info VEXInfo) (govex.VEX, error) {
	doc := govex.New()

	doc.Author = info.Author
	doc.AuthorRole = info.AuthorRole
	doc.Tooling = info.Tooling

	// Add mitigated CVEs
	for _, m := range mitigated {
		purl, err := packageurl.FromString(m.PURL)
		if err != nil {
			return doc, fmt.Errorf("failed parsing PURL: %w", err)
		}

		impact := "Mitigated by Kubernetes securityContext"
		if len(m.Labels) > 0 {
			impact = fmt.Sprintf("Mitigated by Kubernetes configuration: classified as %s", strings.Join(m.Labels, ", "))
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
							govex.PURL: purl.ToString(),
						},
					},
				},
			},
			Status:          govex.StatusNotAffected,
			Justification:   govex.InlineMitigationsAlreadyExist,
			ImpactStatement: impact,
		})
	}

	cID, err := doc.GenerateCanonicalID()
	if err != nil {
		return doc, err
	}
	doc.ID = cID

	return doc, nil
}
