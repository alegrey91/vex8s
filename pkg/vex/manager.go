package vex

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/alegrey91/vex8s/pkg/k8s"
	"github.com/alegrey91/vex8s/pkg/trivy"
	"github.com/openvex/go-vex/pkg/vex"

	govex "github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"
)

// CVEMitigation represents a CVE mitigation rule
type CVEMitigation struct {
	CVEPattern    string
	Description   string
	CheckFunc     func(*k8s.SecurityContext) bool
	Justification govex.Justification
	Confidence    string
	Controls      string
}

type MitigatedCVE struct {
	CVE  trivy.CVE
	Rule CVEMitigation
}

// GetMitigationRules returns the list of mitigation rules
func GetMitigationRules() []CVEMitigation {
	return []CVEMitigation{
		{
			CVEPattern:  ".*privilege.*escalation.*",
			Description: "Privilege escalation vulnerabilities",
			CheckFunc: func(sc *k8s.SecurityContext) bool {
				return sc.AllowPrivilegeEscalation != nil && !*sc.AllowPrivilegeEscalation &&
					sc.RunAsNonRoot != nil && *sc.RunAsNonRoot
			},
			Justification: govex.InlineMitigationsAlreadyExist,
			Confidence:    "high",
			Controls:      "allowPrivilegeEscalation=false, runAsNonRoot=true",
		},
		{
			CVEPattern:  ".*container.*escape.*",
			Description: "Container escape vulnerabilities",
			CheckFunc: func(sc *k8s.SecurityContext) bool {
				hasDropAll := false
				for _, cap := range sc.CapabilitiesDrop {
					if cap == "ALL" {
						hasDropAll = true
						break
					}
				}
				return (sc.Privileged == nil || !*sc.Privileged) &&
					(sc.AllowPrivilegeEscalation == nil || !*sc.AllowPrivilegeEscalation) &&
					hasDropAll
			},
			Justification: govex.InlineMitigationsAlreadyExist,
			Confidence:    "high",
			Controls:      "privileged=false, allowPrivilegeEscalation=false, capabilities.drop=[ALL]",
		},
		{
			CVEPattern:  ".*root.*exploit.*",
			Description: "Root-only exploits",
			CheckFunc: func(sc *k8s.SecurityContext) bool {
				return sc.RunAsNonRoot != nil && *sc.RunAsNonRoot &&
					sc.RunAsUser != nil && *sc.RunAsUser >= 1000
			},
			Justification: govex.VulnerableCodeCannotBeControlledByAdversary,
			Confidence:    "medium",
			Controls:      "runAsNonRoot=true, runAsUser>=1000",
		},
		{
			CVEPattern:  ".*filesystem.*write.*",
			Description: "Filesystem write exploits",
			CheckFunc: func(sc *k8s.SecurityContext) bool {
				return sc.ReadOnlyRootFilesystem != nil && *sc.ReadOnlyRootFilesystem
			},
			Justification: govex.InlineMitigationsAlreadyExist,
			Confidence:    "medium",
			Controls:      "readOnlyRootFilesystem=true",
		},
		{
			CVEPattern:  "CVE-.*-(runc|containerd|docker).*",
			Description: "Container runtime vulnerabilities",
			CheckFunc: func(sc *k8s.SecurityContext) bool {
				return (sc.Privileged == nil || !*sc.Privileged) &&
					(sc.AllowPrivilegeEscalation == nil || !*sc.AllowPrivilegeEscalation)
			},
			Justification: govex.InlineMitigationsAlreadyExist,
			Confidence:    "high",
			Controls:      "privileged=false, allowPrivilegeEscalation=false",
		},
	}
}

// IsCVEMitigated checks if a CVE is mitigated by the security context
func IsCVEMitigated(cve trivy.CVE, sc *k8s.SecurityContext, rules []CVEMitigation) *CVEMitigation {
	cveText := strings.ToLower(fmt.Sprintf("%s %s %s", cve.ID, cve.Title, cve.Description))

	for _, rule := range rules {
		matched, err := regexp.MatchString(strings.ToLower(rule.CVEPattern), cveText)
		if err != nil || !matched {
			continue
		}

		if rule.CheckFunc(sc) {
			return &rule
		}
	}

	return nil
}

// GenerateVEX generates a VEX document
func GenerateVEX(image string, mitigated []MitigatedCVE, author string) (govex.VEX, error) {
	doc := govex.New()

	doc.Author = author

	// Add mitigated CVEs
	for _, m := range mitigated {
		purl, err := packageurl.FromString(m.CVE.PURL)
		if err != nil {
			return doc, fmt.Errorf("failed parsing PURL: %w", err)
		}

		doc.Statements = append(doc.Statements, govex.Statement{
			Vulnerability: govex.Vulnerability{
				Name: govex.VulnerabilityID(m.CVE.ID),
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
			Justification:   m.Rule.Justification,
			ImpactStatement: fmt.Sprintf("Mitigated by Kubernetes securityContext: %s", m.Rule.Description),
			ActionStatement: fmt.Sprintf("Security controls in place: %s", m.Rule.Controls),
		})
	}
	doc.GenerateCanonicalID()

	return doc, nil
}
