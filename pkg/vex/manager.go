package vex

import (
	"fmt"

	"github.com/alegrey91/vex8s/pkg/mitigation"
	govex "github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"
)

// Verdict is the outcome for a CVE that gets recorded in the VEX document.
type Verdict int

const (
	// Suppress: a blocking control neutralizes the CVE. Maps to VEX
	// not_affected.
	Suppress Verdict = iota
	// SuppressAsReduced: a reducing control bounds the impact but the flaw can
	// still trigger. Maps to VEX affected + action_statement.
	SuppressAsReduced
)

// Suppression records a suppressed CVE and why.
type Suppression struct {
	CVE     *mitigation.CVE
	Verdict Verdict
	Reason  string
}

type VEXInfo struct {
	Author     string
	AuthorRole string
	Tooling    string
}

// GenerateVEX builds a VEX document from suppression decisions.
//
//   - Suppress          -> not_affected + inline_mitigations_already_exist
//   - SuppressAsReduced -> affected + action_statement (impact reduced, still
//     triggerable; scanners will still surface it, which is correct for a
//     bounded DoS).
func GenerateVEX(decisions []Suppression, info VEXInfo) (govex.VEX, error) {
	doc := govex.New()
	doc.Author = info.Author
	doc.AuthorRole = info.AuthorRole
	doc.Tooling = info.Tooling

	for _, d := range decisions {
		purl, err := packageurl.FromString(d.CVE.PURL)
		if err != nil {
			return doc, fmt.Errorf("failed parsing PURL: %w", err)
		}

		stmt := govex.Statement{
			Vulnerability: govex.Vulnerability{Name: govex.VulnerabilityID(d.CVE.ID)},
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
		}

		switch d.Verdict {
		case Suppress:
			stmt.Status = govex.StatusNotAffected
			stmt.Justification = govex.InlineMitigationsAlreadyExist
			stmt.ImpactStatement = d.Reason
		case SuppressAsReduced:
			stmt.Status = govex.StatusAffected
			stmt.ActionStatement = d.Reason
		default:
			continue
		}

		doc.Statements = append(doc.Statements, stmt)
	}

	cID, err := doc.GenerateCanonicalID()
	if err != nil {
		return doc, err
	}
	doc.ID = cID
	return doc, nil
}
