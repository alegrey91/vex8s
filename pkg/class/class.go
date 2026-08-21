// Package class defines the shared vocabulary describing the exploitation
// *outcome* of a CVE (what an attacker gains), not the vulnerability type.
// It is a leaf package: the deterministic CWE map (pkg/cwe), the probabilistic
// classifier (pkg/classifier) and the decision pipeline (pkg/decision) all
// depend on it, so it must not import any of them.
package class

// ExploitClass is a single exploitation outcome.
type ExploitClass string

const (
	ArbitraryFileWrite              ExploitClass = "arbitrary_file_write"
	ArbitraryFileRead               ExploitClass = "arbitrary_file_read"
	SystemPrivilegesEscalation      ExploitClass = "system_privileges_escalation"
	ApplicationPrivilegesEscalation ExploitClass = "application_privileges_escalation"
	ResourceExhaustion              ExploitClass = "resource_exhaustion"
	ApplicationCrash                ExploitClass = "application_crash"
	// Other is the safe fallback: no mitigable exploitation outcome applies.
	Other ExploitClass = "other"
)

// All is the canonical ordered set. Used to constrain classifier output
// (e.g. the enum an LLM backend must return) and to validate inputs.
var All = []ExploitClass{
	ArbitraryFileWrite,
	ArbitraryFileRead,
	SystemPrivilegesEscalation,
	ApplicationPrivilegesEscalation,
	ResourceExhaustion,
	ApplicationCrash,
	Other,
}

// IsValid reports whether c is a known class.
func (c ExploitClass) IsValid() bool {
	for _, k := range All {
		if k == c {
			return true
		}
	}
	return false
}
