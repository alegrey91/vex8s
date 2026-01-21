package mitigation

import (
	"github.com/alegrey91/vex8s/pkg/inference"
	corev1 "k8s.io/api/core/v1"
)

// CVE represents a vulnerability
type CVE struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	PURL        string   `json:"purl"`
	CWEs        []string `json:"cwes"`
}

type MitigationRule struct {
	Verify func(*corev1.PodSpec, *corev1.Container) bool
}

func cweToClass(cwe string) MitigationRule {
	switch cwe {
	// CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
	// https://cwe.mitre.org/data/definitions/22.html
	// CWE-23: Relative Path Traversal
	// https://cwe.mitre.org/data/definitions/23.html
	// CWE-36: Absolute Path Traversal
	// https://cwe.mitre.org/data/definitions/36.html
	// CWE-276: Incorrect Default Permissions
	// https://cwe.mitre.org/data/definitions/276.html
	// CWE-377: Insecure Temporary File
	// https://cwe.mitre.org/data/definitions/377.html
	// CWE-378: Creation of Temporary File with Insecure Permissions
	// https://cwe.mitre.org/data/definitions/378.html
	// CWE-379: Creation of Temporary File in Directory with Insecure Permissions
	// https://cwe.mitre.org/data/definitions/379.html
	// CWE-434: Unrestricted Upload of File with Dangerous Type
	// https://cwe.mitre.org/data/definitions/434.html
	// CWE-732: Incorrect Permission Assignment for Critical Resource
	// https://cwe.mitre.org/data/definitions/732.html
	case "CWE-22", "CWE-23", "CWE-36", "CWE-276", "CWE-377", "CWE-378", "CWE-379", "CWE-434", "CWE-732":
		return MitigationRule{
			Verify: func(p *corev1.PodSpec, c *corev1.Container) bool {
				return true
			},
		}
	// CWE-77: Improper Neutralization of Special Elements used in a Command
	// ('Command Injection')
	// https://cwe.mitre.org/data/definitions/77.html
	// CWE-78: Improper Neutralization of Special Elements used in an OS Command
	// ('OS Command Injection')
	// https://cwe.mitre.org/data/definitions/78.html
	// CWE-250: Execution with Unnecessary Privileges
	// https://cwe.mitre.org/data/definitions/250.html
	// CWE-266: Incorrect Privilege Assignment
	// https://cwe.mitre.org/data/definitions/266.html
	// CWE-269: Improper Privilege Management
	// https://cwe.mitre.org/data/definitions/269.html
	case "CWE-77", "CWE-78", "CWE-250", "CWE-266", "CWE-269":
		return MitigationRule{
			Verify: func(p *corev1.PodSpec, c *corev1.Container) bool {
				return true
			},
		}
	// CWE-400: Uncontrolled Resource Consumption
	// https://cwe.mitre.org/data/definitions/400.html
	// CWE-770: Allocation of Resources Without Limits or Throttling
	// https://cwe.mitre.org/data/definitions/770.html
	case "CWE-400", "CWE-770":
		return MitigationRule{
			Verify: func(p *corev1.PodSpec, c *corev1.Container) bool {
				return true
			},
		}
	default:
		return MitigationRule{
			Verify: func(ps *corev1.PodSpec, c *corev1.Container) bool {
				return false
			},
		}
	}
}

func classMitigations(label string) MitigationRule {
	switch label {
	case "arbitrary_file_write":
		return MitigationRule{
			Verify: func(p *corev1.PodSpec, c *corev1.Container) bool {
				// readOnlyRootFilesystem: true
				// volumeMounts[].readOnly: true
				return hasReadOnlyRootFileSystem(c) &&
					hasVolumeMountReadOnly(c)
			},
		}
	case "system_privilege_escalation":
		return MitigationRule{
			Verify: func(p *corev1.PodSpec, c *corev1.Container) bool {
				// privileged: false
				// allowPrivilegeEscalation: false
				// runAsNonRoot: true || runAsUser: <non-zero>
				return hasPrivileged(c) &&
					hasAllowPrivilegeEscalation(c) &&
					(hasRunAsNonRoot(p, c) || hasRunAsUser(p, c))
			},
		}
	case "resource_exhaustion":
		return MitigationRule{
			Verify: func(p *corev1.PodSpec, c *corev1.Container) bool {
				// resources.limits.cpu
				// resources.limits.memory
				return hasResourceLimitCPU(p, c) &&
					hasResourceLimitMemory(p, c)
			},
		}
	case "arbitrary_file_read":
		return MitigationRule{
			Verify: func(p *corev1.PodSpec, c *corev1.Container) bool {
				// we are not able to mitigate arbitrary file read
				// vulnerabilities at the moment
				return false
			},
		}
	case "code_injection":
		return MitigationRule{
			Verify: func(p *corev1.PodSpec, c *corev1.Container) bool {
				// we are not able to mitigate code injection
				// vulnerabilities at the moment
				return false
			},
		}
	case "application_privilege_escalation":
		return MitigationRule{
			Verify: func(p *corev1.PodSpec, c *corev1.Container) bool {
				// we are not able to mitigate application privilege escalation
				// vulnerabilities at the moment
				return false
			},
		}
	case "other":
		return MitigationRule{
			Verify: func(p *corev1.PodSpec, c *corev1.Container) bool {
				return false
			},
		}
	default:
		return MitigationRule{
			Verify: func(ps *corev1.PodSpec, c *corev1.Container) bool {
				return false
			},
		}
	}
}

func IsCVEMitigated(cve CVE, spec *corev1.PodSpec, ct *corev1.Container, m *inference.Model) bool {
	if len(cve.CWEs) == 0 {
		return false
	}

	labels := m.Predict(cve.Description)

	mitigateByLabel := false
	// All predicted labels must be mitigated
	for _, label := range labels {
		if classMitigations(label).Verify(spec, ct) {
			mitigateByLabel = true
		}
	}
	if !mitigateByLabel {
		return false
	}

	mitigateByCWE := false
	// All CWEs must be mitigated
	for _, cwe := range cve.CWEs {
		if cweToClass(cwe).Verify(spec, ct) {
			mitigateByCWE = true
		}
	}
	if !mitigateByCWE {
		return false
	}

	return true
}
