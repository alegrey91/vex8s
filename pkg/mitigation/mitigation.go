package mitigation

import (
	"github.com/alegrey91/vex8s/pkg/trivy"
	corev1 "k8s.io/api/core/v1"
)

type MitigationRule struct {
	Verify func(*corev1.PodSpec, *corev1.Container) bool
}

func mitigations(cwe string) MitigationRule {
	switch cwe {
	// CWE-77: Improper Neutralization of Special Elements used in a Command
	// ('Command Injection')
	// https://cwe.mitre.org/data/definitions/77.html
	// CWE-78: Improper Neutralization of Special Elements used in an OS Command
	// ('OS Command Injection')
	// https://cwe.mitre.org/data/definitions/78.html
	case "CWE-77", "CWE-78":
		return MitigationRule{
			Verify: func(p *corev1.PodSpec, c *corev1.Container) bool {
				// runAsNonRoot: true
				// allowPrivilegeEscalation: false
				return hasRunAsNonRoot(p, c) &&
					hasAllowPrivilegeEscalation(c)
			},
		}
	// CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer
	// https://cwe.mitre.org/data/definitions/835.html
	// CWE-787: Out-of-bounds Write
	// https://cwe.mitre.org/data/definitions/787.html
	case "CWE-119", "CWE-787":
		return MitigationRule{
			Verify: func(p *corev1.PodSpec, c *corev1.Container) bool {
				// seccompProfile.type: RuntimeDefault
				return hasSeccompProfileTypeRuntimeDefault(p, c)
			},
		}
	// CWE-250: Execution with Unnecessary Privileges
	// https://cwe.mitre.org/data/definitions/250.html
	case "CWE-250":
		return MitigationRule{
			Verify: func(p *corev1.PodSpec, c *corev1.Container) bool {
				// runAsNonRoot: true
				// runAsUser: <UID> >= 1000
				// allowPrivilegeEscalation: false
				// capabilities.drop: ["ALL"]
				return hasRunAsNonRoot(p, c) &&
					hasRunAsUser(p, c) &&
					hasAllowPrivilegeEscalation(c) &&
					hasCapabilitiesDropAll(c)
			},
		}
	// CWE-266: Incorrect Privilege Assignment
	// https://cwe.mitre.org/data/definitions/266.html
	case "CWE-266":
		return MitigationRule{
			Verify: func(p *corev1.PodSpec, c *corev1.Container) bool {
				// privileged: false
				// capabilities.drop
				// allowPrivilegeEscalation: false
				return hasPrivileged(c) &&
					hasCapabilitiesDropAll(c) &&
					hasAllowPrivilegeEscalation(c)
			},
		}
	// CWE-269: Improper Privilege Management
	case "CWE-269":
		return MitigationRule{
			Verify: func(p *corev1.PodSpec, c *corev1.Container) bool {
				// privileged: false
				// allowPrivilegeEscalation: false
				return hasPrivileged(c) &&
					hasAllowPrivilegeEscalation(c)
			},
		}
	// CWE-276: Incorrect Default Permissions
	// https://cwe.mitre.org/data/definitions/276.html
	case "CWE-276":
		return MitigationRule{
			Verify: func(p *corev1.PodSpec, c *corev1.Container) bool {
				// readOnlyRootFilesystem: true
				return hasReadOnlyRootFileSystem(c)
			},
		}
	// CWE-732: Incorrect Permission Assignment for Critical Resource
	// https://cwe.mitre.org/data/definitions/732.html
	case "CWE-732":
		return MitigationRule{
			Verify: func(ps *corev1.PodSpec, c *corev1.Container) bool {
				// readOnlyRootFilesystem: true
				// volumeMounts[].readOnly: true
				return hasReadOnlyRootFileSystem(c) &&
					hasVolumeMountReadOnly(c)
			},
		}
	// CWE-400: Uncontrolled Resource Consumption
	// https://cwe.mitre.org/data/definitions/400.html
	// CWE-770: Allocation of Resources Without Limits or Throttling
	// https://cwe.mitre.org/data/definitions/770.html
	case "CWE-400", "CWE-770":
		return MitigationRule{
			Verify: func(p *corev1.PodSpec, c *corev1.Container) bool {
				// resources.limits.cpu
				// resources.limits.memory
				// readOnlyRootFilesystem: true
				return hasResourceLimitCPU(p, c) &&
					hasResourceLimitMemory(p, c) &&
					hasReadOnlyRootFileSystem(c)
			},
		}
	// CWE-835:
	// https://cwe.mitre.org/data/definitions/835.html
	case "CWE-835":
		return MitigationRule{
			Verify: func(p *corev1.PodSpec, c *corev1.Container) bool {
				return hasResourceLimitCPU(p, c)
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

func IsCVEMitigated(cve trivy.CVE, spec *corev1.PodSpec, ct *corev1.Container) bool {
	if len(cve.CWEs) == 0 {
		return false
	}
	for _, cwe := range cve.CWEs {
		if !mitigations(cwe).Verify(spec, ct) {
			return false
		}
	}
	return true
}
