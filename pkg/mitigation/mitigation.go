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
	case "CWE-77", "CWE-78":
		return MitigationRule{
			Verify: func(p *corev1.PodSpec, c *corev1.Container) bool {
				// runAsNonRoot: true,
				// allowPrivilegeEscalation: false
				return hasRunAsNonRoot(p, c) &&
					hasAllowPrivilegeEscalation(c)
			},
		}
	case "CWE-266":
		return MitigationRule{
			Verify: func(p *corev1.PodSpec, c *corev1.Container) bool {
				// privileged: false,
				// capabilities.drop,
				// allowPrivilegeEscalation: false
				return hasPrivileged(c) &&
					hasCapabilitiesDropAll(c) &&
					hasAllowPrivilegeEscalation(c)
			},
		}
	case "CWE-276":
		return MitigationRule{
			Verify: func(p *corev1.PodSpec, c *corev1.Container) bool {
				// readOnlyRootFilesystem: true
				return hasReadOnlyRootFileSystem(c)
			},
		}
	case "CWE-732":
		return MitigationRule{
			Verify: func(ps *corev1.PodSpec, c *corev1.Container) bool {
				// readOnlyRootFilesystem: true,
				// volumeMounts[].readOnly: true
				return hasReadOnlyRootFileSystem(c) &&
					hasVolumeMountReadOnly(c)
			},
		}
	case "CWE-770":
		return MitigationRule{
			Verify: func(p *corev1.PodSpec, c *corev1.Container) bool {
				// resources.limits.cpu/memory,
				// readOnlyRootFilesystem: true
				return hasResourceLimitCPU(p, c) &&
					hasResourceLimitMemory(p, c) &&
					hasReadOnlyRootFileSystem(c)
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
