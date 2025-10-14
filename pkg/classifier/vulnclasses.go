package classifier

import (
	"slices"

	corev1 "k8s.io/api/core/v1"
)

const (
	PrivilegeEscalation    string = "PrivilegeEscalation"
	ContainerEscape        string = "ContainerEscape"
	FilesystemManipulation string = "FilesystemManipulation"
	RootOnly               string = "RootOnly"
	None                   string = "None"
)

type MitigationRule struct {
	Rule func(*corev1.PodSpec, *corev1.Container) bool
}

type Class struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

var Classes = []Class{
	{
		Name:        PrivilegeEscalation,
		Description: "Flaws that allow a process to gain higher privileges (e.g., root in the container or node) than originally intended.",
	},
	{
		Name:        ContainerEscape,
		Description: "Bugs that allow code inside a container to break isolation and access the host filesystem, processes, or kernel.",
	},
	{
		Name:        FilesystemManipulation,
		Description: "Vulnerabilities that rely on modifying or writing to files (e.g., replacing binaries, symlink attacks, tampering with configs).",
	},
	{
		Name:        RootOnly,
		Description: "CVEs that require root privileges (UID 0) to exploit successfully.",
	},
	{
		Name:        None,
		Description: "CVE does not belong to any class.",
	},
}

var mitigationChecks = map[string]MitigationRule{
	PrivilegeEscalation: {
		Rule: func(ps *corev1.PodSpec, c *corev1.Container) bool {
			// allowPrivilegeEscalation: false
			// runAsNonRoot: true
			// capabilities.drop: ["ALL"]
			hasDropAll := false
			if c.SecurityContext.Capabilities != nil {
				if c.SecurityContext.Capabilities.Drop != nil {
					hasDropAll = slices.Contains(c.SecurityContext.Capabilities.Drop, "ALL")
				}
			}
			if (c.SecurityContext.AllowPrivilegeEscalation != nil && !*c.SecurityContext.AllowPrivilegeEscalation) &&
				(c.SecurityContext.RunAsNonRoot != nil && *c.SecurityContext.RunAsNonRoot) &&
				hasDropAll {
				return true
			}
			return false
		},
	},
	ContainerEscape: {
		Rule: func(ps *corev1.PodSpec, c *corev1.Container) bool {
			// privileged: false
			// readOnlyRootFilesystem: true
			// capabilities.drop: ["ALL"]
			hasDropAll := false
			if c.SecurityContext.Capabilities != nil {
				if c.SecurityContext.Capabilities.Drop != nil {
					hasDropAll = slices.Contains(c.SecurityContext.Capabilities.Drop, "ALL")
				}
			}
			if (c.SecurityContext.Privileged != nil && !*c.SecurityContext.Privileged) &&
				(c.SecurityContext.ReadOnlyRootFilesystem != nil && *c.SecurityContext.ReadOnlyRootFilesystem) &&
				hasDropAll {
				return true
			}
			return false
		},
	},
	FilesystemManipulation: {
		Rule: func(ps *corev1.PodSpec, c *corev1.Container) bool {
			// readOnlyRootFilesystem: true
			// runAsNonRoot: true
			if (c.SecurityContext.ReadOnlyRootFilesystem != nil && *c.SecurityContext.ReadOnlyRootFilesystem) &&
				(c.SecurityContext.RunAsNonRoot != nil && *c.SecurityContext.RunAsNonRoot) {
				return true
			}
			return false
		},
	},
	RootOnly: {
		Rule: func(ps *corev1.PodSpec, c *corev1.Container) bool {
			// runAsNonRoot: true
			// runAsUser: >=1000
			if (c.SecurityContext.RunAsNonRoot != nil && *c.SecurityContext.RunAsNonRoot) &&
				(c.SecurityContext.RunAsUser != nil && *c.SecurityContext.RunAsUser >= 1000) {
				return true
			}
			return false
		},
	},
	None: {
		Rule: func(ps *corev1.PodSpec, c *corev1.Container) bool {
			// CVE cannot be mitigated if doesn't belong to any class.
			return false
		},
	},
}

// IsCVEMitigated verify that based on the classification,
// the manifest has the right security context to mitigate the CVE.
func IsCVEMitigated(cve ClassifiedCVE, manifest *corev1.PodSpec) bool {
	mitigated := true
	for _, cveClass := range cve.Classes {
		if !mitigationChecks[cveClass.Name].Rule(manifest, &manifest.Containers[0]) {
			return false
		}
	}
	return mitigated
}
