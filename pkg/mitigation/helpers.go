package mitigation

import (
	"slices"

	corev1 "k8s.io/api/core/v1"
)

func containerHasSecurityContext(c *corev1.Container) bool {
	return c.SecurityContext != nil
}

func podSpecHasSecurityContext(p *corev1.PodSpec) bool {
	return p.SecurityContext != nil
}

// hasReadOnlyRootFileSystem ensures that readOnlyRootFileSystem is true.
func hasReadOnlyRootFileSystem(c *corev1.Container) bool {
	if !containerHasSecurityContext(c) {
		return false
	}
	if c.SecurityContext.ReadOnlyRootFilesystem != nil && *c.SecurityContext.ReadOnlyRootFilesystem {
		return true
	}
	return false
}

// hasVolumeMountReadOnly ensures that volumeMount.readOnly is true.
func hasVolumeMountReadOnly(c *corev1.Container) bool {
	// if we don't have volume mount to check, then we are fine.
	if len(c.VolumeMounts) == 0 {
		return true
	}
	for _, v := range c.VolumeMounts {
		if !v.ReadOnly {
			return false
		}
	}
	return true
}

// hasCapabilitiesDropAll ensures that capabilities.Drop is "ALL".
func hasCapabilitiesDropAll(c *corev1.Container) bool {
	if !containerHasSecurityContext(c) {
		return false
	}
	if c.SecurityContext.Capabilities == nil || c.SecurityContext.Capabilities.Drop == nil {
		return false
	}
	return slices.Contains(c.SecurityContext.Capabilities.Drop, "ALL")
}

// hasCapabilitiesAddContains checks if the securityContext.Capabilities.Add attribute
// contains one of the capabilities provided as input.
// If so, returns true. Otherwise, returns false.
// This function should be used with the negation:
// !hasCapabilitiesAddContains(c, []string{"CAP_NET_ADMIN", "CAP_SYS_ADMIN"})
func hasCapabilitiesAddContains(c *corev1.Container, capabilities []string) bool {
	if !containerHasSecurityContext(c) ||
		c.SecurityContext.Capabilities == nil ||
		c.SecurityContext.Capabilities.Add == nil {
		return false
	}
	for _, cap := range capabilities {
		capability := corev1.Capability(cap)
		if slices.Contains(c.SecurityContext.Capabilities.Add, capability) {
			return true
		}
	}
	return false
}

func hasRunAsNonRoot(p *corev1.PodSpec, c *corev1.Container) bool {
	// A non-nil container-level value overrides the pod-level one, so it is
	// authoritative even when it is false (container explicitly runs as root).
	if containerHasSecurityContext(c) && c.SecurityContext.RunAsNonRoot != nil {
		return *c.SecurityContext.RunAsNonRoot
	}
	if podSpecHasSecurityContext(p) && p.SecurityContext.RunAsNonRoot != nil {
		return *p.SecurityContext.RunAsNonRoot
	}
	return false
}

func disallowsPrivilegeEscalation(c *corev1.Container) bool {
	if !containerHasSecurityContext(c) {
		return false
	}
	if c.SecurityContext.AllowPrivilegeEscalation != nil && !*c.SecurityContext.AllowPrivilegeEscalation {
		return true
	}
	return false
}

func isNotPrivileged(c *corev1.Container) bool {
	if !containerHasSecurityContext(c) {
		return false
	}
	if c.SecurityContext.Privileged != nil && !*c.SecurityContext.Privileged {
		return true
	}
	return false
}

func hasRunAsUser(p *corev1.PodSpec, c *corev1.Container) bool {
	// A non-nil container-level value overrides the pod-level one, so it is
	// authoritative even when it is a root uid (container explicitly runs as 0).
	if containerHasSecurityContext(c) && c.SecurityContext.RunAsUser != nil {
		return *c.SecurityContext.RunAsUser >= 1000
	}
	if podSpecHasSecurityContext(p) && p.SecurityContext.RunAsUser != nil {
		return *p.SecurityContext.RunAsUser >= 1000
	}
	return false
}

// hasHostPath checks that volumes doens't have the hostPath option set.
func hasHostPath(p *corev1.PodSpec) bool {
	if len(p.Volumes) == 0 {
		return false
	}
	for _, v := range p.Volumes {
		if v.HostPath != nil {
			return true
		}
	}
	return false
}

func hasHostNetwork(p *corev1.PodSpec) bool {
	return p.HostNetwork
}

func hasMountPropagation(c *corev1.Container) bool {
	for _, v := range c.VolumeMounts {
		if v.MountPropagation != nil && *v.MountPropagation == corev1.MountPropagationNone {
			return true
		}
	}
	return false
}

func hasResourceLimitCPU(p *corev1.PodSpec, c *corev1.Container) bool {
	if c.Resources.Limits.Cpu().Value() != 0 {
		return true
	}
	// we check only p.Resources because in podSpec
	// it is defined as *corev1.ResourceRequirements (so a pointer)
	if p.Resources == nil {
		return false
	}
	if p.Resources.Limits.Cpu().Value() != 0 {
		return true
	}
	return false
}

func hasResourceLimitMemory(p *corev1.PodSpec, c *corev1.Container) bool {
	if c.Resources.Limits.Memory().Value() != 0 {
		return true
	}
	// we check only p.Resources because in podSpec
	// it is defined as *corev1.ResourceRequirements (so a pointer)
	if p.Resources == nil {
		return false
	}
	if p.Resources.Limits.Memory().Value() != 0 {
		return true
	}
	return false
}

// hasSeccompProfileTypeRuntimeDefault checks that the RuntimeDefault profile
// is used by Seccomp
func hasSeccompProfileTypeRuntimeDefault(p *corev1.PodSpec, c *corev1.Container) bool {
	if !containerHasSecurityContext(c) {
		return false
	}
	if c.SecurityContext.SeccompProfile != nil &&
		c.SecurityContext.SeccompProfile.Type == corev1.SeccompProfileTypeRuntimeDefault {
		return true
	}

	if !podSpecHasSecurityContext(p) {
		return false
	}
	if p.SecurityContext != nil &&
		p.SecurityContext.SeccompProfile != nil &&
		p.SecurityContext.SeccompProfile.Type == corev1.SeccompProfileTypeRuntimeDefault {
		return true
	}

	return false
}
