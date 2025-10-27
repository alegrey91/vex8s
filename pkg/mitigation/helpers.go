package mitigation

import (
	"slices"

	corev1 "k8s.io/api/core/v1"
)

// hasReadOnlyRootFileSystem ensures that readOnlyRootFileSystem is true.
func hasReadOnlyRootFileSystem(c *corev1.Container) bool {
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
	hasDropAll := false
	if c.SecurityContext.Capabilities.Drop != nil {
		hasDropAll = slices.Contains(c.SecurityContext.Capabilities.Drop, "ALL")
	}
	return hasDropAll
}

func hasRunAsNonRoot(p *corev1.PodSpec, c *corev1.Container) bool {
	if c.SecurityContext.RunAsNonRoot != nil && *c.SecurityContext.RunAsNonRoot {
		return true
	}
	if p.SecurityContext.RunAsNonRoot != nil && *p.SecurityContext.RunAsNonRoot {
		return true
	}
	return false
}

func hasAllowPrivilegeEscalation(c *corev1.Container) bool {
	if c.SecurityContext.AllowPrivilegeEscalation != nil && !*c.SecurityContext.AllowPrivilegeEscalation {
		return true
	}
	return false
}

func hasPrivileged(c *corev1.Container) bool {
	if c.SecurityContext.Privileged != nil && !*c.SecurityContext.Privileged {
		return true
	}
	return false
}

func hasRunAsUser(p *corev1.PodSpec, c *corev1.Container) bool {
	if c.SecurityContext.RunAsUser != nil && *c.SecurityContext.RunAsUser >= 1000 {
		return true
	}
	if p.SecurityContext.RunAsUser != nil && *p.SecurityContext.RunAsUser >= 1000 {
		return true
	}
	return false
}

func hasHostPath(p *corev1.PodSpec) bool {
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
	if c.Resources.Limits.Cpu().Format != "" {
		return true
	}
	if p.Resources.Limits.Cpu().Format != "" {
		return true
	}
	return false
}

func hasResourceLimitMemory(p *corev1.PodSpec, c *corev1.Container) bool {
	if c.Resources.Limits.Memory().Format != "" {
		return true
	}
	if p.Resources.Limits.Memory().Format != "" {
		return true
	}
	return false
}
