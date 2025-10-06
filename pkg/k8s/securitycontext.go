package k8s

// SecurityContext represents extracted securityContext from K8s manifest
type SecurityContext struct {
	RunAsNonRoot             *bool    `json:"runAsNonRoot,omitempty"`
	RunAsUser                *int64   `json:"runAsUser,omitempty"`
	RunAsGroup               *int64   `json:"runAsGroup,omitempty"`
	ReadOnlyRootFilesystem   *bool    `json:"readOnlyRootFilesystem,omitempty"`
	AllowPrivilegeEscalation *bool    `json:"allowPrivilegeEscalation,omitempty"`
	Privileged               *bool    `json:"privileged,omitempty"`
	CapabilitiesAdd          []string `json:"capabilitiesAdd,omitempty"`
	CapabilitiesDrop         []string `json:"capabilitiesDrop,omitempty"`
	SeccompProfile           string   `json:"seccompProfile,omitempty"`
}

// ExtractPodSecurityContext extracts pod-level security context
func ExtractPodSecurityContext(manifest map[string]any) map[string]any {
	spec, ok := manifest["spec"].(map[string]any)
	if !ok {
		return nil
	}

	kind, _ := manifest["kind"].(string)
	if kind == "Deployment" || kind == "StatefulSet" || kind == "DaemonSet" || kind == "Job" {
		template, ok := spec["template"].(map[string]any)
		if ok {
			spec, _ = template["spec"].(map[string]any)
		}
	}

	secCtx, _ := spec["securityContext"].(map[string]any)
	return secCtx
}

// ExtractSecurityContext extracts and merges pod and container security contexts
func ExtractSecurityContext(container, podSecCtx map[string]any) *SecurityContext {
	sc := &SecurityContext{
		CapabilitiesAdd:  []string{},
		CapabilitiesDrop: []string{},
	}

	// Pod-level security context
	if podSecCtx != nil {
		if val, ok := podSecCtx["runAsNonRoot"].(bool); ok {
			sc.RunAsNonRoot = &val
		}
		if val, ok := podSecCtx["runAsUser"].(int); ok {
			uid := int64(val)
			sc.RunAsUser = &uid
		}
		if val, ok := podSecCtx["runAsGroup"].(int); ok {
			gid := int64(val)
			sc.RunAsGroup = &gid
		}
		if profile, ok := podSecCtx["seccompProfile"].(map[string]any); ok {
			if typ, ok := profile["type"].(string); ok {
				sc.SeccompProfile = typ
			}
		}
	}

	// Container-level security context (overrides pod-level)
	containerSecCtx, ok := container["securityContext"].(map[string]any)
	if ok {
		if val, ok := containerSecCtx["runAsNonRoot"].(bool); ok {
			sc.RunAsNonRoot = &val
		}
		if val, ok := containerSecCtx["runAsUser"].(int); ok {
			uid := int64(val)
			sc.RunAsUser = &uid
		}
		if val, ok := containerSecCtx["runAsGroup"].(int); ok {
			gid := int64(val)
			sc.RunAsGroup = &gid
		}
		if val, ok := containerSecCtx["readOnlyRootFilesystem"].(bool); ok {
			sc.ReadOnlyRootFilesystem = &val
		}
		if val, ok := containerSecCtx["allowPrivilegeEscalation"].(bool); ok {
			sc.AllowPrivilegeEscalation = &val
		}
		if val, ok := containerSecCtx["privileged"].(bool); ok {
			sc.Privileged = &val
		}

		if caps, ok := containerSecCtx["capabilities"].(map[string]any); ok {
			if add, ok := caps["add"].([]any); ok {
				for _, cap := range add {
					if capStr, ok := cap.(string); ok {
						sc.CapabilitiesAdd = append(sc.CapabilitiesAdd, capStr)
					}
				}
			}
			if drop, ok := caps["drop"].([]any); ok {
				for _, cap := range drop {
					if capStr, ok := cap.(string); ok {
						sc.CapabilitiesDrop = append(sc.CapabilitiesDrop, capStr)
					}
				}
			}
		}

		if profile, ok := containerSecCtx["seccompProfile"].(map[string]any); ok {
			if typ, ok := profile["type"].(string); ok {
				sc.SeccompProfile = typ
			}
		}
	}

	return sc
}
