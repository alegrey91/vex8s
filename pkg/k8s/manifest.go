package k8s

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParseManifest parses a Kubernetes manifest YAML file
func ParseManifest(filepath string) (map[string]any, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	decoder := yaml.NewDecoder(strings.NewReader(string(data)))

	var doc map[string]any
	err = decoder.Decode(&doc)
	if err != nil {
		return nil, fmt.Errorf("failed decoding manifest: %w", err)
	}

	return doc, nil
}

// ExtractContainers extracts container specs from a manifest
func ExtractContainers(manifest map[string]any) []map[string]any {
	var containers []map[string]any

	spec, ok := manifest["spec"].(map[string]any)
	if !ok {
		return containers
	}

	kind, _ := manifest["kind"].(string)
	if kind == "Deployment" || kind == "StatefulSet" || kind == "DaemonSet" || kind == "Job" {
		template, ok := spec["template"].(map[string]any)
		if ok {
			spec, _ = template["spec"].(map[string]any)
		}
	}

	if containersList, ok := spec["containers"].([]any); ok {
		for _, c := range containersList {
			if container, ok := c.(map[string]any); ok {
				containers = append(containers, container)
			}
		}
	}

	if initContainersList, ok := spec["initContainers"].([]any); ok {
		for _, c := range initContainersList {
			if container, ok := c.(map[string]any); ok {
				containers = append(containers, container)
			}
		}
	}

	return containers
}
