package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/alegrey91/vex8s/pkg/k8s"
	"github.com/alegrey91/vex8s/pkg/trivy"
	"github.com/alegrey91/vex8s/pkg/vex"
	"github.com/briandowns/spinner"
	govex "github.com/openvex/go-vex/pkg/vex"
)

func main() {
	manifestPath := flag.String("manifest", "", "Path to Kubernetes manifest YAML")
	outputPath := flag.String("output", "", "Output VEX file path")
	flag.Parse()

	if *manifestPath == "" {
		fmt.Println("Error: -manifest flag is required")
		os.Exit(1)
	}

	fmt.Printf("[*] Parsing manifest: %s\n", *manifestPath)
	manifest, err := k8s.ParseManifest(*manifestPath)
	if err != nil {
		fmt.Printf("Failed to parse manifest: %v", err)
		os.Exit(1)
	}

	rules := vex.GetMitigationRules()
	var allVexDocs []govex.VEX

	kind, _ := manifest["kind"].(string)
	metadata, _ := manifest["metadata"].(map[string]any)
	name, _ := metadata["name"].(string)

	fmt.Printf("[*] Processing %s/%s\n", kind, name)

	containers := k8s.ExtractContainers(manifest)
	podSecCtx := k8s.ExtractPodSecurityContext(manifest)

	for _, container := range containers {
		containerName, _ := container["name"].(string)
		image, _ := container["image"].(string)

		fmt.Printf("[+] Container: %s\n", containerName)
		fmt.Printf("Image: %s\n", image)

		sc := k8s.ExtractSecurityContext(container, podSecCtx)
		fmt.Printf("Security Context:\n")
		fmt.Printf("  - runAsNonRoot: %v\n", boolPtrToString(sc.RunAsNonRoot))
		fmt.Printf("  - allowPrivilegeEscalation: %v\n", boolPtrToString(sc.AllowPrivilegeEscalation))
		fmt.Printf("  - readOnlyRootFilesystem: %v\n", boolPtrToString(sc.ReadOnlyRootFilesystem))
		fmt.Printf("  - capabilities.drop: %v\n", sc.CapabilitiesDrop)

		var cves []trivy.CVE
		fmt.Println("[*] Scanning for CVEs...")
		s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
		s.Start()
		cves, err = trivy.ScanImage(image)
		s.Stop()
		if err != nil {
			fmt.Printf("[!] Warning: %v\n", err)
			cves = []trivy.CVE{}
		}
		fmt.Printf("[*] Found %d CVEs\n", len(cves))

		var mitigated []vex.MitigatedCVE
		var unmitigated []trivy.CVE

		for _, cve := range cves {
			if rule := vex.IsCVEMitigated(cve, sc, rules); rule != nil {
				mitigated = append(mitigated, vex.MitigatedCVE{
					CVE:  cve,
					Rule: *rule,
				})
			} else {
				unmitigated = append(unmitigated, cve)
			}
		}

		fmt.Printf("[✓] Mitigated CVEs: %d\n", len(mitigated))
		fmt.Printf("[✗] Unmitigated CVEs: %d\n", len(unmitigated))

		vexDoc, err := vex.GenerateVEX(image, mitigated, "vex8s")
		if err != nil {
			fmt.Printf("[!] Failed to generate VEX document: %v\n", err)
			os.Exit(1)
		}
		allVexDocs = append(allVexDocs, vexDoc)
	}

	// Write VEX output
	output, err := json.MarshalIndent(allVexDocs[0], "", "  ")
	if err != nil {
		fmt.Printf("Failed to marshal VEX document: %v", err)
		os.Exit(1)
	}

	if *outputPath != "" {
		if err := os.WriteFile(*outputPath, output, 0644); err != nil {
			fmt.Printf("Failed to write output file: %v", err)
			os.Exit(1)
		}
		fmt.Printf("[✓] VEX document written to: %s\n", *outputPath)
	} else {
		fmt.Println(string(output))
	}
}

func boolPtrToString(b *bool) string {
	if b == nil {
		return "nil"
	}
	return fmt.Sprintf("%t", *b)
}
