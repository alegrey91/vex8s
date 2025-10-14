package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/alegrey91/vex8s/pkg/classifier"
	"github.com/alegrey91/vex8s/pkg/k8s"
	"github.com/alegrey91/vex8s/pkg/llm"
	"github.com/alegrey91/vex8s/pkg/trivy"
	"github.com/alegrey91/vex8s/pkg/vex"
	"github.com/briandowns/spinner"
	govex "github.com/openvex/go-vex/pkg/vex"
	"github.com/tmc/langchaingo/jsonschema"
	"github.com/tmc/langchaingo/llms"
	"github.com/tmc/langchaingo/llms/ollama"
)

func main() {
	manifestPath := flag.String("manifest", "", "Path to Kubernetes manifest YAML")
	outputPath := flag.String("output", "", "Output VEX file path")
	showPrompt := flag.Bool("show-prompt", false, "Show the generated prompt")
	showAnswer := flag.Bool("show-answer", false, "Show the generated answer")
	flag.Parse()

	if *manifestPath == "" {
		fmt.Println("Error: -manifest flag is required")
		os.Exit(1)
	}

	fmt.Printf("[*] Parsing manifest: %s\n", *manifestPath)
	podSpec, err := k8s.ParseManifestPodSpec(*manifestPath)
	if err != nil {
		fmt.Printf("Failed to parse manifest: %v", err)
		os.Exit(1)
	}

	var allVexDocs []govex.VEX

	fmt.Printf("[*] Processing\n")

	for _, container := range podSpec.Containers {
		containerName := container.Name
		image := container.Image

		fmt.Printf("[+] Container: %s\n", containerName)
		fmt.Printf("Image: %s\n", image)

		fmt.Printf("Security Context:\n")
		fmt.Printf("  - runAsNonRoot: %v\n", boolPtrToString(container.SecurityContext.RunAsNonRoot))
		fmt.Printf("  - allowPrivilegeEscalation: %v\n", boolPtrToString(container.SecurityContext.AllowPrivilegeEscalation))
		fmt.Printf("  - readOnlyRootFilesystem: %v\n", boolPtrToString(container.SecurityContext.ReadOnlyRootFilesystem))
		fmt.Printf("  - capabilities: %v\n", container.SecurityContext.Capabilities.Drop)

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

		schema := &jsonschema.Definition{
			Type: jsonschema.Object,
			Properties: map[string]jsonschema.Definition{
				"classification": {
					Type: jsonschema.Array,
					Items: &jsonschema.Definition{
						Type: jsonschema.Object,
						Properties: map[string]jsonschema.Definition{
							"cve": {
								Type: jsonschema.Object,
								Properties: map[string]jsonschema.Definition{
									"id": {
										Type: jsonschema.String,
									},
								},
								Required: []string{"id"},
							},
							"classes": {
								Type: jsonschema.Array,
								Items: &jsonschema.Definition{
									Type: jsonschema.Object,
									Properties: map[string]jsonschema.Definition{
										"name": {
											Type: jsonschema.String,
										},
									},
									Required: []string{"name"},
								},
							},
						},
						Required: []string{"cve", "classes"},
					},
				},
			},
			Required: []string{"classification"},
		}
		schemaJ, err := schema.MarshalJSON()
		if err != nil {
			fmt.Printf("[!] Failed to marshall JSON schema: %v", err)
		}

		td := llm.TemplateData{
			CVEList:       cves,
			VulnClassList: classifier.Classes,
			Schema:        string(schemaJ),
		}
		input := td.GeneratePrompt()
		if *showPrompt {
			fmt.Printf("[*] Prompt:\n%s\n", input)
		}

		llm, err := ollama.New(
			ollama.WithModel("granite3.1-dense"),
			ollama.WithServerURL("http://127.0.0.1:11434/"),
		)
		if err != nil {
			fmt.Printf("[!] Failed to setup ollama: %v\n", err)
			os.Exit(1)
		}
		answer, err := llm.Call(context.Background(), input,
			llms.WithTemperature(0.8),
		)
		if err != nil {
			fmt.Printf("[!] Failed to call ollama: %v\n", err)
			os.Exit(1)
		}
		if *showAnswer {
			fmt.Printf("[*] Answer:\n%s\n", answer)
		}

		var report *classifier.Report
		if err = json.Unmarshal([]byte(answer), &report); err != nil {
			fmt.Printf("[!] Unparsable JSON output from LLM: %v: %q", err, answer)
		}
		report.Enrich(cves)

		var mitigated []vex.MitigatedCVE
		for _, classifiedCVE := range report.Classification {
			if classifier.IsCVEMitigated(classifiedCVE, podSpec) {
				mitigated = append(mitigated, vex.MitigatedCVE{
					CVE: *classifiedCVE.CVE,
				})
			}
		}

		fmt.Printf("[✓] Mitigated CVEs: %d\n", len(mitigated))

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
		fmt.Printf("[!] Failed to marshal VEX document: %v", err)
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
