/*
Copyright © 2025 Alessio Greggi
*/
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/alegrey91/vex8s/pkg/classifier"
	"github.com/alegrey91/vex8s/pkg/k8s"
	"github.com/alegrey91/vex8s/pkg/prompt"
	"github.com/alegrey91/vex8s/pkg/trivy"
	"github.com/alegrey91/vex8s/pkg/vex"
	"github.com/briandowns/spinner"
	govex "github.com/openvex/go-vex/pkg/vex"
	"github.com/spf13/cobra"
	"github.com/tmc/langchaingo/llms"
	"github.com/tmc/langchaingo/llms/ollama"
)

var (
	manifestPath string
	outputPath   string
	llmModel     string
	llmURL       string
	showPrompt   bool
	showAnswer   bool
)

// generateCmd represents the generate command
var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("[*] Parsing manifest: %s\n", manifestPath)
		podSpec, err := k8s.ParseManifestPodSpec(manifestPath)
		if err != nil {
			return fmt.Errorf("[!] Failed to parse manifest: %w", err)
		}

		fmt.Printf("[*] Processing\n")
		var allVexDocs []govex.VEX

		llm, err := ollama.New(
			ollama.WithModel(llmModel),
			ollama.WithServerURL(llmURL),
			ollama.WithFormat("json"),
		)
		if err != nil {
			return fmt.Errorf("[!] Failed to setup llm: %w", err)
		}

		for _, container := range podSpec.Containers {
			containerName := container.Name
			image := container.Image

			fmt.Printf("[+] Container: %s\n", containerName)
			fmt.Printf("Image: %s\n", image)

			fmt.Printf("Security Context:\n")
			fmt.Printf("  - runAsNonRoot: %v\n", boolPtrToString(container.SecurityContext.RunAsNonRoot))
			fmt.Printf("  - allowPrivilegeEscalation: %v\n", boolPtrToString(container.SecurityContext.AllowPrivilegeEscalation))
			fmt.Printf("  - readOnlyRootFilesystem: %v\n", boolPtrToString(container.SecurityContext.ReadOnlyRootFilesystem))
			fmt.Printf("  - capabilities.Drop: %v\n", container.SecurityContext.Capabilities.Drop)
			fmt.Printf("  - capabilities.Add: %v\n", container.SecurityContext.Capabilities.Add)

			var cves []trivy.CVE
			fmt.Println("[*] Scanning for CVEs...")
			s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
			s.Suffix = " Scanning image"
			s.Start()
			cves, err = trivy.ScanImage(image)
			s.Stop()
			if err != nil {
				return fmt.Errorf("[!] Error: %w", err)
			}
			fmt.Printf("[*] Found %d CVEs\n", len(cves))

			schema := classifier.GetReportSchema()
			schemaJ, err := schema.MarshalJSON()
			if err != nil {
				return fmt.Errorf("[!] Failed to marshall JSON schema: %w", err)
			}

			// split cves into multiple templates
			var templates []prompt.TemplateData
			if len(cves) > 10 {
				for i := 0; i < len(cves); i += 10 {
					// Calculate the end index for this batch
					end := min(i+10, len(cves))
					// Process the batch
					batch := cves[i:end]
					templates = append(templates, prompt.TemplateData{
						CVEList:       batch,
						VulnClassList: classifier.Classes,
						Schema:        string(schemaJ),
					})
				}
			} else {
				templates = append(templates, prompt.TemplateData{
					CVEList:       cves,
					VulnClassList: classifier.Classes,
					Schema:        string(schemaJ),
				})
			}

			// generate inputs from the given templates
			var inputs []string
			for _, td := range templates {
				input := td.GeneratePrompt()
				inputs = append(inputs, input)
			}

			// call llm
			var answers []string
			for id, input := range inputs {
				if showPrompt {
					fmt.Printf("[*] Prompt [%d/%d]:\n%s\n", id+1, len(templates), input)
				}
				s.Suffix = fmt.Sprintf(" Calling LLM [%d/%d]", id+1, len(inputs))
				s.Start()
				answer, err := llm.Call(
					context.Background(),
					input,
					llms.WithTemperature(0.0),
					llms.WithJSONMode(),
					// This is to try to reduce the answer randomness
					// as much as possible. 16 is just a nice number.
					llms.WithSeed(16),
					// Add line below when the PR will be merged:
					// https://github.com/tmc/langchaingo/pull/1302
					// llms.WithJSONSchema(schema),
				)
				s.Stop()
				if err != nil {
					return fmt.Errorf("[!] Failed to call llm: %w", err)
				}
				answers = append(answers, answer)
				if showAnswer {
					fmt.Printf("[*] Answer [%d/%d]:\n%s\n", id+1, len(templates), answer)
				}
			}

			// assemble the reports all together
			finalReport := &classifier.Report{}
			for _, answer := range answers {
				var report *classifier.Report
				if err = json.Unmarshal([]byte(answer), &report); err != nil {
					return fmt.Errorf("[!] Failed to Unmarshal JSON from LLM: %w: %q", err, answer)
				}
				report.Enrich(cves)
				finalReport.Add(report)
			}

			var mitigated []trivy.CVE
			for _, classifiedCVE := range finalReport.Classification {
				if classifier.IsCVEMitigated(classifiedCVE, podSpec) {
					mitigated = append(mitigated, *classifiedCVE.CVE)
				}
			}

			fmt.Printf("[✓] Mitigated CVEs: %d\n", len(mitigated))

			vexDoc, err := vex.GenerateVEX(image, mitigated, "vex8s")
			if err != nil {
				return fmt.Errorf("[!] Failed to generate VEX document: %w", err)
			}
			allVexDocs = append(allVexDocs, vexDoc)
		}

		// Write VEX output
		output, err := json.MarshalIndent(allVexDocs[0], "", "  ")
		if err != nil {
			return fmt.Errorf("[!] Failed to marshal VEX document: %w", err)
		}

		if outputPath != "" {
			if err := os.WriteFile(outputPath, output, 0644); err != nil {
				return fmt.Errorf("Failed to write output file: %w", err)
			}
			fmt.Printf("[✓] VEX document written to: %s\n", outputPath)
		} else {
			fmt.Println(string(output))
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(generateCmd)

	generateCmd.Flags().StringVarP(&manifestPath, "manifest", "M", "", "path to Kubernetes manifest YAML")
	generateCmd.MarkFlagRequired("manifest")
	generateCmd.Flags().StringVarP(&outputPath, "output", "O", "", "output VEX file path")
	generateCmd.Flags().StringVar(&llmModel, "llm.model", "", "llm model")
	generateCmd.Flags().StringVar(&llmURL, "llm.url", "http://127.0.0.1:11434/", "llm server URL")
	generateCmd.Flags().BoolVar(&showPrompt, "show.prompt", false, "show the generated prompt")
	generateCmd.Flags().BoolVar(&showAnswer, "show.answer", false, "show the generated answer")
}

func boolPtrToString(b *bool) string {
	if b == nil {
		return "nil"
	}
	return fmt.Sprintf("%t", *b)
}
