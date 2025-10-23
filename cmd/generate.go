/*
Copyright © 2025 Alessio Greggi
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/alegrey91/vex8s/pkg/k8s"
	"github.com/alegrey91/vex8s/pkg/mitigation"
	"github.com/alegrey91/vex8s/pkg/trivy"
	"github.com/alegrey91/vex8s/pkg/vex"
	"github.com/briandowns/spinner"
	"github.com/spf13/cobra"
)

var (
	manifestPath string
	outputPath   string
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
		var totalMitigated []trivy.CVE

		for _, container := range podSpec.Containers {
			containerName := container.Name
			image := container.Image

			fmt.Printf("[+] Container: %s\n", containerName)
			fmt.Printf("Image: %s\n", image)

			//fmt.Printf("Security Context:\n")
			//fmt.Printf("  - runAsNonRoot: %v\n", boolPtrToString(container.SecurityContext.RunAsNonRoot))
			//fmt.Printf("  - allowPrivilegeEscalation: %v\n", boolPtrToString(container.SecurityContext.AllowPrivilegeEscalation))
			//fmt.Printf("  - readOnlyRootFilesystem: %v\n", boolPtrToString(container.SecurityContext.ReadOnlyRootFilesystem))
			//fmt.Printf("  - capabilities.Drop: %v\n", container.SecurityContext.Capabilities.Drop)
			//fmt.Printf("  - capabilities.Add: %v\n", container.SecurityContext.Capabilities.Add)

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
			for _, cve := range cves {
				fmt.Printf("[%s]: %s\n", cve.ID, cve.CWEs)
			}

			var mitigated []trivy.CVE
			for _, cve := range cves {
				if mitigation.IsCVEMitigated(cve, podSpec, &container) {
					mitigated = append(mitigated, cve)
				}
			}
			fmt.Printf("[✓] Mitigated %d CVEs for container %s\n", len(mitigated), image)
			totalMitigated = append(totalMitigated, mitigated...)
		}

		// Write VEX output
		if len(totalMitigated) == 0 {
			return nil
		}
		vexDoc, err := vex.GenerateVEX(totalMitigated, "vex8s")
		if err != nil {
			return fmt.Errorf("[!] Failed to generate VEX document: %w", err)
		}
		output, err := json.MarshalIndent(vexDoc, "", "  ")
		if err != nil {
			return fmt.Errorf("[!] Failed to marshal VEX document: %w", err)
		}

		if outputPath != "" {
			if err := os.WriteFile(outputPath, output, 0644); err != nil {
				return fmt.Errorf("failed to write output file: %w", err)
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

	generateCmd.Flags().StringVarP(&manifestPath, "manifest", "m", "", "path to Kubernetes manifest YAML")
	generateCmd.MarkFlagRequired("manifest")
	generateCmd.Flags().StringVarP(&outputPath, "output", "O", "", "output VEX file path")
}

func boolPtrToString(b *bool) string {
	if b == nil {
		return "nil"
	}
	return fmt.Sprintf("%t", *b)
}
