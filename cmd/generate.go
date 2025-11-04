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
	manifestPath   string
	outputPath     string
	showCVEs       bool
	showSecContext bool
	vexAuthor      string
)

const (
	defaultVexAuthor = "vex8s"
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

		if showSecContext {
			fmt.Printf("[+] spec.SecurityContext:\n")
			podSC, _ := json.MarshalIndent(podSpec.SecurityContext, "", "  ")
			fmt.Println(string(podSC))
		}

		for _, container := range podSpec.Containers {
			containerName := container.Name
			image := container.Image

			fmt.Printf("[+] Container: %s\n", containerName)
			fmt.Printf("[+] Image: %s\n", image)

			if showSecContext {
				fmt.Printf("[+] container.SecurityContext:\n")
				ctSC, _ := json.MarshalIndent(container.SecurityContext, "", "  ")
				fmt.Println(string(ctSC))
			}

			var cves []trivy.CVE
			fmt.Println("[*] Scanning for CVEs...")
			s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
			s.Suffix = " Scanning image"
			s.Start()
			cves, err = trivy.Scan(image)
			s.Stop()
			if err != nil {
				return fmt.Errorf("[!] Error: %w", err)
			}
			fmt.Printf("[*] Found %d CVEs\n", len(cves))
			if showCVEs {
				for _, cve := range cves {
					fmt.Printf("[%s]: %s\n", cve.ID, cve.CWEs)
				}
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
		vexDoc, err := vex.GenerateVEX(totalMitigated, vexAuthor)
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

	// Show flags
	generateCmd.Flags().BoolVar(&showCVEs, "show.cves", false, "show CVEs found")
	generateCmd.Flags().BoolVar(&showSecContext, "show.sec", false, "show SecurityContext found")

	// VEX flags
	generateCmd.Flags().StringVar(&vexAuthor, "vex.author", defaultVexAuthor, "set VEX author")
}
