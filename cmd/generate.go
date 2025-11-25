/*
Copyright © 2025 Alessio Greggi
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/alegrey91/vex8s/pkg/k8s"
	"github.com/alegrey91/vex8s/pkg/mitigation"
	"github.com/alegrey91/vex8s/pkg/scanner"
	"github.com/alegrey91/vex8s/pkg/vex"
	"github.com/spf13/cobra"
)

var (
	manifestPath       string
	vulnReportPath     string
	outputPath         string
	showCVEs           bool
	showSecContext     bool
	vexAuthor          string
	vexAuthorRole      string
	suppressDisclaimer bool
)

const (
	disclaimerMessage = `[!] WARNING:
    Please, review the VEX statements generated to be sure 
    that they match mitigation configured in your 
    running cluster, because the tool generates its 
    results based on configurations that might be changed 
    during runtime, so you can be sure that CVEs are 
    correctly suppressed.`
)

// generateCmd represents the generate command
var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generates VEX documents",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("[*] Parsing manifest: %s\n", manifestPath)
		podSpec, err := k8s.ParseManifestPodSpec(manifestPath)
		if err != nil {
			return fmt.Errorf("[!] Failed to parse manifest: %w", err)
		}

		fmt.Printf("[*] Processing\n")
		var totalMitigated []scanner.CVE

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

			var report scanner.ScanResult
			var cves []scanner.CVE
			if vulnReportPath != "" {
				fmt.Println("[*] Reading from report...")
				report, err = scanner.ReadFromReport(vulnReportPath)
				if err != nil {
					return fmt.Errorf("[!] Error: %w", err)
				}
			}
			cves, err = scanner.ConvertReport(report)
			if err != nil {
				return fmt.Errorf("[!] Error: %w", err)
			}

			fmt.Printf("[*] Found %d CVEs\n", len(cves))
			if showCVEs {
				for _, cve := range cves {
					fmt.Printf("%s: %s\n", cve.ID, cve.CWEs)
				}
			}

			var mitigated []scanner.CVE
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

		vexInfo := vex.VEXInfo{
			Author:     vexAuthor,
			AuthorRole: vexAuthorRole,
			// Tooling value is not negotiable
			Tooling: "vex8s",
		}
		vexDoc, err := vex.GenerateVEX(totalMitigated, vexInfo)
		if err != nil {
			return fmt.Errorf("[!] Failed to generate VEX document: %w", err)
		}
		output, err := json.MarshalIndent(vexDoc, "", "  ")
		if err != nil {
			return fmt.Errorf("[!] Failed to marshal VEX document: %w", err)
		}

		if !suppressDisclaimer {
			fmt.Println(disclaimerMessage)
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
	generateCmd.Flags().StringVarP(&vulnReportPath, "report", "r", "", "path to vulnerability report")
	generateCmd.Flags().StringVarP(&outputPath, "output", "o", "", "output VEX file path")

	// Show flags
	generateCmd.Flags().BoolVar(&showCVEs, "show.cves", false, "show CVEs found")
	generateCmd.Flags().BoolVar(&showSecContext, "show.sec", false, "show SecurityContext found")

	// VEX flags
	generateCmd.Flags().StringVar(&vexAuthor, "vex.author", "Unknown Author", "set VEX author")
	generateCmd.Flags().StringVar(&vexAuthorRole, "vex.role", "", "set VEX author role")

	// Suppress flags
	generateCmd.Flags().BoolVar(&suppressDisclaimer, "suppress.disclaimer", false, "suppress disclaimer")
}
