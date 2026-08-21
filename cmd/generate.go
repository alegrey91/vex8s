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

	"github.com/alegrey91/vex8s/pkg/classifier/registry"
	"github.com/alegrey91/vex8s/pkg/decision"
	"github.com/alegrey91/vex8s/pkg/k8s"
	"github.com/alegrey91/vex8s/pkg/scanner"
	"github.com/alegrey91/vex8s/pkg/vex"
	"github.com/briandowns/spinner"
	"github.com/spf13/cobra"
)

var (
	manifestPath       string
	vulnReportPath     string
	scanEngine         string
	outputPath         string
	showCVEs           bool
	showMitigation     bool
	showMitigated      bool
	showSecContext     bool
	vexAuthor          string
	vexAuthorRole      string
	suppressDisclaimer bool
	classifierEngine   string
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
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if vulnReportPath == "" && scanEngine == "" {
			return fmt.Errorf("[!] Error: at least one flag between -r or -s must be provided")
		}
		if err := registry.Validate(registry.Options{Engine: registry.Engine(classifierEngine)}); err != nil {
			return fmt.Errorf("[!] Error: %w", err)
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("[*] Parsing manifest: %s\n", manifestPath)
		podSpec, err := k8s.ParseManifestPodSpec(manifestPath)
		if err != nil {
			return fmt.Errorf("[!] Failed to parse manifest: %w", err)
		}

		// Build the classifier once for the whole run.
		clf, err := registry.New(registry.Options{Engine: registry.Engine(classifierEngine)})
		if err != nil {
			return fmt.Errorf("[!] Error: setting up classifier: %w", err)
		}
		defer clf.Close()

		fmt.Printf("[*] Processing\n")
		var suppressed []decision.Suppression

		if showSecContext {
			fmt.Printf("[+] spec.SecurityContext:\n")
			podSC, _ := json.MarshalIndent(podSpec.SecurityContext, "", "  ")
			fmt.Println(string(podSC))
		}

		for i := range podSpec.Containers {
			container := podSpec.Containers[i]
			fmt.Printf("[+] Container: %s\n", container.Name)
			fmt.Printf("[+] Image: %s\n", container.Image)

			if showSecContext {
				fmt.Printf("[+] container.SecurityContext:\n")
				ctSC, _ := json.MarshalIndent(container.SecurityContext, "", "  ")
				fmt.Println(string(ctSC))
			}

			report, err := loadReport(container.Image)
			if err != nil {
				return err
			}

			cves, err := scanner.ConvertReport(report)
			if err != nil {
				return fmt.Errorf("[!] Error: converting report: %w", err)
			}

			fmt.Printf("[*] Found %d CVEs\n", len(cves))
			if showCVEs {
				for _, cve := range cves {
					fmt.Printf("%s: %s\n", cve.ID, cve.CWEs)
				}
			}

			pc := decision.Context{
				Ctx:        context.Background(),
				Spec:       podSpec,
				Container:  &container,
				Classifier: clf,
			}

			var containerSuppressed int
			for j := range cves {
				verdict, reason, ok := decision.Decide(pc, &cves[j])
				if ok {
					suppressed = append(suppressed, decision.Suppression{
						CVE:     &cves[j],
						Verdict: verdict,
						Reason:  reason,
					})
					containerSuppressed++
					if showMitigation || showMitigated {
						fmt.Printf("[✓] %s [%s]: %s\n", cves[j].ID, verdict, reason)
					}
				} else if showMitigation && !showMitigated {
					fmt.Printf("[ ] %s: not suppressed (%s)\n", cves[j].ID, reason)
				}
			}
			fmt.Printf("[✓] Suppressed %d CVEs for container %s\n", containerSuppressed, container.Image)
		}

		if len(suppressed) == 0 {
			return nil
		}

		vexInfo := vex.VEXInfo{
			Author:     vexAuthor,
			AuthorRole: vexAuthorRole,
			Tooling:    "vex8s",
		}
		vexDoc, err := vex.GenerateVEX(suppressed, vexInfo)
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

// loadReport returns the vulnerability report for an image, either by reading a
// pre-generated report (passive mode) or by scanning (active mode).
func loadReport(image string) (scanner.ScanResult, error) {
	if vulnReportPath != "" {
		fmt.Println("[*] Reading from report...")
		report, err := scanner.ReadFromReport(vulnReportPath)
		if err != nil {
			return scanner.ScanResult{}, fmt.Errorf("[!] Error: failed to read from report: %w", err)
		}
		return report, nil
	}

	fmt.Println("[*] Scanning with engine...")
	s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	s.Suffix = " Scanning image"
	s.Start()
	defer s.Stop()

	var vulnScanner scanner.Scanner
	switch scanEngine {
	case "trivy":
		vulnScanner = &scanner.TrivyScanner{}
	case "grype":
		vulnScanner = &scanner.GrypeScanner{}
	default:
		return scanner.ScanResult{}, fmt.Errorf("[!] Error: invalid scanning tool selected")
	}
	return vulnScanner.Scan(image)
}

func init() {
	rootCmd.AddCommand(generateCmd)

	generateCmd.Flags().StringVarP(&manifestPath, "manifest", "m", "", "path to Kubernetes manifest YAML")
	generateCmd.MarkFlagRequired("manifest")
	generateCmd.Flags().StringVarP(&vulnReportPath, "report", "r", "", "path to vulnerability report")
	generateCmd.Flags().StringVarP(&scanEngine, "scan.engine", "s", "", "tool to scan for images [trivy, grype]")
	generateCmd.MarkFlagsMutuallyExclusive("report", "scan.engine")
	generateCmd.Flags().StringVarP(&outputPath, "output", "o", "", "output VEX file path")

	// Decision flags
	generateCmd.Flags().StringVar(&classifierEngine, "classifier", "embedded", "classifier engine [embedded, gemini]")

	// Show flags
	generateCmd.Flags().BoolVar(&showCVEs, "show.cve", false, "show CVE list")
	generateCmd.Flags().BoolVar(&showMitigation, "show.mitigation", false, "show mitigation status")
	generateCmd.Flags().BoolVar(&showMitigated, "show.mitigated", false, "show only mitigated CVE list")
	generateCmd.Flags().BoolVar(&showSecContext, "show.securitycontext", false, "show manifest SecurityContext")

	// VEX flags
	generateCmd.Flags().StringVar(&vexAuthor, "vex.author", "Unknown Author", "set VEX author")
	generateCmd.Flags().StringVar(&vexAuthorRole, "vex.role", "", "set VEX author role")

	// Suppress flags
	generateCmd.Flags().BoolVar(&suppressDisclaimer, "suppress.disclaimer", false, "suppress disclaimer")
}
