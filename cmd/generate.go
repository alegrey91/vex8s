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

	"strings"

	"github.com/alegrey91/vex8s/pkg/class"
	"github.com/alegrey91/vex8s/pkg/classifier"
	"github.com/alegrey91/vex8s/pkg/classifier/registry"
	"github.com/alegrey91/vex8s/pkg/cwe"
	"github.com/alegrey91/vex8s/pkg/k8s"
	"github.com/alegrey91/vex8s/pkg/mitigation"
	"github.com/alegrey91/vex8s/pkg/scanner"
	"github.com/alegrey91/vex8s/pkg/vex"
	"github.com/briandowns/spinner"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
)

var (
	manifestPath       string
	vulnReportPath     string
	scanEngine         string
	outputPath         string
	showCVEs           bool
	showMitigation     bool
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
		var suppressed []vex.Suppression

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

			pc := decisionContext{
				ctx:        context.Background(),
				spec:       podSpec,
				container:  &container,
				classifier: clf,
			}

			var containerSuppressed int
			for j := range cves {
				verdict, reason, ok := decide(pc, &cves[j])
				if ok {
					suppressed = append(suppressed, vex.Suppression{
						CVE:     &cves[j],
						Verdict: verdict,
						Reason:  reason,
					})
					containerSuppressed++
					if showMitigation {
						fmt.Printf("[✓] CVE %s [%s]: %s\n", cves[j].ID, verdictLabel(verdict), reason)
					}
				} else if showMitigation {
					fmt.Printf("[ ] CVE %s: not suppressed (%s)\n", cves[j].ID, reason)
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

// decisionContext carries the per-CVE dependencies for the decision logic.
type decisionContext struct {
	ctx        context.Context
	spec       *corev1.PodSpec
	container  *corev1.Container
	classifier classifier.Classifier
}

func verdictLabel(v vex.Verdict) string {
	if v == vex.SuppressAsReduced {
		return "suppress-as-reduced"
	}
	return "suppress"
}

// decide runs a CVE through the suppression logic for a single container. It
// returns the verdict, a human-readable reason, and whether the CVE is
// suppressed. A CVE is suppressed only if every exploitation class implied by
// its CWEs AND every class predicted by the classifier is mitigated on the
// container.
func decide(pc decisionContext, cve *mitigation.CVE) (vex.Verdict, string, bool) {
	if len(cve.CWEs) == 0 {
		return 0, "no CWE data on CVE; cannot reason about exploitation without ground truth", false
	}

	cweClasses := cwe.Classes(cve.CWEs)
	if len(cweClasses) == 0 {
		return 0, "no CWE maps to a mitigable exploitation class", false
	}

	pred, err := pc.classifier.Classify(pc.ctx, *cve)
	if err != nil {
		return 0, fmt.Sprintf("classifier error: %v", err), false
	}
	if pred.Abstained {
		return 0, "classifier abstained (low confidence)", false
	}
	if len(pred.Classes) == 0 {
		return 0, "classifier predicted no exploitation class", false
	}

	// Union of both arms; every class in it must be mitigated.
	verifyClasses := unionClasses(cweClasses, pred.Classes)
	if len(verifyClasses) == 0 {
		return 0, "no exploitation class to verify", false
	}

	// Track the strongest kind required: if any mitigated class only reduces
	// impact, the whole verdict is capped at reduced.
	worstKind := mitigation.Blocks
	var controls []string
	seenControl := map[string]bool{}
	for _, ec := range verifyClasses {
		res := mitigation.Verify(ec, pc.spec, pc.container)
		if !res.Mitigated {
			return 0, unmitigatedReason(pc.container.Name, ec, res), false
		}
		key := string(ec) + ":" + strings.Join(res.Satisfied, "+")
		if !seenControl[key] {
			seenControl[key] = true
			controls = append(controls, fmt.Sprintf("%s via [%s]", ec, strings.Join(res.Satisfied, ", ")))
		}
		if res.Kind == mitigation.Reduces {
			worstKind = mitigation.Reduces
		}
	}

	verdict := vex.Suppress
	verb := "blocked"
	if worstKind == mitigation.Reduces {
		verdict = vex.SuppressAsReduced
		verb = "impact reduced"
	}

	reason := fmt.Sprintf("%s: %s (CWEs: %s; engine: %s)",
		verb, strings.Join(controls, "; "), strings.Join(cve.CWEs, ", "), pred.Engine)

	// Surface verified classes on the CVE for downstream consumers.
	labels := make([]string, 0, len(verifyClasses))
	for _, c := range verifyClasses {
		labels = append(labels, string(c))
	}
	cve.Labels = labels

	return verdict, reason, true
}

func unionClasses(a, b []class.ExploitClass) []class.ExploitClass {
	seen := map[class.ExploitClass]bool{}
	var out []class.ExploitClass
	for _, c := range append(append([]class.ExploitClass{}, a...), b...) {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

func unmitigatedReason(container string, ec class.ExploitClass, res mitigation.VerifyResult) string {
	if len(res.Vetoed) > 0 {
		return fmt.Sprintf("container %q, class %s: disqualified by %s", container, ec, strings.Join(res.Vetoed, ", "))
	}
	if res.Kind == mitigation.NotMitigable {
		return fmt.Sprintf("container %q, class %s: no pod-level control mitigates this class", container, ec)
	}
	return fmt.Sprintf("container %q, class %s: missing controls %s", container, ec, strings.Join(res.Missing, ", "))
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
	generateCmd.Flags().StringVar(&classifierEngine, "classifier", "embedded", "classifier engine [embedded]")

	// Show flags
	generateCmd.Flags().BoolVar(&showCVEs, "show.cve", false, "show CVE list")
	generateCmd.Flags().BoolVar(&showMitigation, "show.mitigation", false, "show mitigation status")
	generateCmd.Flags().BoolVar(&showSecContext, "show.securitycontext", false, "show manifest SecurityContext")

	// VEX flags
	generateCmd.Flags().StringVar(&vexAuthor, "vex.author", "Unknown Author", "set VEX author")
	generateCmd.Flags().StringVar(&vexAuthorRole, "vex.role", "", "set VEX author role")

	// Suppress flags
	generateCmd.Flags().BoolVar(&suppressDisclaimer, "suppress.disclaimer", false, "suppress disclaimer")
}
