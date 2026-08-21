package decision

import (
	"context"
	"fmt"
	"strings"

	"github.com/alegrey91/vex8s/pkg/class"
	"github.com/alegrey91/vex8s/pkg/classifier"
	"github.com/alegrey91/vex8s/pkg/cwe"
	"github.com/alegrey91/vex8s/pkg/mitigation"
	corev1 "k8s.io/api/core/v1"
)

// Verdict is the outcome for a suppressed CVE.
type Verdict int

const (
	// Suppress: a blocking control neutralizes the CVE. Maps to VEX
	// not_affected.
	Suppress Verdict = iota
	// SuppressAsReduced: a reducing control bounds the impact but the flaw can
	// still trigger. Maps to VEX affected + action_statement.
	SuppressAsReduced
)

func (v Verdict) String() string {
	if v == SuppressAsReduced {
		return "suppress-as-reduced"
	}
	return "suppress"
}

// Suppression records a suppressed CVE and why.
type Suppression struct {
	CVE     *mitigation.CVE
	Verdict Verdict
	Reason  string
}

// Context carries the per-CVE dependencies for the decision logic.
type Context struct {
	Ctx        context.Context
	Spec       *corev1.PodSpec
	Container  *corev1.Container
	Classifier classifier.Classifier
}

// Decide runs a CVE through the suppression logic for a single container. It
// returns the verdict, a human-readable reason, and whether the CVE is
// suppressed. A CVE is suppressed only if every exploitation class implied by
// its CWEs AND every class predicted by the classifier is mitigated on the
// container.
func Decide(pc Context, cve *mitigation.CVE) (Verdict, string, bool) {
	if len(cve.CWEs) == 0 {
		return 0, "no CWE data on CVE; cannot reason about exploitation without ground truth", false
	}

	cweClasses := cwe.Classes(cve.CWEs)
	if len(cweClasses) == 0 {
		return 0, "no CWE maps to a mitigable exploitation class", false
	}

	pred, err := pc.Classifier.Classify(pc.Ctx, *cve)
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
		res := mitigation.Verify(ec, pc.Spec, pc.Container)
		if !res.Mitigated {
			return 0, unmitigatedReason(pc.Container.Name, ec, res), false
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

	verdict := Suppress
	verb := "blocked"
	if worstKind == mitigation.Reduces {
		verdict = SuppressAsReduced
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
