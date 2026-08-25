package mitigation

import (
	"github.com/alegrey91/vex8s/pkg/class"
	corev1 "k8s.io/api/core/v1"
)

// MitigationKind distinguishes controls that fully block an exploitation
// outcome from those that only reduce its impact (e.g. resource limits bound a
// DoS but do not prevent it). The decision layer maps these to different VEX
// statuses: blocks -> not_affected, reduces -> affected + action_statement.
type MitigationKind int

const (
	// Blocks means the required controls neutralize the exploitation vector.
	Blocks MitigationKind = iota
	// Reduces means the controls bound the blast radius but the flaw can still
	// be triggered.
	Reduces
	// NotMitigable means no pod-level control addresses this class.
	NotMitigable
)

// Check is a single named securityContext / pod-spec predicate. The Name is
// surfaced in the VEX justification, so it must be human-meaningful.
type Check struct {
	Name string
	Eval func(*corev1.PodSpec, *corev1.Container) bool
}

// Rule describes how a single exploitation class can be mitigated.
//
// A container is mitigated for the class iff every Required check passes AND no
// Disqualifier check fires. Disqualifiers are OR-ed then negated: any single
// one present vetoes the suppression regardless of the required checks.
type Rule struct {
	Kind          MitigationKind
	Required      []Check
	Disqualifiers []Check
}

// VerifyResult reports the outcome of evaluating a Rule against one container.
type VerifyResult struct {
	Mitigated  bool
	Kind       MitigationKind
	Satisfied  []string // required checks that passed
	Missing    []string // required checks that failed
	Vetoed     []string // disqualifiers that fired
}

// rules is the per-class mitigation table.
var rules = map[class.ExploitClass]Rule{
	class.ArbitraryFileWrite: {
		Kind: Blocks,
		Required: []Check{
			{"readOnlyRootFilesystem", func(p *corev1.PodSpec, c *corev1.Container) bool { return hasReadOnlyRootFileSystem(c) }},
			{"volumeMountsReadOnly", func(p *corev1.PodSpec, c *corev1.Container) bool { return hasVolumeMountReadOnly(c) }},
		},
	},
	class.SystemPrivilegesEscalation: {
		Kind: Blocks,
		Required: []Check{
			{"privileged=false", func(p *corev1.PodSpec, c *corev1.Container) bool { return isNotPrivileged(c) }},
			{"allowPrivilegeEscalation=false", func(p *corev1.PodSpec, c *corev1.Container) bool { return disallowsPrivilegeEscalation(c) }},
			{"runAsNonRootOrNonZeroUser", func(p *corev1.PodSpec, c *corev1.Container) bool { return hasRunAsNonRoot(p, c) || hasRunAsUser(p, c) }},
			{"capabilitiesDropAll", func(p *corev1.PodSpec, c *corev1.Container) bool { return hasCapabilitiesDropAll(c) }},
		},
		Disqualifiers: []Check{
			// Host namespace / path exposure is not addressed by the required
			// checks above, and turns an in-container escalation into a host
			// compromise. Any of these vetoes the suppression.
			{"hostPID", func(p *corev1.PodSpec, c *corev1.Container) bool { return p.HostPID }},
			{"hostIPC", func(p *corev1.PodSpec, c *corev1.Container) bool { return p.HostIPC }},
			{"hostPathVolume", func(p *corev1.PodSpec, c *corev1.Container) bool { return hasHostPath(p) }},
			{"dangerousCapabilityAdded", func(p *corev1.PodSpec, c *corev1.Container) bool {
				return hasCapabilitiesAddContains(c, []string{"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_ADMIN", "DAC_OVERRIDE", "DAC_READ_SEARCH"})
			}},
		},
	},
	class.ResourceExhaustion: {
		Kind: Reduces,
		Required: []Check{
			{"resourceLimitCPU", func(p *corev1.PodSpec, c *corev1.Container) bool { return hasResourceLimitCPU(p, c) }},
			{"resourceLimitMemory", func(p *corev1.PodSpec, c *corev1.Container) bool { return hasResourceLimitMemory(p, c) }},
		},
	},
	// The following classes have no pod-level mitigation and always keep the CVE
	// flagged. They are listed explicitly so the pipeline can report *why*.
	class.ArbitraryFileRead:               {Kind: NotMitigable},
	class.ApplicationPrivilegesEscalation: {Kind: NotMitigable},
	class.ApplicationCrash:                {Kind: NotMitigable},
	class.Other:                           {Kind: NotMitigable},
}

// Verify evaluates the rule for a class against a single container. An unknown
// class or a NotMitigable class yields Mitigated=false.
func Verify(c class.ExploitClass, p *corev1.PodSpec, ct *corev1.Container) VerifyResult {
	rule, ok := rules[c]
	if !ok || rule.Kind == NotMitigable {
		return VerifyResult{Mitigated: false, Kind: NotMitigable}
	}

	res := VerifyResult{Kind: rule.Kind, Mitigated: true}
	for _, req := range rule.Required {
		if req.Eval(p, ct) {
			res.Satisfied = append(res.Satisfied, req.Name)
		} else {
			res.Missing = append(res.Missing, req.Name)
			res.Mitigated = false
		}
	}
	for _, dq := range rule.Disqualifiers {
		if dq.Eval(p, ct) {
			res.Vetoed = append(res.Vetoed, dq.Name)
			res.Mitigated = false
		}
	}
	return res
}

// Kind returns the MitigationKind for a class (NotMitigable if unknown).
func Kind(c class.ExploitClass) MitigationKind {
	if r, ok := rules[c]; ok {
		return r.Kind
	}
	return NotMitigable
}
