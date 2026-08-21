package gemini

import (
	"fmt"
	"strings"

	"github.com/alegrey91/vex8s/pkg/class"
	"github.com/alegrey91/vex8s/pkg/mitigation"
)

// classDescriptions documents, in security terms, what each exploitation class
// means. The values describe the *outcome an attacker gains* (not the
// vulnerability type), matching the semantics of pkg/class. These descriptions
// are injected verbatim into the prompt so the model reasons about the same
// taxonomy the rest of the pipeline uses.
var classDescriptions = map[class.ExploitClass]string{
	class.ArbitraryFileWrite: "The attacker can create, overwrite, or modify files on the target " +
		"filesystem at paths of their choosing (e.g. path traversal on upload, zip-slip, symlink " +
		"attacks, arbitrary file overwrite). Includes writing outside an intended directory.",
	class.ArbitraryFileRead: "The attacker can read the contents of files on the target filesystem at " +
		"paths of their choosing (e.g. path traversal / local file inclusion / directory traversal " +
		"disclosing sensitive files such as /etc/passwd, secrets, or source code).",
	class.SystemPrivilegesEscalation: "The attacker gains higher privileges at the operating-system / " +
		"host level, e.g. escalating to root, container escape/breakout to the host, kernel privilege " +
		"escalation, or abusing setuid/capabilities to gain system-wide control.",
	class.ApplicationPrivilegesEscalation: "The attacker gains higher privileges *within the application* " +
		"without leaving it, e.g. a normal user becoming an admin, authentication/authorization bypass, " +
		"privilege escalation confined to the app's own permission model.",
	class.ResourceExhaustion: "The attacker can exhaust system resources (CPU, memory, disk, file " +
		"descriptors, network, threads) causing degraded service or denial of service, e.g. algorithmic " +
		"complexity attacks, unbounded allocation, decompression bombs, infinite loops.",
	class.ApplicationCrash: "The attacker can crash or abnormally terminate the application/process, e.g. " +
		"unhandled panic, null-pointer dereference, segmentation fault, assertion failure, or " +
		"reachable fatal error triggered by malicious input.",
	class.Other: "Use ONLY when none of the specific classes above apply, or the description does not " +
		"provide enough information to determine a concrete exploitation outcome (e.g. information " +
		"disclosure that is not file read, spoofing, or an unclear/generic description).",
}

// buildPrompt renders the full instruction sent to Gemini for a single CVE.
func buildPrompt(cve mitigation.CVE) string {
	var b strings.Builder

	b.WriteString("You are a security expert classifying software vulnerabilities (CVEs) by the " +
		"concrete exploitation OUTCOME an attacker gains — NOT by the vulnerability type or root cause.\n\n")

	b.WriteString("Classify the CVE below into one or more of the following classes. A CVE may map to " +
		"multiple classes. Choose every class that clearly applies based on the described impact. " +
		"If nothing specific applies, use \"other\".\n\n")

	b.WriteString("Classes:\n")
	for _, c := range class.All {
		fmt.Fprintf(&b, "- %s: %s\n", c, classDescriptions[c])
	}

	b.WriteString("\nGuidelines:\n")
	b.WriteString("- Base your decision strictly on the described impact; do not speculate beyond the text.\n")
	b.WriteString("- Prefer a specific class over \"other\" whenever the impact is clear.\n")
	b.WriteString("- Do not include \"other\" together with any specific class.\n")
	b.WriteString("- Distinguish system-level from application-level privilege escalation carefully.\n\n")

	b.WriteString("CVE to classify:\n")
	fmt.Fprintf(&b, "ID: %s\n", cve.ID)
	if len(cve.CWEs) > 0 {
		fmt.Fprintf(&b, "CWEs: %s\n", strings.Join(cve.CWEs, ", "))
	}
	fmt.Fprintf(&b, "Description: %s\n", cve.Description)

	b.WriteString("\nReturn a JSON object with a single field \"classes\" containing the array of " +
		"matching class identifiers from the list above.")

	return b.String()
}
