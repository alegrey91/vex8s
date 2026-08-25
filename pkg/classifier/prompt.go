package classifier

import (
	_ "embed"
	"strings"
	"text/template"

	"github.com/alegrey91/vex8s/pkg/class"
	"github.com/alegrey91/vex8s/pkg/mitigation"
)

//go:embed prompt.tmpl
var promptText string

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

// promptTemplate renders the full instruction sent to an LLM backend. It is
// shared across LLM providers (Gemini, Anthropic, ...) so every backend reasons
// about the same taxonomy and returns the same JSON shape.
var promptTemplate = template.Must(template.New("prompt").
	Funcs(template.FuncMap{"join": strings.Join}).
	Parse(promptText))

// BuildPrompt renders the full instruction sent to an LLM backend for a single
// CVE.
func BuildPrompt(cve mitigation.CVE) string {
	type classEntry struct {
		Name string
		Desc string
	}
	classes := make([]classEntry, 0, len(class.All))
	for _, c := range class.All {
		classes = append(classes, classEntry{Name: string(c), Desc: classDescriptions[c]})
	}

	var b strings.Builder
	promptTemplate.Execute(&b, struct {
		Classes []classEntry
		CVE     mitigation.CVE
	}{Classes: classes, CVE: cve})

	return b.String()
}
