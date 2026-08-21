// Package cwe provides the deterministic, authoritative mapping from CWE
// identifiers to exploitation classes. This is the "precision" signal in the
// decision chain: it comes straight from the CVE record with no inference.
package cwe

import "github.com/alegrey91/vex8s/pkg/class"

// cweClasses maps a CWE id to the exploitation class(es) it implies.
// A CWE may map to more than one class. CWEs absent from this map contribute
// no class (the CVE is only suppressible if *some* CWE anchors a class).
var cweClasses = map[string][]class.ExploitClass{
	// arbitrary_file_write
	"CWE-22":  {class.ArbitraryFileWrite},  // Path Traversal
	"CWE-23":  {class.ArbitraryFileWrite},  // Relative Path Traversal
	"CWE-36":  {class.ArbitraryFileWrite},  // Absolute Path Traversal
	"CWE-59":  {class.ArbitraryFileWrite},  // Link Following
	"CWE-73":  {class.ArbitraryFileWrite},  // External Control of File Name or Path
	"CWE-276": {class.ArbitraryFileWrite},  // Incorrect Default Permissions
	"CWE-377": {class.ArbitraryFileWrite},  // Insecure Temporary File
	"CWE-378": {class.ArbitraryFileWrite},  // Temp File with Insecure Permissions
	"CWE-379": {class.ArbitraryFileWrite},  // Temp File in Insecure Dir
	"CWE-434": {class.ArbitraryFileWrite},  // Unrestricted Upload
	"CWE-732": {class.ArbitraryFileWrite},  // Incorrect Permission Assignment
	"CWE-915": {class.ArbitraryFileWrite},  // Improperly Controlled Modification of Object Attributes

	// system_privileges_escalation
	"CWE-77":  {class.SystemPrivilegesEscalation}, // Command Injection
	"CWE-78":  {class.SystemPrivilegesEscalation}, // OS Command Injection
	"CWE-250": {class.SystemPrivilegesEscalation}, // Execution with Unnecessary Privileges
	"CWE-266": {class.SystemPrivilegesEscalation}, // Incorrect Privilege Assignment
	"CWE-269": {class.SystemPrivilegesEscalation}, // Improper Privilege Management
	"CWE-271": {class.SystemPrivilegesEscalation}, // Privilege Dropping / Lowering Errors
	"CWE-272": {class.SystemPrivilegesEscalation}, // Least Privilege Violation
	"CWE-273": {class.SystemPrivilegesEscalation}, // Improper Check for Dropped Privileges
	"CWE-653": {class.SystemPrivilegesEscalation}, // Improper Isolation or Compartmentalization

	// resource_exhaustion
	"CWE-400": {class.ResourceExhaustion}, // Uncontrolled Resource Consumption
	"CWE-770": {class.ResourceExhaustion}, // Allocation of Resources Without Limits
}

// Classes returns the deduplicated set of exploitation classes anchored by the
// given CWE ids. Unknown CWEs contribute nothing. The result is empty when no
// CWE maps to a known class.
func Classes(cweIDs []string) []class.ExploitClass {
	seen := map[class.ExploitClass]bool{}
	var out []class.ExploitClass
	for _, id := range cweIDs {
		for _, c := range cweClasses[id] {
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	return out
}
