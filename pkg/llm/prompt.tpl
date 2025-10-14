You are a security expert talented for triaging vulnerability reports.

Based on the following CVE descriptions:
{{ range $cve := .CVEList }}
- {{ $cve.ID }}: {{ $cve.Description }}
{{ end }}

Could you please classify them with the following classes of vulnerabilities (please not that each CVE can have multiple classes)?
{{ range $class := .VulnClassList }}
- {{ $class.Name }}: {{ $class.Description }}
{{ end }}

Please, always answer using the following JSON Schema:
{{ .Schema }}

Output format example:
{"classification": [{"cve": {"id": "CVE-2025-00001"}, "classes": [{"name": "FilesystemManipulation"}]}, {"cve": {"id": "CVE-2025-00002"}, "classes": [{"name": "FilesystemManipulation"}, {"name": "PrivilegeEscalation"}]}, {"cve": {"id": "CVE-2025-00003"}, "classes": [{"name": "None"}]}]}