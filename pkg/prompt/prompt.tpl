You are a security expert talented for triaging vulnerability reports.

Based on the following CVEs with their descriptions:
{{ range $cve := .CVEList }}
• [{{ $cve.ID }}]: --- {{ $cve.Description }} ---
{{ end }}

Could you please classify them with the following classes of vulnerabilities?
(please use only the ones listed below)
{{ range $class := .VulnClassList }}
• [{{ $class.Name }}]: --- {{ $class.Description }} ---
{{ end }}

The output MUST always be formatted with the following JSON Schema:
{{ .Schema }}

This is an output EXAMPLE:
{
  "classification": [
    {"cve": {"id": "CVE-2019-16149"}, "classes": [{"name": "None"}]},
    {"cve": {"id": "CVE-2020-31137"}, "classes": [{"name": "FilesystemManipulation"}]},
    {"cve": {"id": "CVE-2020-18891"}, "classes": [{"name": "RootOnly"}]},
    {"cve": {"id": "CVE-2021-42170"}, "classes": [{"name": "PrivilegeEscalation"}]},
    {"cve": {"id": "CVE-2022-42559"}, "classes": [{"name": "PrivilegeEscalation"}]},
    {"cve": {"id": "CVE-2022-52380"}, "classes": [{"name": "PrivilegeEscalation"}]},
    {"cve": {"id": "CVE-2023-12384"}, "classes": [{"name": "PrivilegeEscalation"}]},
    {"cve": {"id": "CVE-2023-42342"}, "classes": [{"name": "PrivilegeEscalation"}]},
    {"cve": {"id": "CVE-2024-42283"}, "classes": [{"name": "PrivilegeEscalation"}]}
  ]
}