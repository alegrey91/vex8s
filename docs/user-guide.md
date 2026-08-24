# Vex8s User Guide

This guide walks through using `vex8s` to generate [VEX](https://www.ntia.gov/files/ntia/publications/vex_one-page_summary.pdf)
documents that suppress CVEs which are not exploitable given your Kubernetes
workload configuration.

For the conceptual background (how CVEs are classified and correlated with
`securityContext` settings), see the [README](../README.md#how-it-works).

## Prerequisites

- `vex8s`: download from the [releases](https://github.com/alegrey91/vex8s/releases)
  page, or build it with `make build`.
- A vulnerability scanner: [`trivy`](https://github.com/aquasecurity/trivy) or
  [`grype`](https://github.com/anchore/grype).
- A Kubernetes manifest (Pod, Deployment, DaemonSet, StatefulSet, Job, CronJob, …)
  describing the workload you want to assess. See the [`examples/`](../examples)
  directory for hardened and non-hardened samples.

## Basic workflow

`vex8s generate` takes a Kubernetes manifest and a vulnerability report, and
produces a VEX document:

```
vex8s generate \
  --manifest examples/deployment-nginx-dummy.yaml \
  --report nginx.trivy.json \
  --output nginx.vex.json
```

You can feed the report from an existing scan (**passive mode**) or let `vex8s`
run the scan for you (**active mode**). Both are described in the
[README Usage section](../README.md#usage).

## Classifiers

Each CVE is categorized into one or more *exploitation classes* — what an
attacker actually gains (e.g. `arbitrary_file_write`,
`system_privileges_escalation`, `resource_exhaustion`). These classes are then
combined with the workload's security settings to decide whether the CVE is
mitigable.

`vex8s` supports two classifier engines, selected with the `--classifier` flag:

| Engine     | Flag value            | How it works                                             | Network |
|------------|-----------------------|----------------------------------------------------------|---------|
| Embedded   | `embedded` (default)  | Offline ONNX ML model bundled in the binary.             | No      |
| Gemini     | `gemini`              | Google's Gemini LLM classifies the CVE description.      | Yes     |

If you omit `--classifier`, the embedded model is used and no network access is
required.

## Using the Gemini classifier

The Gemini classifier sends each CVE's description to Google's Gemini API and
asks the model to classify it into the canonical exploitation classes. It can
capture nuance in free-text descriptions that the embedded model may miss, at
the cost of requiring an API key and network access.

### 1. Set your API key

```
export GEMINI_API_KEY="your-api-key"
```

`vex8s` validates the key up front, so a missing key fails immediately rather
than mid-run.

Optionally override the model (defaults to `gemini-3.7-flash`):

```
export GEMINI_MODEL="gemini-3.7-flash"
```

### 2. Run with `--classifier gemini`

```
vex8s generate \
  --manifest examples/deployment-nginx-dummy.yaml \
  --report nginx.trivy.json \
  --output nginx.vex.json \
  --classifier gemini
```

### 3. (Optional) Watch the classification

Add `--show.classification` to see per-CVE classifier activity on stderr,
including API calls and cache hits:

```
vex8s generate \
  --manifest examples/deployment-nginx-dummy.yaml \
  --report nginx.trivy.json \
  --output nginx.vex.json \
  --classifier gemini \
  --show.classification
```

```
[*] classifier(gemini:gemini-3.7-flash): calling API for CVE-2023-1234
[+] classifier(gemini:gemini-3.7-flash): CVE-2023-1234 classified as [arbitrary_file_write]
[*] classifier: cache hit for CVE-2023-1234
```

### Caching

Because a CVE's exploitation class depends only on the vulnerability itself
(not on the container it ships in), each CVE is classified **once per run** and
the result is reused wherever that CVE appears again. This keeps API usage and
cost low when the same CVE spans multiple packages or containers.

