# Vex8s

![vex8s](./vex8s.png)
(this logo is not AI generated)

Vex8s generates [VEX](https://www.ntia.gov/files/ntia/publications/vex_one-page_summary.pdf) documents by correlating container vulnerabilities with Kubernetes `securityContext` to determine which CVEs are actually exploitable in your cluster.

Please note, this is an experimental project. Things might change quickly.

## How It Works

The project aims to assess the exploitability of known CVEs within Kubernetes workloads by combining vulnerability classification and [`securityContext`](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/) analysis.

It is based on the following concept:

* Each CVE is categorized into one or more vulnerability classes ([CWE](https://cwe.mitre.org/index.html))
* Each class, maps to a set of Kubernetes `securityContext` settings that can block or reduce the impact.
* By parsing a Kubernetes manifest, we can inspect the container's `securityContext` to evaluate whether the relevant settings are in place.
* Combining both analyses allows the system to determine if a CVE is exploitable in a given workload configuration.
* If it results in a CVE mitigation, we add this to the final VEX document.

## Installation

You can install it directly:

```
go install github.com/alegrey91/vex8s@latest
```

Or you can build it manually:

```
make build
```

## Example

```
# scan the image without passing a VEX file.
trivy image --skip-version-check nginx:1.21.0

# examples/nginx.yaml uses the nginx:1.21.0 image.
vex8s generate --manifest=examples/nginx.yaml --output nginx.vex.json

# nginx.vex.json will let trivy suppress the CVEs listed inside.
trivy image --skip-version-check --vex=nginx.vex.json --show-suppressed nginx:1.21.0
```

## References

This project was inspired by Akihiro Suda's project [vexllm](https://github.com/AkihiroSuda/vexllm).
