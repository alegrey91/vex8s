# Vex8s

Vex8s generates [VEX](https://www.ntia.gov/files/ntia/publications/vex_one-page_summary.pdf) documents by correlating container vulnerabilities with Kubernetes `securityContext` to determine which CVEs are actually exploitable in your cluster.

Please note, this is an experimental project. Things might change quickly.

## How It Works

The project aims to assess the exploitability of known CVEs within Kubernetes workloads by combining vulnerability classification and [`securityContext`](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/) analysis.

It is based on the following concept:

* Each CVE can be categorized into one or more vulnerability classes (e.g., Privilege Escalation, Container Escape, Filesystem Manipulation).
* Each class, maps to a set of Kubernetes `securityContext` settings that can block or reduce the impact.
* By analyzing the CVE description, we can infer which vulnerability class(es) the CVE belongs to.
* By parsing a Kubernetes manifest, we can inspect the container's `securityContext` to evaluate whether the relevant settings are in place.
* Combining both analyses allows the system to determine if a CVE is exploitable in a given workload configuration.
* If it results in a CVE mitigation, we can add this to the final VEX document.

Below, here's an example of the identified classes for the CVEs.

| Class | Rules | Description |
|-------|-------|-------------|
| Privilege Escalation | `allowPrivilegeEscalation: false`,</br>`runAsNonRoot: true`,</br>`capabilities.drop: ["ALL"]` | Flaws that allow a process to gain higher privileges (e.g., root in the container or node) than originally intended. |
| Container Escape | `privileged: false`,</br>`capabilities.drop: ["ALL"]`,</br>`readOnlyRootFilesystem: true` | Bugs that allow code inside a container to break isolation and access the host filesystem, processes, or kernel. |
| Filesystem Manipulation | `readOnlyRootFilesystem: true`,</br>`runAsNonRoot: true`,</br>(volumes)`readOnly: true` | Vulnerabilities that rely on modifying or writing to files (e.g., replacing binaries, symlink attacks, tampering with configs). |
| Root-Only | `runAsNonRoot: true`,</br>`runAsUser: >=1000` | CVEs that require root privileges (UID 0) to exploit successfully. |

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
# examples/nginx.yaml uses the nginx:1.21.0 image.
vex8s -manifest examples/nginx.yaml -output nginx.vex.json

# nginx.vex.json will let trivy suppress the CVEs listed inside.
trivy image --skip-version-check --vex nginx.vex.json --show-suppressed nginx:1.21.0
```

## References

This project was inspired by Akihiro Suda's project [vexllm](https://github.com/AkihiroSuda/vexllm).
