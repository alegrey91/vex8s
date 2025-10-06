# Vex8s

Vex8s generates [VEX](https://www.ntia.gov/files/ntia/publications/vex_one-page_summary.pdf) documents by parsing the Kubernetes `securityContext` configuration.

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
