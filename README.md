```
vex8s -manifest examples/nginx.yaml -output nginx.vex.json
trivy image --skip-version-check --vex nginx.vex.json --show-suppressed nginx:1.21.0
```
