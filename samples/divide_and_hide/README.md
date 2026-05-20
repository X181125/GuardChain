# Divide-and-Hide Sample

This sample demonstrates a HERCULE-inspired dependency-chain scenario.

- `root_pkg` contains only benign helper code and declares `hidden-payload-dep`.
- `hidden_payload_dep` contains obfuscation followed by dynamic execution.

Scanning `root_pkg` without dependency resolution should only inspect the root package. Scanning with dependency resolution and a suitable local/mock index can surface the dependency-origin behavior and report the chain:

```text
root-pkg -> hidden-payload-dep
```
