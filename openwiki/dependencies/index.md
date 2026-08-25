# Files

- [Endpoint exposure](endpoint-exposure.md) - The one control that asks about the developer's machine rather than the repository, and the four ways an empty scan is not a clean one.
- [Manifests and package trust](manifests-and-package-trust.md) - Which manifests are read, why a dependency's source decides what may be asked about it, and how the approved-package baseline gates new dependencies.
- [OpenVEX suppression](openvex.md) - The full lifecycle of a VEX waiver — written by one module, consumed by another — and why a bare product name deliberately reaches across ecosystems.
- [SBOM generation](sbom-generation.md) - Producing a software bill of materials, validating it is what it claims to be, and one gap in the matcher's output handling.
- [Vulnerability scanning](vulnerability-scanning.md) - How Trivy and OSV-Scanner are orchestrated, how severity gating decides an exit code, and why every suppression is named rather than silently honoured.
