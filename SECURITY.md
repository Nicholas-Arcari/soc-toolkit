# Security policy

## Reporting a vulnerability

If you believe you've found a security issue in this project, please
**do not open a public issue**. Instead, file a private security
advisory through GitHub:

> <https://github.com/Nicholas-Arcari/soc-toolkit/security/advisories/new>

Include a reproducer, the affected workspace (`sec-common`,
`soc-toolkit`, or `osint-toolkit`), and a proposed severity. We aim
to triage within 72 hours and to publish a fix + advisory within 30
days for High/Critical findings. Lower-severity issues ship in the
next regular release.

Coordinated disclosure is preferred - we'll credit reporters in the
advisory and the CHANGELOG once a fix is public, unless you ask to
remain anonymous.

## Signed release artifacts

Every tagged release publishes four images to GHCR:

- `ghcr.io/nicholas-arcari/soc-toolkit-soc-backend`
- `ghcr.io/nicholas-arcari/soc-toolkit-soc-frontend`
- `ghcr.io/nicholas-arcari/soc-toolkit-osint-backend`
- `ghcr.io/nicholas-arcari/soc-toolkit-osint-frontend`

Each image is:

- **Signed** with [cosign](https://github.com/sigstore/cosign) keyless
  (OIDC identity bound to the release workflow).
- **Attested** with a [SLSA build-level 2](https://slsa.dev/spec/v1.0/levels)
  provenance attestation produced by BuildKit, recording the exact
  source commit, builder identity, and build context.
- **Documented** with a buildx SBOM attestation (syft-generated) plus
  an SPDX SBOM attached to the GitHub release assets.

### Verify the signature

```bash
IMAGE=ghcr.io/nicholas-arcari/soc-toolkit-soc-backend:v0.1.0

cosign verify "$IMAGE" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity-regexp='^https://github.com/Nicholas-Arcari/soc-toolkit/\.github/workflows/release\.yml@refs/tags/v.+$'
```

A successful run prints the signature payload (image digest,
certificate subject, signer identity). Any mismatch - a repo fork
re-pushing under a different identity, or a registry-side tag retag
against an unsigned digest - fails verification.

### Verify the SLSA provenance

```bash
cosign verify-attestation "$IMAGE" \
  --type slsaprovenance \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity-regexp='^https://github.com/Nicholas-Arcari/soc-toolkit/\.github/workflows/release\.yml@refs/tags/v.+$' \
  | jq -r '.payload | @base64d | fromjson | .predicate'
```

The predicate body includes `buildDefinition.externalParameters`
(source repo + ref), `buildDefinition.resolvedDependencies` (base
images pinned by digest), and `runDetails.metadata.invocationID` -
the GitHub Actions run that built the image.

### Verify the SBOM attestation

```bash
cosign verify-attestation "$IMAGE" \
  --type spdxjson \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity-regexp='^https://github.com/Nicholas-Arcari/soc-toolkit/\.github/workflows/release\.yml@refs/tags/v.+$' \
  | jq -r '.payload | @base64d | fromjson | .predicate.Packages | length'
```

The predicate is an SPDX 2.3 document enumerating every OS package
and language dependency baked into the final image.

## Supported versions

Only the latest minor release receives security fixes. The `main`
branch gets fixes as they land; older minors are not patched unless
an organization has a sponsorship arrangement with the maintainers.

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |
