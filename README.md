# EasyConstat Evidence Verifier

Source repository:
[probantia-sas/easyconstat-evidence-verifier](https://github.com/probantia-sas/easyconstat-evidence-verifier)

This repository contains the offline verifier and specification for
EasyConstat self-contained evidence packages. The verifier reads only the
files supplied to it; it has no access to EasyConstat production services.
This is a release candidate, not a change to the evidence delivered today.

## Goals

- package all evidence artifacts in an ETSI ASiC-E container;
- bind every payload through a CAdES Baseline LT electronic seal;
- include a small machine-readable manifest for semantic verification;
- validate locally, without uploading evidence to EasyConstat;
- report `VALID`, `INVALID` or `INDETERMINATE` without overstating what the
  cryptography proves;
- keep the current ZIP delivery unchanged until shadow qualification is
  complete.

## Verification scope

The V2 manifest, strict container and hash validation, and DSS validation
boundary are implemented. The test suite creates real synthetic
ASiC-E/CAdES-B-LT packages with a local RFC 3161 timestamp, a test-only PKI and
CRL. It proves that approved trust can produce `VALID`, missing trust produces
`INDETERMINATE`, unrelated trust is never accepted, altered payloads are
`INVALID`, historical validation survives signer-certificate expiry, and a
timestamped package without embedded LT material is rejected.

A production-neutral preparer now converts an immutable copy of an existing
EasyConstat ZIP into a deterministic staging directory. It copies every
payload byte-for-byte, assigns a documented semantic role, records its size
and SHA-256 digest, and creates `evidence-manifest.json`. The preparer rejects
unsafe names, duplicate or foreign artifacts, symbolic paths, oversized
entries and existing output directories. It never signs, calls a TSA, reads a
database or changes a workflow.

The manifest is not self-signed JSON. It is one of the payloads covered by the
CAdES signature inside the ASiC-E container, together with every artifact it
describes. This avoids an ambiguous second signature mechanism while binding
the manifest and the evidence payloads to the same seal and trusted timestamp.

A complete automated test exercises preparation, ASiC-E/CAdES-B-LT
signature, offline verification and payload alteration detection.

A durable non-production package, trust store and signed provenance statement
are retained under `src/test/resources/qualification`. The build verifies the
provenance signature, both recorded SHA-256 values and the package result.

All keys and certificates used by these tests are unrelated to EasyConstat
production. Authenticity of a distributed binary is established separately
by the release signature and an independently obtained public release key.

See [SPECIFICATION.md](SPECIFICATION.md) and [SECURITY.md](SECURITY.md).

## Build

Prerequisites: JDK 17 and Maven 3.9 or later.

```text
mvn clean verify
```

No production deployment is performed by the build.

The Maven build uses a fixed output timestamp so that identical sources and
dependencies produce a byte-for-byte reproducible verifier JAR.

The build tests the prepared-evidence lifecycle, French/English output,
the EU LOTL bootstrap and the standalone runtime ZIP. It starts the
verifier from the extracted ZIP against a durable synthetic ASiC-E package
and checks the bundled libraries and notices. Release qualification compares
two clean builds. Exact release hashes are carried by the signed manifest.

The build also produces a standalone runtime ZIP, main/test source JARs, a
complete source-release ZIP and a CycloneDX 1.6 JSON SBOM. See
[SIGNED_RELEASES.md](docs/SIGNED_RELEASES.md) for deterministic release
preparation, detached Ed25519 signing and independent verification.
Repository protection is specified in
[REPOSITORY_GOVERNANCE.md](docs/REPOSITORY_GOVERNANCE.md), and definitive key
handling in [RELEASE_KEY_CUSTODY.md](docs/RELEASE_KEY_CUSTODY.md).

## Licence

Copyright 2026 PROBANTIA SAS. This project is licensed under the
[Apache License 2.0](LICENSE). The EasyConstat and PROBANTIA names and logos
remain protected marks; see [NOTICE](NOTICE).

Contributions are governed by [CONTRIBUTING.md](CONTRIBUTING.md). Report
security vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Command-line verifier

Unpack the runtime ZIP, keep the `lib/` directory beside `verifier.jar`, and
run:

```text
java -jar verifier.jar --lang fr evidence.asice
```

The all-in-one JAR in `target/` is for internal qualification, not distribution.

Use `--lang fr` or `--lang en` for a human-readable result. `--json` keeps the
stable machine-readable output and ignores presentation language.

For authenticated European trust, refresh a versioned bundle with the
separate maintenance command and pass it with `--eu-trust-bundle`. Ordinary
verification then remains offline. See
[EU_TRUST_LISTS.md](docs/EU_TRUST_LISTS.md) for commands, bootstrap provenance
and fail-closed update rules.

Without an approved trust source, successful integrity checks intentionally
return `INDETERMINATE`. An authenticated, locally cached EU List of Trusted
Lists bundle can be supplied for European trust. A curated JKS or PKCS12 trust
store can also be supplied for qualification tests; its password is read from
`EASYCONSTAT_TRUSTSTORE_PASSWORD` and is never accepted as a command-line
argument.

The verifier never extracts or uploads evidence payloads. Its result does not
establish that statements captured in the evidence are true or determine
whether a court will admit or rely on that evidence.
