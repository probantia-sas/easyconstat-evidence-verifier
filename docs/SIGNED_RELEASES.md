# Signed verifier releases

This document describes the release mechanism prepared for the public
EasyConstat Evidence Verifier. It does not publish anything and it is not
connected to an EasyConstat production workflow.

## Release contents

`mvn clean verify` creates reproducible build artifacts using the fixed Maven
output timestamp:

- the executable shaded verifier JAR, for internal qualification only;
- the runtime ZIP with `verifier.jar`, original libraries in `lib/` and
  their license and attribution files in `licenses/`;
- main and test source JARs;
- a complete source-release ZIP including tests, resources and build files;
- a CycloneDX 1.6 JSON SBOM without a random BOM serial number.

`ops/release/prepare-release.sh` copies the runtime ZIP, source artifacts,
SBOM and documentation to a new release directory. It does not distribute
the shaded JAR. Provide the upstream DSS source archive separately; the
script checks its locked SHA-256 and verifies that the DSS version in the
SBOM matches. Both ZIPs are covered by the same signed manifest.

For the current DSS 6.5.1 dependency, download the
[exact upstream source ZIP](https://codeload.github.com/esig/dss/zip/98ab6c136fc90bfca78352b4e673e2eae72b7d5a)
under the name `dss-6.5.1-source.zip`. Its checksum is locked in
`ops/release/dss-source.sha256`. Release preparation is local and does not
fetch anything. Changing DSS requires updating the inventory, the license,
and the matching source archive and checksum.

The preparer also writes:

- `SHA256SUMS` for convenient manual checks;
- `release-signing-key.pem`, which is public material only;
- `release-manifest.json`, a deterministic inventory containing every file's
  role, size and SHA-256 digest.

The manifest is never overwritten. Preparation also refuses an existing
release directory.

## Detached signature

The release manifest is signed with Ed25519 by
`ops/release/sign-release.sh`. The script checks the recorded public-key
fingerprint and verifies the new signature against that public key before
publishing it. OpenSSL reads the encrypted private key directly without
writing a decrypted key to disk. The output is the raw detached signature
`release-manifest.json.sig`.

The definitive release private key must be created and retained outside the
EasyConstat production server. Its public-key fingerprint must be published
through an independently authenticated EasyConstat channel. A public key
bundled with a release is convenient, but is not by itself an authenticity
anchor. The mandatory custody and recovery controls are defined in
`RELEASE_KEY_CUSTODY.md`.

## Verification

The verifier script requires a separately obtained trusted public key:

```text
tools/verify-release.sh RELEASE_DIRECTORY TRUSTED_RELEASE_PUBLIC_KEY_PEM
```

It verifies, in this order:

1. the SHA-256 fingerprint of the trusted Ed25519 public key;
2. the detached signature of the exact manifest bytes;
3. the manifest format and algorithms;
4. every declared file's path, size and SHA-256 digest;
5. the absence of undeclared files;
6. the human-readable `SHA256SUMS` inventory.

The script depends on OpenSSL, `jq` and standard GNU userland tools. It does
not execute the verifier JAR before its digest has been checked.

## Internal qualification example

The following commands use a disposable key only. They must not be used to
create the definitive public signing key:

```text
openssl genpkey -algorithm ED25519 -out /tmp/release-test-private.pem
openssl pkey -in /tmp/release-test-private.pem -pubout \
  -out /tmp/release-test-public.pem
mvn clean verify
ops/release/prepare-release.sh 0.1.0-SNAPSHOT \
  /tmp/easyconstat-verifier-0.1.0-SNAPSHOT \
  /tmp/release-test-public.pem \
  /path/to/dss-6.5.1-source.zip
ops/release/sign-release.sh \
  /tmp/easyconstat-verifier-0.1.0-SNAPSHOT \
  /tmp/release-test-private.pem
/tmp/easyconstat-verifier-0.1.0-SNAPSHOT/tools/verify-release.sh \
  /tmp/easyconstat-verifier-0.1.0-SNAPSHOT \
  /tmp/release-test-public.pem
```

Delete the disposable key and release directory after the test.

On Linux, `bash ops/release/qualify-release.sh 0.1.0-SNAPSHOT
/path/to/dss-6.5.1-source.zip` additionally compares two clean builds,
checks rejection of altered runtime bytes and of a wrong DSS source archive,
and repeats the signing test with a disposable encrypted key.

## Publication gate

Technical release preparation does not authorize public distribution. The
source-code licence is Apache License 2.0. Before the first public binary
release, PROBANTIA must complete:

- execution and recording of the offline custody and recovery procedure for
  the definitive Ed25519 key;
- the independent publication locations for the key fingerprint;
- final review of the runtime ZIP, corresponding DSS sources and notices
  listed in [THIRD_PARTY_INVENTORY.md](THIRD_PARTY_INVENTORY.md).

The release must include `LICENSE`, `NOTICE` and the original license and
attribution files reconciled with the SBOM before publication.
