# EasyConstat Evidence Package V2

Status: development draft, not used in production.

## Container

The canonical package is an ETSI ASiC-E container with MIME type
`application/vnd.etsi.asic-e+zip` and extension `.asice`.

The first ZIP entry MUST be the uncompressed `mimetype` entry. The container
MUST contain exactly one CAdES signature in `META-INF/`, an ASiC manifest, the
`evidence-manifest.json` payload and every artifact listed by that JSON
manifest.

The CAdES signature MUST cover the JSON manifest and every evidence payload.
The target signature level is CAdES Baseline LT with at least one RFC 3161
signature timestamp. The qualified status of the timestamp is reported as a
property of the validation result; it is never inferred from a display label.

## Evidence manifest

`evidence-manifest.json` is itself a signed payload. Its bytes therefore do not
need to be canonicalised before verification. Parsers MUST reject duplicate
JSON keys, trailing data and unknown fields.

`createdAt` records package creation while `capturedAt` records the capture
instant represented by the evidence. Both are offset date-times. Neither value
is treated as trusted time merely because it appears in JSON: the cryptographic
time evidence remains the RFC 3161 signature timestamp inside the CAdES-LT
signature.

The manifest deliberately excludes the requester's email address and target
URL. Those data remain in the signed report and need not be duplicated.

Every non-metadata payload except `evidence-manifest.json` MUST appear exactly
once in `artifacts`. Every listed artifact MUST exist, have the declared byte
size and match the declared SHA-256 digest. Exactly one artifact MUST have the
`report` role and its path MUST equal `reportPath`.

## Verification result

- `VALID`: structure, payload hashes, CAdES signature, timestamp, LT profile
  and trust chain all pass the configured validation policy.
- `INVALID`: at least one deterministic integrity or cryptographic check
  fails.
- `INDETERMINATE`: integrity checks pass but trust or revocation status cannot
  be established with the available validation material and trust sources.

`VALID` means that the package has not changed since sealing and that the
signature and timestamp validate under the selected policy. It does not assert
that statements captured from a website are true or lawful, or that their
author has a particular identity.

## Compatibility strategy

During qualification, the existing client ZIP remains the only production
artifact. V2 packages are generated manually from synthetic fixtures. A later
shadow phase may generate V2 packages after the current ZIP and timestamp have
completed, without affecting credit consumption, delivery or recovery.
