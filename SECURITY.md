# Security model

The verifier treats every package as hostile input.

## Reporting a vulnerability

Do not disclose a suspected vulnerability through a public GitHub issue.
Send the report to `contact@easyconstat.com` with the subject
`[SECURITY] EasyConstat Evidence Verifier`. Include the affected version,
reproduction steps and security impact. Do not attach customer evidence or
production credentials.

## Required controls

- no extraction of package entries to disk;
- duplicate ZIP names are rejected;
- absolute paths, backslashes, parent traversal and control characters are
  rejected;
- entry count, package size, manifest size and expanded payload size are
  bounded;
- the ASiC `mimetype` entry must be first, stored and exact;
- payload names must match the restrictive V2 filename grammar;
- JSON duplicate keys, unknown properties and trailing tokens are rejected;
- artifact sets must match exactly; extra or missing payloads are invalid;
- all digests are recalculated with SHA-256;
- a cryptographically valid but untrusted signature is `INDETERMINATE`, never
  `VALID`;
- packaged certificates are never accepted as trust anchors merely because
  they are inside the package;
- the EU LOTL bootstrap store and its exact six certificate fingerprints are
  verified against Official Journal C/2026/1944 before each use;
- EU trusted lists are updated separately, published atomically only after
  strict signature and expiration checks, and reloaded with networking
  disabled during evidence verification;
- verification performs no upload and no EasyConstat API call.

## Synthetic qualification material

Cryptographic integration tests generate their own RSA keys, certificate
chain, timestamp authority, CRL and trust stores in a temporary test
directory. No fixture key is persisted, packaged in the verifier JAR or shared
with production. The synthetic trust anchor is accepted only when the test
passes it explicitly to the verifier.

One durable synthetic package and its trust store are retained as regression
fixtures. Their public test password is not a secret and neither store contains
a private key. A separate one-time RSA key signs their provenance statement;
only its public key is retained. The build verifies that signature and the
recorded SHA-256 values before validating the package.

## Out of scope for this tranche

- graphical desktop application;
- browser-only cryptographic validation;
- production package generation and delivery;
- definitive release-key custody and signed public release publication;
- long-term archive timestamp renewal.
