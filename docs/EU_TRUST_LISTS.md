# Authenticated EU trusted-list bundle

The public verifier must not download trust material while a user verifies an
evidence package. Network availability, a transient remote failure or a newly
published list must never change a verification halfway through.

EasyConstat therefore separates two operations:

1. a maintenance command downloads and authenticates the EU LOTL and every
   referenced national trusted list;
2. the verifier reloads the last published bundle from disk with networking
   disabled and validates the cached signatures again.

## Bootstrap provenance

The embedded public PKCS12 store comes from the official DSS Demonstrations
6.5.1 source tree. It contains no private key. Before every use, the verifier
checks:

- the store SHA-256:
  `98a76fbcd726e3553ecdf8dec59eef1b015b0579e7514d8c26f7c6124ce382e6`;
- the exact set of six certificate SHA-256 fingerprints published in Official
  Journal C/2026/1944;
- the deterministic Official Journal URI
  `https://eur-lex.europa.eu/eli/C/2026/1944/oj`.

The provenance is also recorded in
`src/main/resources/eu-lotl-oj-2026-1944.json`.

## Online maintenance command

Run these examples from the extracted runtime ZIP, with `lib/` beside
`verifier.jar`. Use a writable location for the bundle.

```text
java -cp verifier.jar \
  com.probantia.easyconstat.verify.EuTrustListUpdaterMain \
  --lang fr --bundle ./eu-trust
```

The updater uses DSS 6.5.1, accepts only Trusted List versions 5 and 6, enables
the LOTL pivot mechanism and rejects expired or incorrectly signed LOTLs and
TLs. It writes a new immutable release under `releases/` and changes `current`
only after the complete set has passed validation. A failed update leaves the
previous current release untouched. Concurrent updates are rejected by an
exclusive lock.

## Offline verification command

```text
java -jar verifier.jar \
  --lang fr \
  --eu-trust-bundle ./eu-trust \
  evidence.asice
```

The offline loader uses DSS `IgnoreDataLoader`; it cannot retrieve a missing
or changed list from the network. It revalidates the cached LOTL and TL
signatures before exposing their trust anchors to signature validation.

## Controlled trial on 2026-11-21

An isolated online refresh authenticated:

- 1 European LOTL;
- 31 national trusted lists;
- 4,702 trusted entity keys.

The resulting release was loaded offline. A synthetic signer absent from the
EU lists produced `INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND`, not `VALID`.
After a copy of the cached LOTL was altered, the bundle was rejected with
`EU_TRUST_BUNDLE_INVALID`.

This trial did not read or modify an EasyConstat production archive, queue,
database, credit, signing key or customer workflow.
