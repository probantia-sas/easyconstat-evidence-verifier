# Durable synthetic qualification fixture

These files are exclusively non-production test material.

- `easyconstat-synthetic-valid.asice` is a synthetic ASiC-E/CAdES-B-LT
  package containing no customer data.
- `easyconstat-synthetic-trust.jks` contains only the synthetic test root.
  Its password is the public test value `fixture-only`.
- `fixture-provenance.json` binds both files by SHA-256.
- `fixture-provenance.sig` authenticates the exact provenance bytes with the
  public key in `fixture-provenance-public-key.pem`.

The private provenance key is discarded after export. None of these files can
sign or validate an EasyConstat production package.
