# EasyConstat Evidence Verifier

Unpack this ZIP into a new directory and keep the `lib/` directory beside
`verifier.jar`. With Java 17 or newer:

```text
java -jar verifier.jar --lang fr evidence.asice
java -jar verifier.jar --lang en evidence.asice
```

Use `--json` for structured output. Verification is local; evidence files
are not uploaded. A result can be indeterminate if no trusted validation
source is available. See the project's README for setting up a trust bundle.

## Licenses and replacement of DSS

`LICENSE` and `NOTICE` cover the verifier. Third-party libraries retain their
own licenses. See `THIRD_PARTY_INVENTORY.md` and `licenses/`, including the
DSS LGPL 2.1 text. The signed release also distributes the corresponding DSS
source ZIP alongside this runtime ZIP.

Each original runtime library is a separate JAR. To use a modified,
interface-compatible DSS build, in an extracted copy replace the relevant
JARs in `lib/` using the filenames listed in `verifier.jar`'s manifest.
Rebuilding the EasyConstat verifier is not required. Verify the publisher's
signature on the original release before making local replacements; that
signature does not endorse modified libraries.
