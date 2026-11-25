# Definitive release-key custody

The EasyConstat Evidence Verifier release manifest is signed with a dedicated
Ed25519 key. This key authenticates public verifier releases; it is unrelated
to the electronic seal and timestamping credentials used for evidence
packages.

## Generation

Generate the definitive key only on a trusted workstation that is disconnected
from production systems and not used as a GitHub Actions runner. Use a fully
patched operating system, full-disk encryption and an encrypted removable
medium.

From a clean checkout, run:

```text
bash ops/release/generate-release-key.sh /media/ENCRYPTED/release-key-2026
```

The command is interactive. It requires an explicit confirmation and asks
OpenSSL for a passphrase. It creates:

- `easyconstat-release-private.pem`, encrypted with AES-256;
- `easyconstat-release-public.pem`, safe to publish;
- `easyconstat-release-key.sha256`, the SHA-256 fingerprint of the public
  SubjectPublicKeyInfo in DER form.

The private key and passphrase must never be copied to the Git repository,
EasyConstat production server, capture node, CI runner, support archive or
customer package.

## Copies and separation

Maintain two encrypted copies of the private key on separate removable media
stored in distinct controlled locations. Keep the passphrase in a managed
password vault or sealed recovery record that is not stored with either key
copy. Record the holders, storage locations, creation date and public-key
fingerprint in PROBANTIA's internal security register.

Before publication, perform a recovery exercise from the secondary copy on a
separate trusted workstation. The exercise must sign and verify a disposable
manifest without exposing or replacing the definitive key.

## Release signing ceremony

1. Build and qualify the release from a protected `main` commit.
2. Transfer the unsigned release directory to the offline signing workstation.
3. Verify its source commit and expected artifact hashes.
4. Unlock the encrypted key interactively and run `sign-release.sh`.
5. Run `verify-release.sh` with an independently obtained copy of the public
   key.
6. Transfer only the signed release directory back to the publishing system.
7. Record the version, Git commit, manifest hash, public-key fingerprint,
   operator and date in the release register.

`sign-release.sh` passes the encrypted key directly to OpenSSL. The key is
unlocked once in memory; no decrypted private key is written to disk.
Only a signature that verifies with the recorded public key is retained.

## Independent publication

Publish the public key and exact fingerprint through at least two independently
authenticated channels:

- this GitHub repository and its signed release package;
- an HTTPS page under `easyconstat.com` controlled outside GitHub.

The key bundled with a release is not sufficient on its own because an
attacker able to replace the release could otherwise replace that key too.

## Rotation or compromise

Planned rotation requires an overlap notice signed by the previous key and
publication of the new fingerprint through both authenticated channels. If
the private key or passphrase may be compromised, stop releases immediately,
publish a security advisory, revoke trust in the affected fingerprint and
generate a new key under a documented incident procedure. Previously signed
releases remain identifiable by their recorded key fingerprint and release
register entry.
