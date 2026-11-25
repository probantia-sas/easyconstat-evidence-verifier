#!/usr/bin/env bash
set -euo pipefail

umask 077

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 RELEASE_DIRECTORY ED25519_PRIVATE_KEY_PEM" >&2
    exit 64
fi

RELEASE_DIRECTORY="$(cd -- "$1" && pwd -P)"
PRIVATE_KEY="$2"
MANIFEST="${RELEASE_DIRECTORY}/release-manifest.json"
PUBLIC_KEY="${RELEASE_DIRECTORY}/release-signing-key.pem"
SIGNATURE="${RELEASE_DIRECTORY}/release-manifest.json.sig"

for command in openssl jq sha256sum awk mktemp mv chmod rm; do
    command -v "${command}" >/dev/null 2>&1 || {
        echo "Missing required command: ${command}" >&2
        exit 69
    }
done
[[ -f "${MANIFEST}" && -f "${PUBLIC_KEY}" && -f "${PRIVATE_KEY}" ]] || {
    echo "Manifest, public key or private key is missing." >&2
    exit 66
}
[[ ! -e "${SIGNATURE}" ]] || {
    echo "Detached signature already exists: ${SIGNATURE}" >&2
    exit 73
}

TEMPORARY_DIRECTORY="$(mktemp -d)"
cleanup() {
    rm -rf -- "${TEMPORARY_DIRECTORY}"
}
trap cleanup EXIT

openssl pkey -pubin -in "${PUBLIC_KEY}" -outform DER -out "${TEMPORARY_DIRECTORY}/release-public.der"

EXPECTED_FINGERPRINT="$(jq -er '.signingKeySha256' "${MANIFEST}")"
ACTUAL_FINGERPRINT="$(sha256sum "${TEMPORARY_DIRECTORY}/release-public.der" | awk '{print $1}')"
[[ "${EXPECTED_FINGERPRINT}" == "${ACTUAL_FINGERPRINT}" ]] || {
    echo "Release public-key fingerprint does not match the signed manifest." >&2
    exit 65
}

openssl pkeyutl -sign -rawin -inkey "${PRIVATE_KEY}" -in "${MANIFEST}" \
    -out "${TEMPORARY_DIRECTORY}/release-manifest.json.sig"
openssl pkeyutl -verify -rawin -pubin -inkey "${PUBLIC_KEY}" -in "${MANIFEST}" \
    -sigfile "${TEMPORARY_DIRECTORY}/release-manifest.json.sig" >/dev/null || {
    echo "The signature does not match the public release key." >&2
    exit 65
}
chmod 0644 "${TEMPORARY_DIRECTORY}/release-manifest.json.sig"
mv -- "${TEMPORARY_DIRECTORY}/release-manifest.json.sig" "${SIGNATURE}"

echo "status=signed"
echo "signature=${SIGNATURE}"
echo "signing_key_sha256=${ACTUAL_FINGERPRINT}"
