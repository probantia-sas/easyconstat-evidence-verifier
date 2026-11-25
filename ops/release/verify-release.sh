#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 RELEASE_DIRECTORY TRUSTED_RELEASE_PUBLIC_KEY_PEM" >&2
    exit 64
fi

RELEASE_DIRECTORY="$(cd -- "$1" && pwd -P)"
TRUSTED_PUBLIC_KEY="$2"
MANIFEST="${RELEASE_DIRECTORY}/release-manifest.json"
SIGNATURE="${RELEASE_DIRECTORY}/release-manifest.json.sig"
BUNDLED_PUBLIC_KEY="${RELEASE_DIRECTORY}/release-signing-key.pem"

for command in openssl jq sha256sum awk stat realpath find sort comm mktemp cmp grep; do
    command -v "${command}" >/dev/null 2>&1 || {
        echo "Missing required command: ${command}" >&2
        exit 69
    }
done
[[ -f "${MANIFEST}" && -f "${SIGNATURE}" && -f "${TRUSTED_PUBLIC_KEY}" \
        && -f "${BUNDLED_PUBLIC_KEY}" ]] || {
    echo "Manifest, signature, bundled key or trusted public key is missing." >&2
    exit 66
}

TEMPORARY_DIRECTORY="$(mktemp -d)"
cleanup() {
    rm -rf -- "${TEMPORARY_DIRECTORY}"
}
trap cleanup EXIT

openssl pkey -pubin -in "${TRUSTED_PUBLIC_KEY}" -outform DER -out "${TEMPORARY_DIRECTORY}/trusted.der"
openssl pkey -pubin -in "${BUNDLED_PUBLIC_KEY}" -outform DER -out "${TEMPORARY_DIRECTORY}/bundled.der"
cmp -- "${TEMPORARY_DIRECTORY}/trusted.der" "${TEMPORARY_DIRECTORY}/bundled.der" >/dev/null || {
    echo "Bundled release key does not match the independently trusted public key." >&2
    exit 65
}
ACTUAL_FINGERPRINT="$(sha256sum "${TEMPORARY_DIRECTORY}/trusted.der" | awk '{print $1}')"
EXPECTED_FINGERPRINT="$(jq -er '.signingKeySha256' "${MANIFEST}")"
[[ "${ACTUAL_FINGERPRINT}" == "${EXPECTED_FINGERPRINT}" ]] || {
    echo "Trusted public-key fingerprint does not match the manifest." >&2
    exit 65
}

openssl pkeyutl -verify -rawin -pubin -inkey "${TRUSTED_PUBLIC_KEY}" -in "${MANIFEST}" \
    -sigfile "${SIGNATURE}" >/dev/null
jq -e '
    .format == "easyconstat-release-manifest" and
    .schemaVersion == 1 and
    .digestAlgorithm == "SHA-256" and
    .signatureAlgorithm == "Ed25519" and
    (.artifacts | type == "array" and length > 0)
' "${MANIFEST}" >/dev/null

printf '%s\n' 'release-manifest.json' 'release-manifest.json.sig' > "${TEMPORARY_DIRECTORY}/expected-files"
jq -c '.artifacts[]' "${MANIFEST}" > "${TEMPORARY_DIRECTORY}/artifacts.jsonl"
while IFS= read -r artifact; do
    path="$(printf '%s' "${artifact}" | jq -er '.path')"
    expected_size="$(printf '%s' "${artifact}" | jq -er '.size')"
    expected_sha256="$(printf '%s' "${artifact}" | jq -er '.sha256')"
    [[ "${path}" =~ ^[0-9A-Za-z][0-9A-Za-z._/-]*$ && "${path}" != *"//"* ]] || {
        echo "Unsafe artifact path in manifest: ${path}" >&2
        exit 65
    }
    IFS='/' read -r -a segments <<< "${path}"
    for segment in "${segments[@]}"; do
        [[ -n "${segment}" && "${segment}" != "." && "${segment}" != ".." ]] || {
            echo "Unsafe artifact path in manifest: ${path}" >&2
            exit 65
        }
    done
    candidate="${RELEASE_DIRECTORY}/${path}"
    [[ -f "${candidate}" && ! -L "${candidate}" ]] || {
        echo "Missing or non-regular release artifact: ${path}" >&2
        exit 66
    }
    resolved="$(realpath -- "${candidate}")"
    [[ "${resolved}" == "${RELEASE_DIRECTORY}/"* ]] || {
        echo "Release artifact escapes its directory: ${path}" >&2
        exit 65
    }
    actual_size="$(stat -c '%s' -- "${candidate}")"
    actual_sha256="$(sha256sum -- "${candidate}" | awk '{print $1}')"
    [[ "${actual_size}" == "${expected_size}" && "${actual_sha256}" == "${expected_sha256}" ]] || {
        echo "Release artifact integrity failure: ${path}" >&2
        exit 1
    }
    printf '%s\n' "${path}" >> "${TEMPORARY_DIRECTORY}/expected-files"
done < "${TEMPORARY_DIRECTORY}/artifacts.jsonl"

sort -u "${TEMPORARY_DIRECTORY}/expected-files" -o "${TEMPORARY_DIRECTORY}/expected-files"
if find "${RELEASE_DIRECTORY}" -type l -print -quit | grep -q .; then
    echo "Release directory contains a symbolic link." >&2
    exit 65
fi
(
    cd -- "${RELEASE_DIRECTORY}"
    find . -type f -printf '%P\n' | sort -u > "${TEMPORARY_DIRECTORY}/actual-files"
)
if ! comm -3 "${TEMPORARY_DIRECTORY}/expected-files" "${TEMPORARY_DIRECTORY}/actual-files" \
        > "${TEMPORARY_DIRECTORY}/file-differences"; then
    echo "Unable to compare the release inventory." >&2
    exit 1
fi
if [[ -s "${TEMPORARY_DIRECTORY}/file-differences" ]]; then
    echo "Release directory contains missing or unmanaged files:" >&2
    cat "${TEMPORARY_DIRECTORY}/file-differences" >&2
    exit 1
fi

(
    cd -- "${RELEASE_DIRECTORY}"
    sha256sum --check --strict SHA256SUMS >/dev/null
)

echo "status=verified"
echo "version=$(jq -er '.version' "${MANIFEST}")"
echo "artifacts=$(jq -er '.artifacts | length' "${MANIFEST}")"
echo "signing_key_sha256=${ACTUAL_FINGERPRINT}"
