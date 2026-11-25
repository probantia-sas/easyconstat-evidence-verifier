#!/usr/bin/env bash
set -euo pipefail

umask 077

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 NEW_KEY_DIRECTORY" >&2
    exit 64
fi

for command in openssl sha256sum awk mktemp mv chmod rm dirname basename; do
    command -v "${command}" >/dev/null 2>&1 || {
        echo "Missing required command: ${command}" >&2
        exit 69
    }
done

[[ -t 0 && -t 1 ]] || {
    echo "Release-key generation requires an interactive terminal." >&2
    exit 69
}

OUTPUT_DIRECTORY="$1"
OUTPUT_PARENT="$(cd -- "$(dirname -- "${OUTPUT_DIRECTORY}")" && pwd -P)"
OUTPUT_NAME="$(basename -- "${OUTPUT_DIRECTORY}")"
FINAL_DIRECTORY="${OUTPUT_PARENT}/${OUTPUT_NAME}"

[[ "${OUTPUT_NAME}" =~ ^[0-9A-Za-z][0-9A-Za-z._-]*$ ]] || {
    echo "Unsafe key-directory name: ${OUTPUT_NAME}" >&2
    exit 65
}
[[ ! -e "${FINAL_DIRECTORY}" ]] || {
    echo "Key directory already exists: ${FINAL_DIRECTORY}" >&2
    exit 73
}

printf '%s' 'Type GENERATE to create the definitive encrypted release key: ' >/dev/tty
IFS= read -r confirmation </dev/tty
[[ "${confirmation}" == "GENERATE" ]] || {
    echo "Release-key generation cancelled." >&2
    exit 1
}

STAGING_DIRECTORY="$(mktemp -d "${OUTPUT_PARENT}/.${OUTPUT_NAME}.tmp.XXXXXX")"
cleanup() {
    rm -rf -- "${STAGING_DIRECTORY}"
}
trap cleanup EXIT

PRIVATE_KEY="${STAGING_DIRECTORY}/easyconstat-release-private.pem"
PUBLIC_KEY="${STAGING_DIRECTORY}/easyconstat-release-public.pem"
FINGERPRINT_FILE="${STAGING_DIRECTORY}/easyconstat-release-key.sha256"

echo "OpenSSL will request and confirm the private-key passphrase." >&2
openssl genpkey -algorithm ED25519 -aes-256-cbc -out "${PRIVATE_KEY}"
echo "Enter the same passphrase once to derive the public key." >&2
openssl pkey -in "${PRIVATE_KEY}" -pubout -out "${PUBLIC_KEY}"

FINGERPRINT="$(openssl pkey -pubin -in "${PUBLIC_KEY}" -outform DER \
    | sha256sum | awk '{print $1}')"
printf '%s\n' "${FINGERPRINT}" > "${FINGERPRINT_FILE}"

chmod 0600 "${PRIVATE_KEY}"
chmod 0644 "${PUBLIC_KEY}" "${FINGERPRINT_FILE}"
mv -- "${STAGING_DIRECTORY}" "${FINAL_DIRECTORY}"
trap - EXIT

echo "status=generated"
echo "key_directory=${FINAL_DIRECTORY}"
echo "public_key=${FINAL_DIRECTORY}/easyconstat-release-public.pem"
echo "signing_key_sha256=${FINGERPRINT}"
echo "The private key remains encrypted and must stay outside production and CI."
