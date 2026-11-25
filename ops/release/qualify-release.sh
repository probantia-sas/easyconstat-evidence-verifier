#!/usr/bin/env bash
set -euo pipefail

umask 077

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 VERSION DSS_SOURCE_ZIP" >&2
    exit 64
fi
VERSION="$1"
PROJECT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
ARTIFACT_PREFIX="easyconstat-evidence-verifier-${VERSION}"
TEMPORARY_DIRECTORY="$(mktemp -d)"

cleanup() {
    rm -rf -- "${TEMPORARY_DIRECTORY}"
}
trap cleanup EXIT

for command in mvn openssl jq sha256sum cmp cp find script grep realpath; do
    command -v "${command}" >/dev/null 2>&1 || {
        echo "Missing qualification command: ${command}" >&2
        exit 69
    }
done
DSS_SOURCE="$(realpath -e -- "$2")"

artifact_paths() {
    printf '%s\n' \
        "target/${ARTIFACT_PREFIX}-all.jar" \
        "target/${ARTIFACT_PREFIX}-runtime.zip" \
        "target/${ARTIFACT_PREFIX}-sources.jar" \
        "target/${ARTIFACT_PREFIX}-test-sources.jar" \
        "target/${ARTIFACT_PREFIX}-source-release.zip" \
        "target/${ARTIFACT_PREFIX}-sbom.json"
}

cd -- "${PROJECT_DIRECTORY}"
mvn --batch-mode --no-transfer-progress clean verify
while IFS= read -r artifact; do
    [[ -f "${artifact}" ]] || {
        echo "Missing expected artifact after first build: ${artifact}" >&2
        exit 66
    }
    sha256sum -- "${artifact}"
done < <(artifact_paths) > "${TEMPORARY_DIRECTORY}/first-build.sha256"

mvn --batch-mode --no-transfer-progress clean verify
while IFS= read -r artifact; do
    [[ -f "${artifact}" ]] || {
        echo "Missing expected artifact after second build: ${artifact}" >&2
        exit 66
    }
    sha256sum -- "${artifact}"
done < <(artifact_paths) > "${TEMPORARY_DIRECTORY}/second-build.sha256"
cmp -- "${TEMPORARY_DIRECTORY}/first-build.sha256" "${TEMPORARY_DIRECTORY}/second-build.sha256" >/dev/null || {
    echo "Release artifacts are not reproducible." >&2
    diff -u "${TEMPORARY_DIRECTORY}/first-build.sha256" "${TEMPORARY_DIRECTORY}/second-build.sha256" >&2 || true
    exit 1
}

openssl genpkey -algorithm ED25519 -out "${TEMPORARY_DIRECTORY}/release-private.pem"
openssl pkey -in "${TEMPORARY_DIRECTORY}/release-private.pem" -pubout \
    -out "${TEMPORARY_DIRECTORY}/release-public.pem"
bash ops/release/prepare-release.sh \
    "${VERSION}" \
    "${TEMPORARY_DIRECTORY}/release" \
    "${TEMPORARY_DIRECTORY}/release-public.pem" \
    "${DSS_SOURCE}"
bash ops/release/sign-release.sh \
    "${TEMPORARY_DIRECTORY}/release" \
    "${TEMPORARY_DIRECTORY}/release-private.pem"
bash "${TEMPORARY_DIRECTORY}/release/tools/verify-release.sh" \
    "${TEMPORARY_DIRECTORY}/release" \
    "${TEMPORARY_DIRECTORY}/release-public.pem"

cp -R -- "${TEMPORARY_DIRECTORY}/release" "${TEMPORARY_DIRECTORY}/tampered-release"
printf 'tampered\n' >> "${TEMPORARY_DIRECTORY}/tampered-release/artifacts/${ARTIFACT_PREFIX}-runtime.zip"
if bash "${TEMPORARY_DIRECTORY}/tampered-release/tools/verify-release.sh" \
        "${TEMPORARY_DIRECTORY}/tampered-release" \
        "${TEMPORARY_DIRECTORY}/release-public.pem" >/dev/null 2>&1; then
    echo "Tampered release was incorrectly accepted." >&2
    exit 1
fi

printf 'incorrect DSS source\n' > "${TEMPORARY_DIRECTORY}/wrong-source.zip"
if bash ops/release/prepare-release.sh "${VERSION}" "${TEMPORARY_DIRECTORY}/wrong-source-release" \
        "${TEMPORARY_DIRECTORY}/release-public.pem" "${TEMPORARY_DIRECTORY}/wrong-source.zip" \
        >"${TEMPORARY_DIRECTORY}/wrong-source.log" 2>&1 ||
        [[ -e "${TEMPORARY_DIRECTORY}/wrong-source-release" ]] ||
        ! grep -Fq 'does not match the locked SHA-256' "${TEMPORARY_DIRECTORY}/wrong-source.log"; then
    echo "Mismatched DSS source was not rejected as expected." >&2
    exit 1
fi

if find "${TEMPORARY_DIRECTORY}/release" -type f \
        \( -name '*private*' -o -name '*.key' \) -print -quit | grep -q .; then
    echo "Private-key material leaked into the release directory." >&2
    exit 1
fi

ENCRYPTED_KEY_DIRECTORY="${TEMPORARY_DIRECTORY}/encrypted-release-key"
ENCRYPTED_RELEASE_DIRECTORY="${TEMPORARY_DIRECTORY}/encrypted-key-release"
TEST_PASSPHRASE="fixture-only-release-passphrase"
printf 'GENERATE\n%s\n%s\n%s\n' \
    "${TEST_PASSPHRASE}" "${TEST_PASSPHRASE}" "${TEST_PASSPHRASE}" \
    | script -q -e -c \
        "bash ops/release/generate-release-key.sh '${ENCRYPTED_KEY_DIRECTORY}'" \
        /dev/null >/dev/null
grep -q 'BEGIN ENCRYPTED PRIVATE KEY' \
    "${ENCRYPTED_KEY_DIRECTORY}/easyconstat-release-private.pem" || {
        echo "Generated release private key is not encrypted." >&2
        exit 1
    }
bash ops/release/prepare-release.sh \
    "${VERSION}" \
    "${ENCRYPTED_RELEASE_DIRECTORY}" \
    "${ENCRYPTED_KEY_DIRECTORY}/easyconstat-release-public.pem" \
    "${DSS_SOURCE}" >/dev/null
printf '%s\n' "${TEST_PASSPHRASE}" \
    | script -q -e -c \
        "bash ops/release/sign-release.sh '${ENCRYPTED_RELEASE_DIRECTORY}' '${ENCRYPTED_KEY_DIRECTORY}/easyconstat-release-private.pem'" \
        /dev/null >/dev/null
bash "${ENCRYPTED_RELEASE_DIRECTORY}/tools/verify-release.sh" \
    "${ENCRYPTED_RELEASE_DIRECTORY}" \
    "${ENCRYPTED_KEY_DIRECTORY}/easyconstat-release-public.pem" >/dev/null

echo "status=qualified"
echo "version=${VERSION}"
echo "reproducible_artifacts=6"
echo "tamper_detection=passed"
echo "dss_source_pin=passed"
echo "encrypted_release_key=passed"
cat "${TEMPORARY_DIRECTORY}/second-build.sha256"
