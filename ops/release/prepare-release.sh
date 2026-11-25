#!/usr/bin/env bash
set -euo pipefail

umask 022

if [[ $# -ne 4 ]]; then
    echo "Usage: $0 VERSION OUTPUT_DIRECTORY RELEASE_PUBLIC_KEY_PEM DSS_SOURCE_ZIP" >&2
    exit 64
fi

VERSION="$1"
OUTPUT_DIRECTORY="$2"
PUBLIC_KEY="$3"
DSS_SOURCE="$4"
BUILD_TIMESTAMP="${EASYCONSTAT_RELEASE_TIMESTAMP:-2026-11-19T00:00:00Z}"
SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_DIRECTORY="$(cd -- "${SCRIPT_DIRECTORY}/../.." && pwd -P)"
ARTIFACT_PREFIX="easyconstat-evidence-verifier-${VERSION}"
TARGET_DIRECTORY="${PROJECT_DIRECTORY}/target"
VERIFIER_JAR="${TARGET_DIRECTORY}/${ARTIFACT_PREFIX}-all.jar"
RUNTIME_RELEASE="${TARGET_DIRECTORY}/${ARTIFACT_PREFIX}-runtime.zip"
SOURCE_JAR="${TARGET_DIRECTORY}/${ARTIFACT_PREFIX}-sources.jar"
TEST_SOURCE_JAR="${TARGET_DIRECTORY}/${ARTIFACT_PREFIX}-test-sources.jar"
SOURCE_RELEASE="${TARGET_DIRECTORY}/${ARTIFACT_PREFIX}-source-release.zip"
SBOM="${TARGET_DIRECTORY}/${ARTIFACT_PREFIX}-sbom.json"

for command in java openssl jq sha256sum find sort xargs awk cp mkdir mv; do
    command -v "${command}" >/dev/null 2>&1 || {
        echo "Missing required command: ${command}" >&2
        exit 69
    }
done

for file in "${VERIFIER_JAR}" "${RUNTIME_RELEASE}" "${SOURCE_JAR}" "${TEST_SOURCE_JAR}" "${SOURCE_RELEASE}" "${SBOM}" "${DSS_SOURCE}"; do
    [[ -f "${file}" && ! -L "${file}" ]] || {
        echo "Missing build artifact: ${file}" >&2
        exit 66
    }
done
[[ -f "${PUBLIC_KEY}" && ! -L "${PUBLIC_KEY}" ]] || {
    echo "Invalid release public key: ${PUBLIC_KEY}" >&2
    exit 66
}
openssl pkey -pubin -in "${PUBLIC_KEY}" -noout >/dev/null

read -r DSS_SOURCE_SHA256 DSS_SOURCE_NAME < "${SCRIPT_DIRECTORY}/dss-source.sha256"
[[ "${DSS_SOURCE_SHA256}" =~ ^[0-9a-f]{64}$ && "${DSS_SOURCE_NAME}" =~ ^dss-([0-9]+[.][0-9]+[.][0-9]+)-source[.]zip$ ]] || {
    echo "Invalid DSS source lock." >&2
    exit 65
}
DSS_VERSION="${BASH_REMATCH[1]}"

OUTPUT_PARENT="$(cd -- "$(dirname -- "${OUTPUT_DIRECTORY}")" && pwd -P)"
OUTPUT_NAME="$(basename -- "${OUTPUT_DIRECTORY}")"
FINAL_DIRECTORY="${OUTPUT_PARENT}/${OUTPUT_NAME}"
[[ ! -e "${FINAL_DIRECTORY}" ]] || {
    echo "Release directory already exists: ${FINAL_DIRECTORY}" >&2
    exit 73
}

STAGING_DIRECTORY="$(mktemp -d "${OUTPUT_PARENT}/.${OUTPUT_NAME}.tmp.XXXXXX")"
cleanup() {
    rm -rf -- "${STAGING_DIRECTORY}"
}
trap cleanup EXIT

mkdir -p "${STAGING_DIRECTORY}/artifacts" "${STAGING_DIRECTORY}/documentation" "${STAGING_DIRECTORY}/tools"
cp -- "${RUNTIME_RELEASE}" "${SOURCE_JAR}" "${TEST_SOURCE_JAR}" "${SOURCE_RELEASE}" "${SBOM}" \
    "${STAGING_DIRECTORY}/artifacts/"
cp -- "${DSS_SOURCE}" "${STAGING_DIRECTORY}/artifacts/${DSS_SOURCE_NAME}"
(
    cd -- "${STAGING_DIRECTORY}/artifacts"
    printf '%s  %s\n' "${DSS_SOURCE_SHA256}" "${DSS_SOURCE_NAME}" | sha256sum --check --strict --status
) || {
    echo "The DSS source archive does not match the locked SHA-256." >&2
    exit 65
}
jq -e --arg version "${VERSION}" --arg dss "${DSS_VERSION}" '
    .metadata.component.version == $version and
    ([.components[] | select(.group == "eu.europa.ec.joinup.sd-dss") | .version] | unique) == [$dss]
' "${STAGING_DIRECTORY}/artifacts/${ARTIFACT_PREFIX}-sbom.json" >/dev/null || {
    echo "The SBOM does not match the release version and locked DSS source version." >&2
    exit 65
}
cp -- "${PROJECT_DIRECTORY}/README.md" "${PROJECT_DIRECTORY}/SECURITY.md" \
    "${PROJECT_DIRECTORY}/SPECIFICATION.md" "${PROJECT_DIRECTORY}/LICENSE" \
    "${PROJECT_DIRECTORY}/NOTICE" "${PROJECT_DIRECTORY}/CONTRIBUTING.md" \
    "${STAGING_DIRECTORY}/documentation/"
cp -R -- "${PROJECT_DIRECTORY}/docs/." "${STAGING_DIRECTORY}/documentation/"
cp -- "${SCRIPT_DIRECTORY}/verify-release.sh" "${STAGING_DIRECTORY}/tools/verify-release.sh"
cp -- "${PUBLIC_KEY}" "${STAGING_DIRECTORY}/release-signing-key.pem"
chmod 0755 "${STAGING_DIRECTORY}/tools/verify-release.sh"
chmod 0644 "${STAGING_DIRECTORY}/release-signing-key.pem"

(
    cd -- "${STAGING_DIRECTORY}"
    find . -type f ! -name 'SHA256SUMS' ! -name 'release-manifest.json' ! -name 'release-manifest.json.sig' -print0 \
        | sort -z \
        | xargs -0 sha256sum > SHA256SUMS
)

SIGNING_KEY_SHA256="$(openssl pkey -pubin -in "${PUBLIC_KEY}" -outform DER | sha256sum | awk '{print $1}')"
MANIFEST_ARGUMENTS=(
    --base-dir "${STAGING_DIRECTORY}"
    --output "${STAGING_DIRECTORY}/release-manifest.json"
    --version "${VERSION}"
    --build-timestamp "${BUILD_TIMESTAMP}"
    --signing-key-sha256 "${SIGNING_KEY_SHA256}"
)
while IFS= read -r -d '' path; do
    relative="${path#${STAGING_DIRECTORY}/}"
    case "${relative}" in
        artifacts/*-runtime.zip) role="executable" ;;
        artifacts/*-sources.jar|artifacts/*-test-sources.jar|artifacts/*-source-release.zip|artifacts/"${DSS_SOURCE_NAME}") role="source" ;;
        artifacts/*-sbom.json) role="sbom" ;;
        documentation/*) role="documentation" ;;
        tools/*) role="verification-tool" ;;
        release-signing-key.pem) role="release-public-key" ;;
        SHA256SUMS) role="checksums" ;;
        *) echo "Unexpected release artifact: ${relative}" >&2; exit 65 ;;
    esac
    MANIFEST_ARGUMENTS+=(--artifact "${role}=${relative}")
done < <(find "${STAGING_DIRECTORY}" -type f ! -name 'release-manifest.json' ! -name 'release-manifest.json.sig' -print0 | sort -z)

java -cp "${VERIFIER_JAR}" com.probantia.easyconstat.release.ReleaseManifestMain "${MANIFEST_ARGUMENTS[@]}"
mv -- "${STAGING_DIRECTORY}" "${FINAL_DIRECTORY}"
trap - EXIT

echo "status=prepared_unsigned"
echo "release_directory=${FINAL_DIRECTORY}"
echo "signing_key_sha256=${SIGNING_KEY_SHA256}"
