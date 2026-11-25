# Third-party dependency inventory

This inventory covers the 58 runtime dependencies in the 0.1.0-SNAPSHOT
CycloneDX SBOM, excluding test dependencies. Each original Maven JAR was
matched to its SHA-256 in the SBOM. File paths refer to files in the original
JARs, not the all-in-one JAR. License labels are the SBOM declarations
except that the exact DSS license version was checked upstream.
This is an inventory, not the binary distribution's legal notices.

## Binary release gate

The shaded JAR is for internal qualification only. Maven Shade collapses
identically named NOTICE and LICENSE resources across dependencies. The
project LICENSE, project NOTICE and SBOM do not replace the original notices
or the licensing terms for the embedded code.

DSS 6.5.1 has 34 modules in this build. Their JARs do not include a standalone
license file, so the distribution must retrieve it from the
[exact upstream release](https://github.com/esig/dss/releases/tag/6.5.1)
and retain the [upstream license](https://github.com/esig/dss/blob/98ab6c136fc90bfca78352b4e673e2eae72b7d5a/LICENSE).
The expected SHA-256 of that license file is
`dc626520dcd53a22f727af3ee42c770e56c97a64fe3adb063799d8ab032fe551`.
Review sections 4 and 6 of the
[LGPL 2.1](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.en.html)
for the chosen distribution format.

The runtime ZIP uses a verifier JAR with separate, replaceable dependency
JARs. The build checks the exact bytes of each bundled library against the
SBOM and verifies its original license and attribution files. Release
preparation includes the matching DSS source ZIP as a signed artifact, not
just an upstream link. See [SIGNED_RELEASES.md](SIGNED_RELEASES.md).

Reconcile this inventory with the new SBOM whenever dependencies change.
Do not infer license compliance from a green build.

## Runtime components

| Maven coordinates | Declared license | License and attribution files |
| --- | --- | --- |
| `com.fasterxml.jackson.core:jackson-annotations:2.20` | Apache-2.0 | `META-INF/LICENSE`, `META-INF/NOTICE` |
| `com.fasterxml.jackson.core:jackson-core:2.20.1` | Apache-2.0 | `META-INF/LICENSE`, `META-INF/NOTICE` |
| `com.fasterxml.jackson.core:jackson-databind:2.20.1` | Apache-2.0 | `META-INF/LICENSE`, `META-INF/NOTICE` |
| `com.fasterxml.woodstox:woodstox-core:6.5.1` | Apache-2.0 | `META-INF/LICENSE` |
| `com.sun.activation:jakarta.activation:2.0.1` | BSD-3-Clause | `META-INF/LICENSE.md`, `META-INF/NOTICE.md` |
| `com.sun.istack:istack-commons-runtime:4.0.1` | BSD-3-Clause | `META-INF/LICENSE.md`, `META-INF/NOTICE.md` |
| `commons-codec:commons-codec:1.18.0` | Apache-2.0 | `META-INF/LICENSE.txt`, `META-INF/NOTICE.txt` |
| `commons-io:commons-io:2.22.0` | Apache-2.0 | `META-INF/LICENSE.txt`, `META-INF/NOTICE.txt` |
| `eu.europa.ec.joinup.sd-dss:dss-alert:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:dss-asic-cades:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:dss-asic-common:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:dss-cades:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:dss-cms:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:dss-cms-object:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:dss-crl-parser:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:dss-crl-parser-stream:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:dss-detailed-report-jaxb:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:dss-diagnostic-jaxb:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:dss-document:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:dss-enumerations:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:dss-i18n:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:dss-jaxb-common:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:dss-jaxb-parsers:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:dss-model:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:dss-policy-jaxb:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:dss-service:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:dss-simple-certificate-report-jaxb:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:dss-simple-report-jaxb:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:dss-spi:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:dss-tsl-validation:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:dss-utils:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:dss-utils-apache-commons:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:dss-validation:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:dss-validation-job:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:dss-xades:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:dss-xml-common:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:dss-xml-utils:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:specs-trusted-list:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:specs-trusted-list-v211:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:specs-validation-report:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:specs-xades:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `eu.europa.ec.joinup.sd-dss:specs-xmldsig:6.5.1` | LGPL 2.1 (upstream) | Upstream DSS license |
| `jakarta.xml.bind:jakarta.xml.bind-api:3.0.1` | BSD-3-Clause | `META-INF/LICENSE.md`, `META-INF/NOTICE.md` |
| `org.apache.commons:commons-collections4:4.6.0` | Apache-2.0 | `META-INF/LICENSE.txt`, `META-INF/NOTICE.txt` |
| `org.apache.commons:commons-lang3:3.21.0` | Apache-2.0 | `META-INF/LICENSE.txt`, `META-INF/NOTICE.txt` |
| `org.apache.httpcomponents.client5:httpclient5:5.6.5` | Apache-2.0 | `META-INF/LICENSE`, `META-INF/NOTICE` |
| `org.apache.httpcomponents.core5:httpcore5:5.4.4` | Apache-2.0 | `META-INF/LICENSE`, `META-INF/NOTICE` |
| `org.apache.httpcomponents.core5:httpcore5-h2:5.4.4` | Apache-2.0 | `META-INF/LICENSE`, `META-INF/NOTICE` |
| `org.apache.santuario:xmlsec:3.0.6` | Apache-2.0 | `META-INF/LICENSE`, `META-INF/NOTICE` |
| `org.bouncycastle:bcpkix-jdk18on:1.86` | Bouncy Castle Licence | `META-INF/LICENSE.md` |
| `org.bouncycastle:bcprov-jdk18on:1.86` | Bouncy Castle Licence | `META-INF/LICENSE.md` |
| `org.bouncycastle:bcutil-jdk18on:1.86` | Bouncy Castle Licence | `META-INF/LICENSE.md` |
| `org.codehaus.woodstox:stax2-api:4.2.1` | BSD-4-Clause | `META-INF/LICENSE` |
| `org.glassfish.jaxb:jaxb-core:3.0.2` | BSD-3-Clause | `META-INF/LICENSE.md`, `META-INF/NOTICE.md` |
| `org.glassfish.jaxb:jaxb-runtime:3.0.2` | BSD-3-Clause | `META-INF/LICENSE.md`, `META-INF/NOTICE.md` |
| `org.glassfish.jaxb:txw2:3.0.2` | BSD-3-Clause | `META-INF/LICENSE.md`, `META-INF/NOTICE.md` |
| `org.slf4j:slf4j-api:2.0.20` | MIT | `META-INF/LICENSE.txt` |
| `org.slf4j:slf4j-simple:2.0.20` | MIT | `META-INF/LICENSE.txt` |
