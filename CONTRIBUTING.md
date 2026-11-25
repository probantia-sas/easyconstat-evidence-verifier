# Contributing

Contributions that improve verification correctness, interoperability,
documentation or hostile-input handling are welcome.

## Before opening a pull request

1. Do not include customer evidence, production identifiers, credentials,
   private keys or EasyConstat infrastructure configuration.
2. Add or update tests for every behavioural change.
3. Run `mvn clean verify` with JDK 17 and Maven 3.9 or later.
4. Keep machine-readable result codes stable unless the public specification
   is deliberately versioned.
5. Explain security and compatibility consequences in the pull request.

Contributions submitted to this repository are licensed under Apache License
2.0, as stated in `LICENSE`.

Security vulnerabilities must be reported privately as described in
`SECURITY.md`, not through a public issue.
