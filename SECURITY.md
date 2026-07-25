# Laboratory Security Policy

## Authorization boundary

This repository does not authorize testing. A test is permitted only when the tester has a complete, current, independently verifiable authorization record for the exact target and environment.

The authorization gate is fail-closed. Missing, expired, ambiguous, or placeholder data blocks testing.

## Permitted laboratory use

- A self-hosted, intentionally vulnerable application controlled by the tester
- Private laboratory ports
- Synthetic accounts and synthetic records
- Manual and automated techniques explicitly listed in the local authorization record
- Sanitized evidence that does not expose credentials, personal data, private URLs, or reusable attack material

## Prohibited use

- Public demonstration instances
- GitHub, GitHub Codespaces, cloud-provider, or network infrastructure
- Third-party services reached by the application
- Production systems or real organizational data
- Denial-of-service, destructive testing, persistence, social engineering, credential collection, or testing outside the approved time window

## Stop conditions

Stop immediately when:

- the observed target differs from the authorized target;
- a port becomes publicly accessible;
- real personal, confidential, or regulated data appears;
- a third-party service receives test traffic;
- the authorization period expires or is revoked;
- instability or unintended impact occurs; or
- evidence cannot be collected safely.

## Secrets and sensitive evidence

Never commit tokens, passwords, cookies, session identifiers, private URLs, signatures, personal data, raw traffic captures, or unsanitized request/response bodies. Store private authorization and raw evidence outside the public repository. Commit only sanitized derivatives and cryptographic hashes when disclosure is authorized.

## Reporting repository vulnerabilities

Do not publish an exploitable repository vulnerability in a public issue. Report it privately to the repository owner through an approved private channel.