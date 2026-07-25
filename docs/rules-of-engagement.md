# Rules of Engagement

Status: **DRAFT — NOT AUTHORIZATION**

Complete this document together with the private local authorization record before testing.

## Objective

Develop and demonstrate authorized web and API security engineering skills against one isolated, self-hosted OWASP Juice Shop instance.

## Included target

Only the exact application instance, version, artifact digest, environment identifier, and private base URL recorded in `scope/authorization.local.json`.

## Default exclusions

- OWASP public demonstration instances
- GitHub and GitHub Codespaces control-plane infrastructure
- Cloud-provider infrastructure
- Package registries and software-update services
- Email, payment, mapping, analytics, webhook, identity, or other third-party services
- Any host, domain, port, API, account, role, or dependency not explicitly included

## Permitted techniques

Record an explicit allowlist in the private authorization record. No technique is permitted by default.

Potential laboratory techniques may include, when explicitly approved:

- browser and HTTP request inspection;
- authentication, session, and access-control verification;
- input-validation and injection testing;
- API inventory and authorization testing;
- safe file-handling and business-logic tests;
- logging, remediation, and regression verification.

## Prohibited techniques

- denial-of-service or resource-exhaustion testing;
- destructive data modification;
- persistence or backdoors;
- social engineering;
- credential theft or collection;
- malware deployment;
- public exposure of the laboratory;
- traffic to third-party systems;
- scanning or testing outside the exact target.

## Operating limits

The private record must define:

- start and end timestamps in UTC;
- maximum request rate and concurrency;
- approved accounts and roles;
- approved tools and payload classes;
- evidence-handling rules;
- emergency contact and stop procedure;
- cleanup and final verification.

## Evidence rules

Use synthetic identifiers. Sanitize requests, responses, screenshots, logs, and reports before committing them. Store sensitive originals outside this repository. Record hashes only when retention and publication are authorized.

## Closure

Testing closes only after accounts, uploaded files, temporary credentials, forwarded ports, processes, and retained evidence have been reviewed and cleaned up.