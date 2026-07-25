# Question 001 — What exact system is the authorized target?

Status: **INCOMPLETE — TESTING BLOCKED**

## Purpose

Establish one unambiguous test target before deployment, enumeration, scanning, exploitation, or other security testing.

## Required answer

Complete the private `scope/authorization.local.json` record with all of the following:

1. Target identifier
2. Application name
3. Exact released version
4. Upstream repository
5. Exact source tag or commit SHA
6. Deployment artifact or container image
7. Artifact or image SHA-256 digest
8. Personally controlled environment identifier
9. Private base URL or endpoint identifier
10. Authorized interfaces and ports
11. Target owner
12. Authorizing person
13. Evidence that the authorizer controls the target
14. Authorization start and end timestamps in UTC
15. Permitted techniques
16. Explicit exclusions
17. Synthetic-data requirement
18. Private-port requirement
19. Stop conditions
20. Cleanup obligations
21. Authorization evidence reference

## Proposed target class

A privately deployed, self-controlled OWASP Juice Shop instance pinned to an exact released version and artifact digest.

This proposal is not authorization. The target does not become authorized until the completed local record is verified and the authorization gate exits with status `0`.

## Mandatory exclusions

- Public OWASP demonstration instances
- GitHub and Codespaces infrastructure
- Cloud-provider infrastructure
- Third-party services
- Production systems
- Any unlisted host, port, account, API, dependency, or environment

## Completion evidence

- Completed private authorization record
- Reproducible version and digest evidence
- Ownership or control evidence
- Approved rules of engagement
- Successful authorization-gate output
- Sanitized evidence-index entry containing no secret or private endpoint

## Mastery check

Explain, without reading the template:

- why repository ownership alone does not authorize testing infrastructure;
- why a version without a digest may be ambiguous;
- why public demonstrations remain excluded; and
- which changes invalidate the authorization record.

## Gate

```bash
python3 scripts/authorization_gate.py scope/authorization.local.json
```

Exit `0`: authorized record accepted.

Exit `2`: incomplete, invalid, expired, unsafe, or blocked; do not test.