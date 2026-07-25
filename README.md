# Authorized Web and API Security Foundations Lab

An evidence-driven, fail-closed learning laboratory for developing the web and API security skills required before RAG, LLM, MCP, and agent security work.

## Current phase

**Phase 0 — Ethics, authorization, scope, and rules of engagement**

Testing is blocked until the local authorization record is complete and the authorization gate returns success. Repository contents are templates and educational material; they do not grant permission to test any system.

## Initial target

The planned first target is a privately deployed, self-controlled OWASP Juice Shop instance. The public OWASP demonstration instance, GitHub infrastructure, Codespaces infrastructure, third-party services, and all systems not explicitly recorded in the authorization record are excluded.

## Safety rules

- Test only a self-hosted instance that you own or are explicitly authorized to assess.
- Keep forwarded laboratory ports private.
- Use synthetic users and synthetic data only.
- Do not perform denial-of-service, social-engineering, persistence, destructive, or third-party testing.
- Never commit credentials, private URLs, signatures, personal data, tokens, cookies, or unsanitized evidence.
- Stop immediately if the target, authorization period, or environment differs from the approved record.

## Start here

1. Read [`SECURITY.md`](SECURITY.md).
2. Read [`docs/rules-of-engagement.md`](docs/rules-of-engagement.md).
3. Complete Question 1 in [`docs/phase-0/question-001-exact-target.md`](docs/phase-0/question-001-exact-target.md).
4. Copy `scope/authorization.example.json` to the ignored local file `scope/authorization.local.json`.
5. Replace every placeholder and obtain the required authorization evidence.
6. Run `python3 scripts/authorization_gate.py scope/authorization.local.json`.
7. Do not deploy or test the target unless the gate exits with status `0`.

A blocked or incomplete record exits with status `2`.

## Validation

```bash
python3 -m unittest discover -s tests -v
python3 scripts/authorization_gate.py scope/authorization.example.json --validate-only
```

## Repository structure

- `docs/phase-0/` — guided Phase 0 questions and completion criteria
- `scope/` — public templates; the completed local authorization record is ignored
- `scripts/` — fail-closed validation tooling
- `tests/` — regression tests for the authorization gate
- `evidence/` — sanitized evidence guidance and index template
- `findings/` — sanitized security-finding templates

## Status

`AUTHORIZATION_BLOCKED` — this is the correct initial state.