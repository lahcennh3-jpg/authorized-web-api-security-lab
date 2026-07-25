# Agent Instructions

## Scope

Work on one verified phase at a time. The current phase is Phase 0: ethics, authorization, scope, and rules of engagement.

## Mandatory safety behavior

- Treat `scope/authorization.local.json` as the only local execution authorization record.
- Never interpret examples, templates, repository ownership, challenge documentation, or public deployment as authorization.
- Do not provide or execute target-testing commands until the authorization gate returns exit status `0`.
- Never test public demos, GitHub infrastructure, Codespaces infrastructure, cloud-provider infrastructure, or third-party systems.
- Use synthetic data and private ports only.
- Never commit private authorization records, secrets, real identities, private URLs, session data, or raw evidence.
- Stop if target identity, ownership, dates, scope, or exclusions are incomplete or inconsistent.

## Working cycle

Scope → build/configure → understand → threat-model → test → collect sanitized evidence → remediate → retest → detect → document → verify mastery.

## Change requirements

Every material change must include:

- a clear purpose;
- relevant automated validation where feasible;
- updated documentation;
- no weakened safety gate; and
- no claim of completed testing without corresponding sanitized evidence.

## Phase advancement

Do not advance beyond Phase 0 until:

1. the exact self-hosted target is identified;
2. ownership and authority are verified;
3. permitted and prohibited actions are recorded;
4. dates and stop conditions are valid;
5. private-port and synthetic-data requirements are accepted; and
6. the authorization gate exits successfully.