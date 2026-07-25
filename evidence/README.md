# Evidence Handling

Commit only sanitized evidence that is necessary to demonstrate authorized work.

## Never commit

- private laboratory URLs;
- credentials, tokens, cookies, or session identifiers;
- signatures or identity documents;
- personal, confidential, regulated, or third-party data;
- raw HAR, packet-capture, database, or log exports;
- unsanitized request or response bodies; or
- evidence whose retention or publication is not authorized.

The `.gitignore` excludes common raw-evidence locations and formats, but ignore rules are not a substitute for manual review.

## Required metadata

Every sanitized artifact should record:

- evidence ID;
- associated question, requirement, test, or finding;
- UTC timestamp;
- target identifier and pinned version, without private endpoint details;
- collection method and tool version;
- command or action, when safe to publish;
- exit status or observed result;
- sanitization performed;
- SHA-256 digest;
- reviewer and verification status; and
- cleanup or retention decision.

Use `evidence/index.md` as the public evidence register. Store sensitive originals outside this repository in an access-controlled location.