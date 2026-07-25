#!/usr/bin/env python3
"""Fail-closed authorization gate for the local security laboratory.

The gate validates metadata only. It never grants legal authorization and never
prints sensitive field values.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

EXIT_OK = 0
EXIT_BLOCKED = 2
PLACEHOLDER_MARKERS = ("REPLACE_ME", "TODO", "TBD", "CHANGEME")
SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
PUBLIC_DEMO_HOSTS = {"demo.owasp-juice.shop", "preview.owasp-juice.shop"}

TARGET_STRING_FIELDS = (
    "target_id",
    "application_name",
    "version",
    "source_repository",
    "source_ref",
    "artifact_reference",
    "artifact_sha256",
    "environment_id",
    "private_base_url",
)
AUTH_STRING_FIELDS = (
    "target_owner",
    "authorized_by",
    "authority_basis",
    "evidence_reference",
    "start_utc",
    "end_utc",
)
AUTH_LIST_FIELDS = (
    "permitted_techniques",
    "approved_tools",
    "explicit_exclusions",
    "stop_conditions",
    "cleanup_obligations",
)
REQUIRED_SAFEGUARDS = (
    "self_hosted_target_only",
    "private_ports_only",
    "synthetic_data_only",
    "public_demo_excluded",
    "third_party_systems_excluded",
    "denial_of_service_prohibited",
    "destructive_testing_prohibited",
    "social_engineering_prohibited",
    "secrets_must_not_be_committed",
)
REQUIRED_ATTESTATIONS = (
    "record_complete",
    "ownership_verified",
    "authorization_verified",
    "rules_of_engagement_approved",
)


def _is_placeholder(value: str) -> bool:
    normalized = value.strip().upper()
    return not normalized or any(marker in normalized for marker in PLACEHOLDER_MARKERS)


def _require_mapping(record: dict[str, Any], name: str, errors: list[str]) -> dict[str, Any]:
    value = record.get(name)
    if not isinstance(value, dict):
        errors.append(f"{name} must be an object")
        return {}
    return value


def _check_string_fields(
    section: dict[str, Any],
    section_name: str,
    fields: tuple[str, ...],
    errors: list[str],
    *,
    reject_placeholders: bool,
) -> None:
    for field in fields:
        value = section.get(field)
        if not isinstance(value, str):
            errors.append(f"{section_name}.{field} must be a string")
        elif reject_placeholders and _is_placeholder(value):
            errors.append(f"{section_name}.{field} is incomplete")


def _check_list_fields(
    section: dict[str, Any],
    section_name: str,
    fields: tuple[str, ...],
    errors: list[str],
    *,
    reject_placeholders: bool,
) -> None:
    for field in fields:
        value = section.get(field)
        if not isinstance(value, list):
            errors.append(f"{section_name}.{field} must be an array")
            continue
        if reject_placeholders and (
            not value
            or any(not isinstance(item, str) or _is_placeholder(item) for item in value)
        ):
            errors.append(f"{section_name}.{field} is incomplete")


def validate_schema(record: Any) -> list[str]:
    """Validate structure and non-negotiable safety invariants."""
    errors: list[str] = []
    if not isinstance(record, dict):
        return ["record must be a JSON object"]

    if record.get("schema_version") != "1.0":
        errors.append("schema_version must be 1.0")
    if not isinstance(record.get("project_id"), str):
        errors.append("project_id must be a string")
    if record.get("status") not in {"BLOCKED", "AUTHORIZED"}:
        errors.append("status must be BLOCKED or AUTHORIZED")

    target = _require_mapping(record, "target", errors)
    authorization = _require_mapping(record, "authorization", errors)
    safeguards = _require_mapping(record, "safeguards", errors)
    attestations = _require_mapping(record, "attestations", errors)

    _check_string_fields(
        target, "target", TARGET_STRING_FIELDS, errors, reject_placeholders=False
    )
    _check_list_fields(
        target,
        "target",
        ("authorized_interfaces",),
        errors,
        reject_placeholders=False,
    )
    _check_string_fields(
        authorization,
        "authorization",
        AUTH_STRING_FIELDS,
        errors,
        reject_placeholders=False,
    )
    _check_list_fields(
        authorization,
        "authorization",
        AUTH_LIST_FIELDS,
        errors,
        reject_placeholders=False,
    )

    for field in REQUIRED_SAFEGUARDS:
        if safeguards.get(field) is not True:
            errors.append(f"safeguards.{field} must be true")
    for field in REQUIRED_ATTESTATIONS:
        if not isinstance(attestations.get(field), bool):
            errors.append(f"attestations.{field} must be boolean")

    return errors


def _parse_utc(value: str, field: str, errors: list[str]) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"authorization.{field} must be an ISO-8601 timestamp")
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        errors.append(f"authorization.{field} must include a UTC offset")
        return None
    return parsed.astimezone(timezone.utc)


def validate_authorization(
    record: Any, *, now: datetime | None = None
) -> list[str]:
    """Validate a complete and currently active authorization record."""
    errors = validate_schema(record)
    if not isinstance(record, dict):
        return errors

    target = record.get("target", {})
    authorization = record.get("authorization", {})
    attestations = record.get("attestations", {})

    if record.get("status") != "AUTHORIZED":
        errors.append("status is not AUTHORIZED")

    if isinstance(target, dict):
        _check_string_fields(
            target, "target", TARGET_STRING_FIELDS, errors, reject_placeholders=True
        )
        _check_list_fields(
            target,
            "target",
            ("authorized_interfaces",),
            errors,
            reject_placeholders=True,
        )

        digest = target.get("artifact_sha256")
        if isinstance(digest, str) and not _is_placeholder(digest):
            if not SHA256_PATTERN.fullmatch(digest):
                errors.append("target.artifact_sha256 must contain 64 hexadecimal characters")

        base_url = target.get("private_base_url")
        if isinstance(base_url, str) and not _is_placeholder(base_url):
            parsed_url = urlparse(base_url)
            if parsed_url.scheme not in {"http", "https"} or not parsed_url.hostname:
                errors.append("target.private_base_url must be an HTTP(S) URL")
            elif parsed_url.hostname.lower() in PUBLIC_DEMO_HOSTS:
                errors.append("target.private_base_url points to a prohibited public demo")

    if isinstance(authorization, dict):
        _check_string_fields(
            authorization,
            "authorization",
            AUTH_STRING_FIELDS,
            errors,
            reject_placeholders=True,
        )
        _check_list_fields(
            authorization,
            "authorization",
            AUTH_LIST_FIELDS,
            errors,
            reject_placeholders=True,
        )

        start_value = authorization.get("start_utc")
        end_value = authorization.get("end_utc")
        start = (
            _parse_utc(start_value, "start_utc", errors)
            if isinstance(start_value, str) and not _is_placeholder(start_value)
            else None
        )
        end = (
            _parse_utc(end_value, "end_utc", errors)
            if isinstance(end_value, str) and not _is_placeholder(end_value)
            else None
        )
        if start and end:
            if start >= end:
                errors.append("authorization window start must precede end")
            current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
            if not start <= current <= end:
                errors.append("authorization window is not currently active")

    if isinstance(attestations, dict):
        for field in REQUIRED_ATTESTATIONS:
            if attestations.get(field) is not True:
                errors.append(f"attestations.{field} must be true")

    return list(dict.fromkeys(errors))


def load_record(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate laboratory authorization metadata")
    parser.add_argument("record", type=Path, help="path to authorization JSON record")
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="validate schema and safety invariants without granting execution",
    )
    args = parser.parse_args(argv)

    try:
        record = load_record(args.record)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"AUTHORIZATION_BLOCKED: record could not be read ({type(exc).__name__})")
        return EXIT_BLOCKED

    errors = validate_schema(record) if args.validate_only else validate_authorization(record)
    if errors:
        print("AUTHORIZATION_BLOCKED")
        for error in errors:
            print(f"- {error}")
        return EXIT_BLOCKED

    if args.validate_only:
        print("SCHEMA_VALID: this result does not authorize testing")
    else:
        print("AUTHORIZED_RECORD_VALID: confirm the real-world authorization independently")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
