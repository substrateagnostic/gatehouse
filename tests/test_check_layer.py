"""Unit tests for gatehouse.checks: GateConstraint -> FCE enclave -> CheckResult.

No HTTP here -- these exercise check_text/compile_constraints/validate_constraints
directly against the FCE runtime (imported, not reimplemented -- C-FCE1).
"""

from __future__ import annotations

import dataclasses
import json

from gatehouse.checks import CheckResult, check_text, compile_constraints, validate_constraints
from gatehouse.models import EnforcementType, GateConstraint, Severity

_NO_DETECTOR_NOTE = "no supported detector fired; stand-down is not an affirmative safety proof"


def make_constraint(
    constraint_id: str,
    enforcement: EnforcementType,
    target: str,
    *,
    severity: Severity = Severity.P1,
    applies_to: str = "both",
    on_violation: str = "flag",
    soul_invariant: bool = False,
) -> GateConstraint:
    return GateConstraint(
        id=constraint_id,
        description=f"test constraint {constraint_id}",
        severity=severity,
        enforcement=enforcement,
        target=target,
        applies_to=applies_to,
        on_violation=on_violation,
        soul_invariant=soul_invariant,
    )


# ---------------------------------------------------------------------------
# compile_constraints
# ---------------------------------------------------------------------------


def test_compile_constraints_filters_by_applies_to():
    constraints = [
        make_constraint("req-only", EnforcementType.MUST_NOT_INCLUDE_REGEX, "x", applies_to="request"),
        make_constraint("resp-only", EnforcementType.MUST_NOT_INCLUDE_REGEX, "y", applies_to="response"),
        make_constraint("both-sides", EnforcementType.MUST_NOT_INCLUDE_REGEX, "z", applies_to="both"),
    ]
    request_set = compile_constraints(constraints, "request")
    assert {c.source_id for c in request_set} == {"req-only", "both-sides"}

    response_set = compile_constraints(constraints, "response")
    assert {c.source_id for c in response_set} == {"resp-only", "both-sides"}


# ---------------------------------------------------------------------------
# Each enforcement type, in isolation: fires when violated, clean when not
# ---------------------------------------------------------------------------


def test_must_include_heading_fires_when_missing_and_clean_when_present():
    constraint = make_constraint("heading-required", EnforcementType.MUST_INCLUDE_HEADING, "Risk Disclosure")

    missing = check_text("Just some prose, no headings at all.", [constraint], applies_to="response")
    assert missing.disposition in ("flag", "block")
    assert "heading-required" in missing.constraint_ids

    present = check_text("# Risk Disclosure\nHere is the content.", [constraint], applies_to="response")
    assert present.disposition == "correct_continue"
    assert present.constraint_ids == []


def test_must_include_regex_fires_when_missing_and_clean_when_present():
    constraint = make_constraint(
        "disclaimer-required", EnforcementType.MUST_INCLUDE_REGEX, r"\bconsult (a|your) (attorney|lawyer)\b"
    )

    missing = check_text("Here is some generic advice.", [constraint], applies_to="response")
    assert missing.disposition in ("flag", "block")
    assert "disclaimer-required" in missing.constraint_ids

    present = check_text(
        "Please consult a lawyer before acting on this.", [constraint], applies_to="response"
    )
    assert present.disposition == "correct_continue"
    assert present.constraint_ids == []


def test_must_not_include_regex_fires_when_present_and_clean_when_absent():
    constraint = make_constraint("no-guarantee", EnforcementType.MUST_NOT_INCLUDE_REGEX, r"\bguarantee(d)?\b")

    violated = check_text("This is a guaranteed return.", [constraint], applies_to="response")
    assert violated.disposition in ("flag", "block")
    assert "no-guarantee" in violated.constraint_ids
    assert violated.resolution == "block"  # hard obstruction, enclave-native

    clean = check_text("This is a safe, modest return.", [constraint], applies_to="response")
    assert clean.disposition == "correct_continue"
    assert clean.constraint_ids == []


# ---------------------------------------------------------------------------
# C-FCE1: at least 3 constraint kinds firing together
# ---------------------------------------------------------------------------


def test_three_enforcement_types_fire_together():
    constraints = [
        make_constraint("heading-required", EnforcementType.MUST_INCLUDE_HEADING, "Risk Disclosure"),
        make_constraint(
            "disclaimer-required", EnforcementType.MUST_INCLUDE_REGEX, r"\bconsult (a|your) (attorney|lawyer)\b"
        ),
        make_constraint("no-guarantee", EnforcementType.MUST_NOT_INCLUDE_REGEX, r"\bguarantee(d)?\b"),
    ]
    text = "This is a guaranteed return with no headings and no legal disclaimer at all."

    result = check_text(text, constraints, applies_to="response")

    assert set(result.constraint_ids) == {"heading-required", "disclaimer-required", "no-guarantee"}
    assert result.disposition in ("flag", "block")
    assert len(result.witnesses) >= 3


def test_three_enforcement_types_pass_when_satisfied():
    constraints = [
        make_constraint("heading-required", EnforcementType.MUST_INCLUDE_HEADING, "Risk Disclosure"),
        make_constraint(
            "disclaimer-required", EnforcementType.MUST_INCLUDE_REGEX, r"\bconsult (a|your) (attorney|lawyer)\b"
        ),
        make_constraint("no-guarantee", EnforcementType.MUST_NOT_INCLUDE_REGEX, r"\bguarantee(d)?\b"),
    ]
    text = "# Risk Disclosure\nPlease consult a lawyer before investing. There are no promises here."

    result = check_text(text, constraints, applies_to="response")

    assert result.constraint_ids == []
    assert result.witnesses == []
    assert result.disposition == "correct_continue"


# ---------------------------------------------------------------------------
# C-FCE2: correct_continue is first-class -- content_hash + honest epistemics
# ---------------------------------------------------------------------------


def test_correct_continue_carries_content_hash_and_honest_note():
    result = check_text("Nothing objectionable here.", [], applies_to="response")

    assert isinstance(result, CheckResult)
    assert result.disposition == "correct_continue"
    assert result.resolution == "release"
    assert len(result.content_hash) == 64  # sha256 hex digest length
    assert all(c in "0123456789abcdef" for c in result.content_hash)
    assert result.note == _NO_DETECTOR_NOTE
    assert result.witnesses == []
    assert result.constraint_ids == []
    assert result.blocked_by == []


# ---------------------------------------------------------------------------
# Soul invariants: P0 violation lands per the disposition mapping
# ---------------------------------------------------------------------------


def test_soul_invariant_p0_violation_blocks_when_on_violation_block():
    constraint = make_constraint(
        "no-ssn",
        EnforcementType.MUST_NOT_INCLUDE_REGEX,
        r"\d{3}-\d{2}-\d{4}",
        severity=Severity.P0,
        on_violation="block",
        soul_invariant=True,
    )
    result = check_text("My number is 123-45-6789.", [constraint], applies_to="request")

    assert result.resolution == "block"
    assert result.disposition == "block"
    assert result.blocked_by == ["no-ssn"]


def test_soul_invariant_p0_violation_flags_when_on_violation_flag():
    constraint = make_constraint(
        "no-ssn",
        EnforcementType.MUST_NOT_INCLUDE_REGEX,
        r"\d{3}-\d{2}-\d{4}",
        severity=Severity.P0,
        on_violation="flag",
        soul_invariant=True,
    )
    result = check_text("My number is 123-45-6789.", [constraint], applies_to="request")

    assert result.resolution == "block"
    assert result.disposition == "flag"  # shadow: observed, not blocked
    assert result.blocked_by == []
    assert "no-ssn" in result.constraint_ids


# ---------------------------------------------------------------------------
# Witnesses are content-free
# ---------------------------------------------------------------------------


def test_witnesses_never_contain_the_checked_text():
    # The regex TARGET is policy config, authored offline -- it's legitimate
    # for a witness to echo it back (see the FCE library's own
    # `suggested_resolution` messages). What must never appear is the
    # CHECKED TEXT itself -- the specific secret value the pattern matched
    # against, and any surrounding prose from the payload.
    secret_value = "ZEBRA-NINE-CASCADE-7734"
    text = f"The launch code is {secret_value} and must never leak to anyone."
    constraint = make_constraint("no-launch-code", EnforcementType.MUST_NOT_INCLUDE_REGEX, r"launch code")

    result = check_text(text, [constraint], applies_to="response")

    assert result.disposition in ("flag", "block")
    serialized = json.dumps(dataclasses.asdict(result))
    assert secret_value not in serialized
    assert "must never leak" not in serialized
    for witness in result.witnesses:
        assert set(witness.keys()) == {
            "obstruction_type",
            "severity",
            "constraint_a_id",
            "constraint_b_id",
            "suggested_resolution",
        }


# ---------------------------------------------------------------------------
# validate_constraints: malformed regex never silently passes
# ---------------------------------------------------------------------------


def test_validate_constraints_catches_bad_regex():
    constraints = [
        make_constraint("bad-regex", EnforcementType.MUST_INCLUDE_REGEX, "(unclosed["),
        make_constraint("good-regex", EnforcementType.MUST_NOT_INCLUDE_REGEX, r"\bfoo\b"),
    ]
    problems = validate_constraints(constraints)

    assert len(problems) == 1
    assert "bad-regex" in problems[0]


def test_validate_constraints_catches_duplicate_ids():
    constraints = [
        make_constraint("dup", EnforcementType.MUST_INCLUDE_HEADING, "A"),
        make_constraint("dup", EnforcementType.MUST_INCLUDE_HEADING, "B"),
    ]
    problems = validate_constraints(constraints)
    assert any("dup" in p and "duplicate" in p for p in problems)


def test_validate_constraints_clean_config_has_no_problems():
    constraints = [
        make_constraint("a", EnforcementType.MUST_INCLUDE_HEADING, "Heading"),
        make_constraint("b", EnforcementType.MUST_INCLUDE_REGEX, r"\bfoo\b"),
        make_constraint("c", EnforcementType.MUST_NOT_INCLUDE_REGEX, r"\bbar\b"),
    ]
    assert validate_constraints(constraints) == []


def test_check_text_never_silently_passes_a_bad_regex_that_bypassed_validation():
    # validate_constraints() is the intended gate at session-open; this proves
    # check_text() itself also fails safe (never silently passes) if a bad
    # regex reaches it anyway, e.g. from a config path that skipped validation.
    constraint = make_constraint("bad-regex", EnforcementType.MUST_INCLUDE_REGEX, "(unclosed[")
    result = check_text("some text", [constraint], applies_to="response")
    assert result.disposition != "correct_continue"
    assert "bad-regex" in result.constraint_ids
