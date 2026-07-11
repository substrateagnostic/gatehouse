"""The check layer: GateConstraint -> FCE enclave verdict -> CheckResult.

Imports the FCE runtime rather than reimplementing constraint evaluation
(C-FCE1). The live-text primitive is `fiduciary.cohomology.enclave.
check_in_enclave`: it runs in volatile memory, never persists the checked
text, and returns a content-free `EnclaveVerdict` (content_hash +
obstruction witnesses only).

Seam-layer note (see final report): as installed, the enclave's
`_check_content_against_constraints` only evaluates MUST_NOT_INCLUDE_REGEX
directly against the checked text. MUST_INCLUDE_HEADING and
MUST_INCLUDE_REGEX are only run through `_extract_prompt_constraints` +
`check_compatibility`, which detects POLICY-vs-POLICY conflicts (e.g. a
required heading that matches a forbidden pattern) -- not textual absence.
Verified empirically: a response missing a required heading/pattern still
resolves RELEASE. Gatehouse supplements presence-detection for those two
enforcement types locally (`_heading_present` / `_pattern_present`) and
folds any local miss into the same hard-obstruction -> BLOCK path the
enclave already uses for MUST_NOT_INCLUDE_REGEX, so disposition mapping
stays uniform regardless of which layer found the violation. All obstruction
severities produced by the deterministic constraint types are "hard" -- WIGGLE
is not reachable from these three enforcement types in the current FCE
release (only semantic/visual constraint types can emit "soft").
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from fiduciary.cohomology.constraints import (
    ConstraintPolarity,
    ConstraintSet,
    ConstraintType,
    NormalizedConstraint,
)
from fiduciary.cohomology.enclave import EnclaveResolution, check_in_enclave
from fiduciary.models import Severity as FceSeverity

from .models import EnforcementType, GateConstraint

__all__ = ["CheckResult", "compile_constraints", "check_text", "validate_constraints"]

# The honest-epistemics line the FCE spec requires on every correct_continue
# verdict: stand-down (no detector fired) is not itself an affirmative proof
# of safety. Preserved verbatim wherever disposition == "correct_continue".
_NO_DETECTOR_NOTE = "no supported detector fired; stand-down is not an affirmative safety proof"

# The heading grammar the enclave itself uses to extract headings from text
# (see fiduciary.cohomology.enclave.EphemeralEnclave._extract_prompt_constraints)
# -- reused here so gatehouse's presence check agrees with the FCE runtime's
# own notion of "heading".
_HEADING_RE = re.compile(r"^#+\s+(.+)$", re.MULTILINE)


@dataclass
class CheckResult:
    """The outcome of checking one payload (request or response text)
    against a set of applicable constraints."""

    disposition: str  # "correct_continue" | "flag" | "block" | "escalate"
    resolution: str  # raw enclave resolution name (or "block" if gatehouse's
    # local presence-detector found a miss the enclave itself doesn't check)
    content_hash: str
    constraint_ids: list[str] = field(default_factory=list)
    witnesses: list[dict] = field(default_factory=list)
    blocked_by: list[str] = field(default_factory=list)
    note: str = ""


def _applies(constraint: GateConstraint, applies_to: str) -> bool:
    return constraint.applies_to == "both" or constraint.applies_to == applies_to


def _to_normalized(constraint: GateConstraint) -> NormalizedConstraint:
    constraint_type = ConstraintType(constraint.enforcement.value)
    polarity = (
        ConstraintPolarity.NEGATIVE
        if constraint.enforcement == EnforcementType.MUST_NOT_INCLUDE_REGEX
        else ConstraintPolarity.POSITIVE
    )
    return NormalizedConstraint(
        constraint_type=constraint_type,
        polarity=polarity,
        target=constraint.target,
        severity=FceSeverity(constraint.severity.value),
        source_id=constraint.id,
        is_soul_invariant=constraint.soul_invariant,
    )


def compile_constraints(constraints: list[GateConstraint], applies_to: str) -> ConstraintSet:
    """Filter GateConstraints by `applies_to` ("both" matches either side)
    and build the FCE ConstraintSet the enclave checks against."""
    constraint_set = ConstraintSet()
    for constraint in constraints:
        if _applies(constraint, applies_to):
            constraint_set.add(_to_normalized(constraint))
    return constraint_set


def validate_constraints(constraints: list[GateConstraint]) -> list[str]:
    """Human-readable config problems, so a bad session config is rejected
    at session-open (400) instead of silently never firing at check time.

    A malformed regex must never silently pass: catch it here before it
    ever reaches the enclave, in addition to the enclave's own ReDoS hard
    obstruction at check time.
    """
    problems: list[str] = []
    seen_ids: set[str] = set()
    for constraint in constraints:
        if constraint.id in seen_ids:
            problems.append(f"constraint '{constraint.id}': duplicate constraint id")
        seen_ids.add(constraint.id)

        if constraint.enforcement in (
            EnforcementType.MUST_INCLUDE_REGEX,
            EnforcementType.MUST_NOT_INCLUDE_REGEX,
        ):
            try:
                re.compile(constraint.target)
            except re.error as exc:
                problems.append(
                    f"constraint '{constraint.id}': invalid regex pattern "
                    f"{constraint.target!r}: {exc}"
                )
    return problems


def _heading_present(text: str, target: str) -> bool:
    target_norm = target.strip().lower()
    if not target_norm:
        return True
    for match in _HEADING_RE.finditer(text):
        heading = match.group(1).strip().lower()
        if target_norm == heading or target_norm in heading:
            return True
    return False


def _pattern_present(text: str, target: str) -> bool:
    # validate_constraints() should have already rejected an uncompilable
    # pattern at session-open; still guard here defensively -- a regex that
    # fails to compile must count as a miss, never a silent pass.
    try:
        return re.search(target, text, re.IGNORECASE | re.MULTILINE) is not None
    except re.error:
        return False


def _witness_dict(
    *, obstruction_type: str, constraint_a_id: str, constraint_b_id: str, suggested_resolution: str
) -> dict:
    return {
        "obstruction_type": obstruction_type,
        "severity": "hard",
        "constraint_a_id": constraint_a_id,
        "constraint_b_id": constraint_b_id,
        "suggested_resolution": suggested_resolution,
    }


def check_text(text: str, constraints: list[GateConstraint], *, applies_to: str) -> CheckResult:
    """Check `text` (a request or response payload) against the constraints
    applicable to `applies_to` ("request" | "response"), via the FCE
    ephemeral enclave. The checked text never persists past this call --
    only the returned CheckResult (content_hash + content-free witnesses)
    is safe to write into the evidence log.
    """
    applicable = [c for c in constraints if _applies(c, applies_to)]
    id_lookup = {c.id: c for c in applicable}

    constraint_set = ConstraintSet()
    for constraint in applicable:
        constraint_set.add(_to_normalized(constraint))

    verdict = check_in_enclave(
        prompt=text,
        constraint_set=constraint_set,
        escalate_soft=True,
        fail_safe=True,
    )

    witnesses = [w.to_dict() for w in verdict.obstruction_witnesses]
    fired_ids: set[str] = set()
    for witness in witnesses:
        for key in ("constraint_a_id", "constraint_b_id"):
            candidate = witness.get(key)
            if candidate in id_lookup:
                fired_ids.add(candidate)

    resolution = verdict.resolution

    # Supplement: local presence-detection for MUST_INCLUDE_HEADING /
    # MUST_INCLUDE_REGEX (see module docstring). Skipped on ERROR -- if the
    # enclave itself failed, fail-safe wins and we don't layer more findings
    # on top of an untrusted result.
    if resolution != EnclaveResolution.ERROR:
        for constraint in applicable:
            missing = False
            if constraint.enforcement == EnforcementType.MUST_INCLUDE_HEADING:
                missing = not _heading_present(text, constraint.target)
            elif constraint.enforcement == EnforcementType.MUST_INCLUDE_REGEX:
                missing = not _pattern_present(text, constraint.target)
            else:
                continue

            if missing:
                fired_ids.add(constraint.id)
                witnesses.append(
                    _witness_dict(
                        obstruction_type="required_content_missing",
                        constraint_a_id=constraint.id,
                        constraint_b_id="checked_text",
                        suggested_resolution=(
                            f"Required {constraint.enforcement.value} target "
                            f"{constraint.target!r} not found in checked text."
                        ),
                    )
                )
                if resolution == EnclaveResolution.RELEASE:
                    resolution = EnclaveResolution.BLOCK

    if resolution == EnclaveResolution.RELEASE:
        disposition = "correct_continue"
        note = _NO_DETECTOR_NOTE
    elif resolution == EnclaveResolution.WIGGLE:
        disposition = "escalate"
        note = "obstruction requires human review (wiggle)"
    elif resolution == EnclaveResolution.ERROR:
        disposition = "escalate"
        note = "check-layer error; fail-safe escalation, no detector output trusted"
    else:  # BLOCK
        blocking_ids = sorted(
            cid
            for cid in fired_ids
            if cid in id_lookup and id_lookup[cid].on_violation == "block"
        )
        disposition = "block" if blocking_ids else "flag"
        note = (
            "on_violation=block constraint fired; traffic blocked"
            if disposition == "block"
            else "constraint violation observed in shadow mode; traffic unaffected"
        )

    blocked_by = sorted(
        cid for cid in fired_ids if cid in id_lookup and id_lookup[cid].on_violation == "block"
    )

    return CheckResult(
        disposition=disposition,
        resolution=resolution.value,
        content_hash=verdict.content_hash,
        constraint_ids=sorted(fired_ids),
        witnesses=witnesses,
        blocked_by=blocked_by,
        note=note,
    )
