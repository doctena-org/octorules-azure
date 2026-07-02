"""Azure WAF lint plugin -- orchestrates all Azure-specific linter checks."""

import json
from typing import Any

from octorules.linter.engine import LintContext, LintResult, Severity
from octorules.linter.helpers import (
    count_phase_rules,
    find_duplicates_by_key,
    is_strict_int,
    iter_provider_phases,
)
from octorules.phases import PHASE_BY_NAME

from octorules_azure import AZURE_PHASE_NAMES
from octorules_azure.validate import RULE_IDS as _validate_ids
from octorules_azure.validate import validate_managed_rules, validate_rules

# Rule IDs emitted by cross-phase checks in this module.
_PLUGIN_RULE_IDS: frozenset[str] = frozenset(
    {
        "AZ024",
        "AZ500",
        "AZ501",
        "AZ520",
        "AZ521",
    }
)

AZ_RULE_IDS: frozenset[str] = _validate_ids | _PLUGIN_RULE_IDS


def _check_duplicate_match_conditions(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """AZ520: Detect duplicate matchConditions across rules within each Azure phase.

    If two rules in the same phase have identical matchConditions (after
    serialising to sorted JSON), warn about potential copy-paste error.

    This is a cross-phase/policy-level check.  Results are emitted with
    ``phase=""`` so they are never filtered by ``ctx.phase_filter``.
    """
    for phase_name, rules in rules_data.items():
        if phase_name not in AZURE_PHASE_NAMES:
            continue
        if phase_name not in PHASE_BY_NAME:
            continue
        if not isinstance(rules, list):
            continue

        # Build (key, ref) pairs for duplicate detection
        pairs: list[tuple[str, str]] = []
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            conditions = rule.get("matchConditions")
            if not isinstance(conditions, list):
                continue
            ref = str(rule.get("ref", ""))
            key = json.dumps(
                sorted(
                    (json.dumps(c, sort_keys=True) for c in conditions),
                ),
            )
            pairs.append((key, ref))

        # find_duplicates_by_key groups by key and returns only those with >1 ref
        duplicates = find_duplicates_by_key(pairs)
        for _, refs in sorted(duplicates.items()):
            ctx.add(
                LintResult(
                    rule_id="AZ520",
                    severity=Severity.WARNING,
                    message=(
                        f"Duplicate matchConditions in rules: {', '.join(refs)}"
                        " (possible copy-paste error)"
                    ),
                    phase="",
                )
            )


_MAX_CUSTOM_RULES_PER_POLICY = 100


def _check_total_rule_count(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """AZ501: Check total custom rules across all Azure phases (per-policy limit).

    Azure WAF limits custom rules to 100 per policy across all rule types
    (MatchRule + RateLimitRule combined).

    This is a cross-phase/policy-level check.  Results are emitted with
    ``phase=""`` so they are never filtered by ``ctx.phase_filter``.
    """
    # dict_only=False: the policy limit counts every list entry, matching
    # Azure's own accounting. Managed rule sets are excluded — they don't
    # count toward the custom-rule limit.
    total = count_phase_rules(
        rules_data,
        AZURE_PHASE_NAMES,
        exclude=("azure_waf_managed_rules",),
        dict_only=False,
    )

    if total > _MAX_CUSTOM_RULES_PER_POLICY:
        ctx.add(
            LintResult(
                rule_id="AZ501",
                severity=Severity.WARNING,
                message=(
                    f"Policy has {total} custom rules across all phases,"
                    f" exceeding the limit of {_MAX_CUSTOM_RULES_PER_POLICY}"
                ),
                phase="",
            )
        )


def _check_cross_phase_priorities(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """AZ521: Detect duplicate priorities across Azure phases.

    Azure WAF requires priorities to be unique across ALL custom rules
    in a policy, not just within a single phase (ruleType).

    This is a cross-phase/policy-level check.  Results are emitted with
    ``phase=""`` so they are never filtered by ``ctx.phase_filter``.
    """
    # Build (priority, phase_ref) pairs for duplicate detection
    pairs: list[tuple[int, tuple[str, str]]] = []
    for phase_name, rules in rules_data.items():
        if phase_name not in AZURE_PHASE_NAMES:
            continue
        if phase_name not in PHASE_BY_NAME:
            continue
        if not isinstance(rules, list):
            continue
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            priority = rule.get("priority")
            if not is_strict_int(priority):
                continue
            ref = str(rule.get("ref", ""))
            pairs.append((priority, (phase_name, ref)))

    # find_duplicates_by_key groups by priority and returns only those with >1 ref
    duplicates = find_duplicates_by_key(pairs)
    for priority, locations in sorted(duplicates.items()):
        phases = {phase for phase, _ in locations}
        if len(phases) > 1:
            labels = [f"{ref} ({phase})" for phase, ref in locations]
            ctx.add(
                LintResult(
                    rule_id="AZ521",
                    severity=Severity.ERROR,
                    message=(f"Priority {priority} used across phases: " + ", ".join(labels)),
                    phase="",
                )
            )


_MAX_REGEX_RULES_PER_POLICY = 5


def _check_cross_phase_regex_count(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """AZ500: Count regex rules across all phases (per-policy limit).

    Overrides the per-phase check to ensure the limit applies across
    all rule types combined.

    This is a cross-phase/policy-level check.  Results are emitted with
    ``phase=""`` so they are never filtered by ``ctx.phase_filter``.
    """
    total_regex = 0
    for phase_name, rules in rules_data.items():
        if phase_name not in AZURE_PHASE_NAMES:
            continue
        if phase_name not in PHASE_BY_NAME:
            continue
        if not isinstance(rules, list):
            continue
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            conditions = rule.get("matchConditions")
            if not isinstance(conditions, list):
                continue
            if any(isinstance(c, dict) and c.get("operator") == "RegEx" for c in conditions):
                total_regex += 1

    if total_regex > _MAX_REGEX_RULES_PER_POLICY:
        ctx.add(
            LintResult(
                rule_id="AZ500",
                severity=Severity.ERROR,
                message=(
                    f"Policy has {total_regex} regex rules across all phases,"
                    f" exceeding the limit of {_MAX_REGEX_RULES_PER_POLICY}"
                ),
                phase="",
            )
        )


def azure_lint(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """Run all Azure WAF lint checks on a zone rules file."""
    for phase_name, rules in iter_provider_phases(rules_data, ctx, AZURE_PHASE_NAMES):
        if phase_name == "azure_waf_managed_rules":
            results = validate_managed_rules(rules, phase=phase_name)
        else:
            results = validate_rules(rules, phase=phase_name)
        for result in results:
            ctx.add(result)

    # Handle non-list phases (AZ024)
    for phase_name in AZURE_PHASE_NAMES:
        if phase_name not in PHASE_BY_NAME:
            continue
        if ctx.phase_filter and phase_name not in ctx.phase_filter:
            continue
        if phase_name in rules_data and not isinstance(rules_data[phase_name], list):
            ctx.add(
                LintResult(
                    rule_id="AZ024",
                    severity=Severity.ERROR,
                    message=f"Phase '{phase_name}' value is not a list",
                    phase=phase_name,
                )
            )

    # Cross-phase checks (run after per-phase validation)
    _check_duplicate_match_conditions(rules_data, ctx)
    _check_total_rule_count(rules_data, ctx)
    _check_cross_phase_priorities(rules_data, ctx)
    _check_cross_phase_regex_count(rules_data, ctx)
