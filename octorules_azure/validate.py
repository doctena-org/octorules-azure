"""Offline validation for Azure WAF rules.

Operates on the normalised internal form (Front Door canonical), so the
same validation logic works for both Front Door and Application Gateway.
"""

import ipaddress
import re
from contextvars import ContextVar

from octorules.linter.engine import LintResult, Severity
from octorules.linter.helpers import (
    CATCH_ALL_CIDRS,
    find_duplicate_priorities,
    find_first_priority_gap,
    find_overlapping_cidrs,
    is_strict_int,
    lint_result,
    normalize_host_bits,
)
from octorules.reserved_ips import is_reserved

# Rule IDs emitted by validate_rules() / validate_managed_rules() — kept in
# sync with _rules.py by test_plugin_rule_ids_match_meta.
RULE_IDS: frozenset[str] = frozenset(
    {
        "AZ001",
        "AZ002",
        "AZ003",
        "AZ004",
        "AZ005",
        "AZ006",
        "AZ010",
        "AZ020",
        "AZ021",
        "AZ022",
        "AZ023",
        "AZ027",
        "AZ100",
        "AZ101",
        "AZ102",
        "AZ103",
        "AZ200",
        "AZ201",
        "AZ300",
        "AZ301",
        "AZ302",
        "AZ310",
        "AZ311",
        "AZ312",
        "AZ313",
        "AZ314",
        "AZ315",
        "AZ316",
        "AZ317",
        "AZ318",
        "AZ319",
        "AZ320",
        "AZ321",
        "AZ322",
        "AZ323",
        "AZ324",
        "AZ325",
        "AZ326",
        "AZ327",
        "AZ328",
        "AZ330",
        "AZ331",
        "AZ332",
        "AZ333",
        "AZ334",
        "AZ335",
        "AZ336",
        "AZ337",
        "AZ338",
        "AZ339",
        "AZ340",
        "AZ341",
        "AZ342",
        "AZ343",
        "AZ344",
        "AZ345",
        "AZ400",
        "AZ401",
        "AZ402",
        "AZ403",
        "AZ410",
        "AZ411",
        "AZ600",
        "AZ601",
        "AZ602",
        "AZ603",
        "AZ700",
        "AZ701",
        "AZ702",
        "AZ703",
        "AZ704",
        "AZ705",
        "AZ706",
        "AZ707",
        "AZ708",
    }
)


# ---------------------------------------------------------------------------
# Azure WAF constants
# ---------------------------------------------------------------------------
_MAX_MATCH_CONDITIONS = 10
# Front Door geo-filtering doc: "You can only include a maximum of ten
# country/region codes in a single custom rule."
_FD_MAX_GEO_COUNTRY_CODES = 10
_MAX_STRING_MATCH_VALUES = 10
_MAX_IP_MATCH_VALUES = 600
_MAX_NAME_LEN = 128
# octorules guidance, not an Azure limit: Microsoft states no priority
# ceiling for Front Door custom rules (the current REST spec declares
# priority as a bare integer while bounding other fields in the same
# object).  With at most 100 custom rules per policy (AZ501), priorities
# above 100 usually signal a numbering scheme worth a look.
_FD_MAX_PRIORITY = 100
_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*$")

# Custom-rule actions per MS docs: FD = Allow/Block/Log/Redirect (+ JSChallenge
# on Premium); AG = Allow/Block/Log (+ JSChallenge, preview). AnomalyScoring is
# a managed-rule override action only and is rejected here (see the separate
# override-action set used for managed-rule validation).
_VALID_ACTIONS = frozenset({"Allow", "Block", "Log", "Redirect", "JSChallenge"})

# waf_type-aware validation: features restricted to one WAF type.
_FD_ONLY_ACTIONS = frozenset({"Redirect"})
_FD_ONLY_OPERATORS = frozenset({"ServiceTagMatch"})
_FD_ONLY_VARIABLES = frozenset({"SocketAddr"})
_AG_ONLY_TRANSFORMS = frozenset({"HtmlEntityDecode"})

# Thread-safe waf_type (set by provider __init__ via set_waf_type()).
_WAF_TYPE: ContextVar[str] = ContextVar("_WAF_TYPE", default="")


def set_waf_type(waf_type: str) -> None:
    """Set the WAF type for waf-type-aware validation.

    Called by ``AzureWafProvider.__init__()`` so that lint rules can warn
    when FD-only features are used with App Gateway (and vice versa).

    Uses a :class:`contextvars.ContextVar` so concurrent providers in
    different threads/tasks don't interfere with each other.
    """
    _WAF_TYPE.set(waf_type)


_VALID_MATCH_VARIABLES = frozenset(
    {
        "RemoteAddr",
        "RequestMethod",
        "QueryString",
        "PostArgs",
        "RequestUri",
        "RequestHeader",
        "RequestBody",
        "Cookies",
        "SocketAddr",
    }
)

# Variables that require a selector (header name, cookie name, etc.)
_SELECTOR_VARIABLES = frozenset({"RequestHeader", "Cookies", "PostArgs"})

_VALID_OPERATORS = frozenset(
    {
        "Any",
        "IPMatch",
        "GeoMatch",
        "Equal",
        "Contains",
        "LessThan",
        "GreaterThan",
        "LessThanOrEqual",
        "GreaterThanOrEqual",
        "BeginsWith",
        "EndsWith",
        "RegEx",
        # Front Door REST spec, stable 2025-10-01+ (WafPolicyCreateOrUpdate
        # examples use it); the pinned SDKs predate it.
        "ServiceTagMatch",
    }
)

_VALID_TRANSFORMS = frozenset(
    {
        "Lowercase",
        "Uppercase",
        "Trim",
        "UrlDecode",
        "UrlEncode",
        "RemoveNulls",
        "HtmlEntityDecode",
    }
)

_VALID_RATE_DURATIONS = frozenset({1, 5})  # minutes
# Azure's REST spec constrains rateLimitThreshold to minimum 0 with no
# maximum, so AZ403 only rejects negative values and there is deliberately
# no upper-bound check.
_RATE_THRESHOLD_MIN = 0

_VALID_GROUP_BY_VARIABLES = frozenset({"SocketAddr", "GeoLocation", "None"})

_COUNTRY_CODE_RE = re.compile(r"^[A-Z]{2}$")
_MAX_GEO_COUNTRY_CODES = 200  # >200 likely means "block the world"

_VALID_ENABLED_STATES = frozenset({"Enabled", "Disabled"})
_VALID_RULE_TYPES = frozenset({"MatchRule", "RateLimitRule"})

# Operators that work on string values (transforms are meaningful).
_STRING_OPERATORS = frozenset(
    {
        "Equal",
        "Contains",
        "BeginsWith",
        "EndsWith",
        "RegEx",
        "LessThan",
        "GreaterThan",
        "LessThanOrEqual",
        "GreaterThanOrEqual",
    }
)
# Operators where transforms have no effect.
_NO_TRANSFORM_OPERATORS = frozenset({"IPMatch", "GeoMatch", "Any", "ServiceTagMatch"})

# Catch-all CIDR ranges (match everything).
# Reserved/bogon network detection is provided by octorules.reserved_ips
# (single source of truth across providers; see core v0.26.0).

# Transform pairs that conflict or are redundant when applied together.
_CONFLICTING_TRANSFORMS = frozenset(
    {
        ("Lowercase", "Uppercase"),
        ("Uppercase", "Lowercase"),
    }
)

# Maximum regex pattern length (Azure doesn't document a hard limit, but
# patterns over 256 chars are likely problematic and indicate configuration errors).
# octorules guidance, not an Azure limit — neither WAF product publishes a
# regex length bound.
_MAX_REGEX_PATTERN_LEN = 256

# Regexes that match every input (overly-permissive patterns).
_OVERLY_PERMISSIVE_REGEX = frozenset(
    {
        "",
        ".",
        ".*",
        "^.*",
        ".*$",
        "^.*$",
        ".+",
        "^.+",
        ".+$",
        "^.+$",
        "^",
        "$",
        "|",
    }
)

# Conservative regex for fully-anchored literal patterns (e.g., "^literal$").
# Matches only literal chars, escaped dots/slashes, and anchors.
_FULLY_ANCHORED_LITERAL_REGEX = re.compile(
    r"^\^"  # start anchor
    r"((?:[a-zA-Z0-9_/-]|\\\.|\\/)+)"  # literal-only payload (escaped . or / OK)
    r"\$$"  # end anchor
)

# Valid top-level rule fields in canonical form.
_VALID_RULE_FIELDS = frozenset(
    {
        "ref",
        "priority",
        "action",
        "enabledState",
        "ruleType",
        "matchConditions",
        "rateLimitDurationInMinutes",
        "rateLimitThreshold",
        "groupBy",
    }
)


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------
def _check_ref(rule: dict, results: list[LintResult], phase: str) -> str:
    """AZ001, AZ010, AZ022, AZ027: Validate ref field."""
    ref = rule.get("ref")
    if ref is None or ref == "":
        results.append(
            lint_result("AZ001", Severity.ERROR, "Rule missing 'ref'", phase, field="ref")
        )
        return ""
    ref_str = str(ref)
    _check_whitespace_structural_field("ref", ref_str, results, phase, "")
    if len(ref_str) > _MAX_NAME_LEN:
        results.append(
            lint_result(
                "AZ010",
                Severity.ERROR,
                f"ref exceeds {_MAX_NAME_LEN} characters ({len(ref_str)})",
                phase,
                ref=ref_str,
                field="ref",
            )
        )
    elif not _NAME_RE.match(ref_str):
        results.append(
            lint_result(
                "AZ010",
                Severity.ERROR,
                "ref must start with a letter and contain only letters, digits, and underscores",
                phase,
                ref=ref_str,
                field="ref",
                suggestion="Rename to match pattern ^[a-zA-Z][a-zA-Z0-9_]*$",
            )
        )
    return ref_str


def _check_whitespace_structural_field(
    field_name: str, field_value: object, results: list[LintResult], phase: str, ref: str
) -> None:
    """AZ027: Check for leading/trailing whitespace in structural fields."""
    if isinstance(field_value, str) and (field_value != field_value.strip()):
        results.append(
            lint_result(
                "AZ027",
                Severity.WARNING,
                f"{field_name}: has leading or trailing whitespace",
                phase,
                ref=ref,
                field=field_name,
                suggestion=f"Remove whitespace: {field_value.strip()!r}",
            )
        )


def _check_priority(
    rule: dict,
    results: list[LintResult],
    phase: str,
    ref: str,
    seen_priorities: dict[int, list[str]],
) -> None:
    """AZ002, AZ100: Validate priority field."""
    priority = rule.get("priority")
    if priority is None:
        results.append(
            lint_result("AZ002", Severity.ERROR, "Rule missing 'priority'", phase, ref=ref)
        )
        return
    if not is_strict_int(priority) or priority < 1:
        results.append(
            lint_result(
                "AZ100",
                Severity.ERROR,
                f"priority must be a positive integer, got {priority!r}",
                phase,
                ref=ref,
                field="priority",
            )
        )
        return
    seen_priorities.setdefault(priority, []).append(ref)

    # AZ103: octorules guidance — Azure publishes no priority ceiling.
    if _WAF_TYPE.get() == "front_door" and priority > _FD_MAX_PRIORITY:
        results.append(
            lint_result(
                "AZ103",
                Severity.WARNING,
                f"Priority {priority} is above {_FD_MAX_PRIORITY} (octorules"
                " guidance — Azure publishes no priority ceiling; a policy"
                " holds at most 100 custom rules)",
                phase,
                ref=ref,
                field="priority",
            )
        )


def _check_action(rule: dict, results: list[LintResult], phase: str, ref: str) -> None:
    """AZ003, AZ027, AZ200: Validate action field."""
    action = rule.get("action")
    if action is None or action == "":
        results.append(
            lint_result("AZ003", Severity.ERROR, "Rule missing 'action'", phase, ref=ref)
        )
        return
    if not isinstance(action, str):
        results.append(
            lint_result(
                "AZ200",
                Severity.ERROR,
                f"action must be a string, got {type(action).__name__}",
                phase,
                ref=ref,
                field="action",
            )
        )
        return
    _check_whitespace_structural_field("action", action, results, phase, ref)
    if action not in _VALID_ACTIONS:
        results.append(
            lint_result(
                "AZ200",
                Severity.ERROR,
                f"Invalid action {action!r}",
                phase,
                ref=ref,
                field="action",
                suggestion=f"Valid: {sorted(_VALID_ACTIONS)}",
            )
        )
        return

    # AZ201: FD-only action used with App Gateway
    if _WAF_TYPE.get() == "app_gateway" and action in _FD_ONLY_ACTIONS:
        results.append(
            lint_result(
                "AZ201",
                Severity.ERROR,
                f"Action {action!r} is only supported on Front Door, not Application Gateway",
                phase,
                ref=ref,
                field="action",
            )
        )


def _check_match_conditions(rule: dict, results: list[LintResult], phase: str, ref: str) -> None:
    """AZ300-AZ320: Validate matchConditions."""
    conditions = rule.get("matchConditions")
    if conditions is None:
        results.append(
            lint_result(
                "AZ004",
                Severity.ERROR,
                "Rule missing 'matchConditions'",
                phase,
                ref=ref,
            )
        )
        return
    if not isinstance(conditions, list):
        results.append(
            lint_result(
                "AZ300",
                Severity.ERROR,
                f"matchConditions must be a list, got {type(conditions).__name__}",
                phase,
                ref=ref,
                field="matchConditions",
            )
        )
        return
    if len(conditions) == 0:
        results.append(
            lint_result(
                "AZ300",
                Severity.ERROR,
                "matchConditions must be a non-empty list",
                phase,
                ref=ref,
                field="matchConditions",
            )
        )
        return
    if len(conditions) > _MAX_MATCH_CONDITIONS:
        results.append(
            lint_result(
                "AZ301",
                Severity.ERROR,
                f"matchConditions has {len(conditions)} entries,"
                f" exceeding the maximum of {_MAX_MATCH_CONDITIONS}",
                phase,
                ref=ref,
                field="matchConditions",
            )
        )

    # AZ302: Front Door geo-filtering — "You can only include a maximum of
    # ten country/region codes in a single custom rule."  Per rule, so the
    # count sums across this rule's GeoMatch conditions; App Gateway
    # publishes no such limit.
    if _WAF_TYPE.get() == "front_door":
        geo_codes = sum(
            len(c.get("matchValue"))
            for c in conditions
            if isinstance(c, dict)
            and c.get("operator") == "GeoMatch"
            and isinstance(c.get("matchValue"), list)
        )
        if geo_codes > _FD_MAX_GEO_COUNTRY_CODES:
            results.append(
                lint_result(
                    "AZ302",
                    Severity.ERROR,
                    f"Rule matches {geo_codes} country/region codes across its"
                    f" GeoMatch conditions (Front Door maximum:"
                    f" {_FD_MAX_GEO_COUNTRY_CODES} per custom rule)",
                    phase,
                    ref=ref,
                    field="matchConditions",
                )
            )

    for i, cond in enumerate(conditions):
        if not isinstance(cond, dict):
            results.append(
                lint_result(
                    "AZ300",
                    Severity.ERROR,
                    f"matchConditions[{i}] must be a dict, got {type(cond).__name__}",
                    phase,
                    ref=ref,
                    field=f"matchConditions[{i}]",
                )
            )
            continue
        _check_single_condition(cond, results, phase, ref, i)

    # AZ336: Multiple conditions on same variable+operator (AND logic = intersection)
    _check_duplicate_variable_operator(conditions, results, phase, ref)


def _check_single_condition(
    cond: dict,
    results: list[LintResult],
    phase: str,
    ref: str,
    index: int,
) -> None:
    """Validate a single match condition."""
    prefix = f"matchConditions[{index}]"

    # AZ310: matchVariable
    variable = cond.get("matchVariable")
    if not isinstance(variable, str) or not variable:
        results.append(
            lint_result(
                "AZ310",
                Severity.ERROR,
                f"{prefix}: missing or empty matchVariable",
                phase,
                ref=ref,
                field=f"{prefix}.matchVariable",
            )
        )
    elif variable not in _VALID_MATCH_VARIABLES:
        results.append(
            lint_result(
                "AZ310",
                Severity.ERROR,
                f"{prefix}: invalid matchVariable {variable!r}",
                phase,
                ref=ref,
                field=f"{prefix}.matchVariable",
                suggestion=f"Expected one of: {', '.join(sorted(_VALID_MATCH_VARIABLES))}",
            )
        )

    # AZ327: FD-only variable used with App Gateway
    if (
        _WAF_TYPE.get() == "app_gateway"
        and isinstance(variable, str)
        and variable in _FD_ONLY_VARIABLES
    ):
        results.append(
            lint_result(
                "AZ327",
                Severity.ERROR,
                f"{prefix}: matchVariable {variable!r} is only supported on"
                " Front Door, not Application Gateway",
                phase,
                ref=ref,
                field=f"{prefix}.matchVariable",
            )
        )

    # AZ321: selector on non-selector variable (likely confusion)
    if isinstance(variable, str) and variable not in _SELECTOR_VARIABLES and variable:
        selector = cond.get("selector")
        if isinstance(selector, str) and selector:
            results.append(
                lint_result(
                    "AZ321",
                    Severity.WARNING,
                    f"{prefix}: selector {selector!r} is set but {variable} does not use selectors",
                    phase,
                    ref=ref,
                    field=f"{prefix}.selector",
                    suggestion="Remove selector or use RequestHeader/Cookies/PostArgs",
                )
            )

    # AZ315/AZ316/AZ027: selector
    if isinstance(variable, str) and variable in _SELECTOR_VARIABLES:
        selector = cond.get("selector")
        if selector is None:
            results.append(
                lint_result(
                    "AZ315",
                    Severity.ERROR,
                    f"{prefix}: selector is required for {variable}",
                    phase,
                    ref=ref,
                    field=f"{prefix}.selector",
                )
            )
        elif isinstance(selector, str) and selector == "":
            results.append(
                lint_result(
                    "AZ316",
                    Severity.WARNING,
                    f"{prefix}: selector is empty for {variable}",
                    phase,
                    ref=ref,
                    field=f"{prefix}.selector",
                )
            )
        elif isinstance(selector, str):
            # AZ027: check for whitespace in selector
            if selector != selector.strip():
                results.append(
                    lint_result(
                        "AZ027",
                        Severity.INFO,
                        f"{prefix}: selector {selector!r} has leading or trailing whitespace",
                        phase,
                        ref=ref,
                        field=f"{prefix}.selector",
                        suggestion=f"Remove whitespace: {selector.strip()!r}",
                    )
                )

    # AZ311: operator
    operator = cond.get("operator")
    if not isinstance(operator, str) or not operator:
        results.append(
            lint_result(
                "AZ311",
                Severity.ERROR,
                f"{prefix}: missing or empty operator",
                phase,
                ref=ref,
                field=f"{prefix}.operator",
            )
        )
    elif operator not in _VALID_OPERATORS:
        results.append(
            lint_result(
                "AZ311",
                Severity.ERROR,
                f"{prefix}: invalid operator {operator!r}",
                phase,
                ref=ref,
                field=f"{prefix}.operator",
                suggestion=f"Expected one of: {', '.join(sorted(_VALID_OPERATORS))}",
            )
        )

    # AZ326: FD-only operator used with App Gateway
    if (
        _WAF_TYPE.get() == "app_gateway"
        and isinstance(operator, str)
        and operator in _FD_ONLY_OPERATORS
    ):
        results.append(
            lint_result(
                "AZ326",
                Severity.ERROR,
                f"{prefix}: operator {operator!r} is only supported on"
                " Front Door, not Application Gateway",
                phase,
                ref=ref,
                field=f"{prefix}.operator",
            )
        )

    # AZ021: negateCondition must be bool
    negate = cond.get("negateCondition")
    if negate is not None and not isinstance(negate, bool):
        results.append(
            lint_result(
                "AZ021",
                Severity.ERROR,
                f"{prefix}: negateCondition must be a boolean, got {type(negate).__name__}",
                phase,
                ref=ref,
                field=f"{prefix}.negateCondition",
            )
        )

    # AZ324: negated Any operator always false (rule never matches)
    if operator == "Any" and negate is True:
        results.append(
            lint_result(
                "AZ324",
                Severity.WARNING,
                f"{prefix}: negated Any operator never matches (always false)",
                phase,
                ref=ref,
                field=f"{prefix}.operator",
                suggestion="Remove negateCondition or change the operator",
            )
        )

    # AZ325: Any operator with non-empty matchValue (values are ignored)
    match_value = cond.get("matchValue")
    if operator == "Any" and isinstance(match_value, list) and len(match_value) > 0:
        results.append(
            lint_result(
                "AZ325",
                Severity.WARNING,
                f"{prefix}: matchValue is ignored when operator is Any",
                phase,
                ref=ref,
                field=f"{prefix}.matchValue",
                suggestion="Use an empty list [] or remove matchValue for Any operator",
            )
        )

    # AZ312/AZ313: matchValue
    if operator and operator != "Any":
        if not isinstance(match_value, list) or len(match_value) == 0:
            results.append(
                lint_result(
                    "AZ312",
                    Severity.ERROR,
                    f"{prefix}: matchValue required for operator {operator!r}",
                    phase,
                    ref=ref,
                    field=f"{prefix}.matchValue",
                )
            )
        elif isinstance(match_value, list):
            if operator == "IPMatch":
                if len(match_value) > _MAX_IP_MATCH_VALUES:
                    results.append(
                        lint_result(
                            "AZ313",
                            Severity.ERROR,
                            f"{prefix}: matchValue has {len(match_value)} entries,"
                            f" exceeding IPMatch limit of {_MAX_IP_MATCH_VALUES}",
                            phase,
                            ref=ref,
                            field=f"{prefix}.matchValue",
                        )
                    )
                # AZ318/AZ319/AZ322: Validate CIDRs
                for val in match_value:
                    if isinstance(val, str):
                        _check_cidr(val, results, phase, ref, prefix)
                        _check_cidr_catch_all(val, results, phase, ref, prefix)
                        _check_cidr_private(val, results, phase, ref, prefix)
                # AZ338: Redundant/overlapping CIDRs
                _check_redundant_cidrs(match_value, results, phase, ref, prefix)
            elif len(match_value) > _MAX_STRING_MATCH_VALUES:
                results.append(
                    lint_result(
                        "AZ313",
                        Severity.ERROR,
                        f"{prefix}: matchValue has {len(match_value)} entries,"
                        f" exceeding string match limit of {_MAX_STRING_MATCH_VALUES}",
                        phase,
                        ref=ref,
                        field=f"{prefix}.matchValue",
                    )
                )

    # AZ317: Validate regex patterns
    if operator == "RegEx" and isinstance(match_value, list):
        for val in match_value:
            if isinstance(val, str):
                try:
                    re.compile(val)
                except re.error as exc:
                    results.append(
                        lint_result(
                            "AZ317",
                            Severity.ERROR,
                            f"{prefix}: invalid regex pattern {val!r}: {exc}",
                            phase,
                            ref=ref,
                            field=f"{prefix}.matchValue",
                        )
                    )
        # AZ342: Overly-permissive regex
        for val in match_value:
            if isinstance(val, str) and val in _OVERLY_PERMISSIVE_REGEX:
                results.append(
                    lint_result(
                        "AZ342",
                        Severity.WARNING,
                        f"{prefix}: regex pattern {val!r} matches every value;"
                        " this rule has effectively no condition",
                        phase,
                        ref=ref,
                        field=f"{prefix}.matchValue",
                        suggestion="Use a more specific pattern, or remove the rule"
                        " if match-all behavior is intentional",
                    )
                )
        # AZ343: Fully-anchored literal regex
        for val in match_value:
            if isinstance(val, str) and _FULLY_ANCHORED_LITERAL_REGEX.match(val):
                results.append(
                    lint_result(
                        "AZ343",
                        Severity.INFO,
                        f"{prefix}: regex pattern {val!r} is a fully-anchored literal;"
                        " use the Equal operator instead",
                        phase,
                        ref=ref,
                        field=f"{prefix}.matchValue",
                        suggestion="Replace operator RegEx with Equal and use the literal"
                        " value (without anchors or escapes) as matchValue",
                    )
                )
    # AZ344: RequestMethod uppercase
    if variable == "RequestMethod" and isinstance(match_value, list):
        for val in match_value:
            if isinstance(val, str) and any(c.islower() for c in val):
                results.append(
                    lint_result(
                        "AZ344",
                        Severity.WARNING,
                        f"{prefix}: HTTP method {val!r} contains lowercase letters;"
                        " Azure method matching is case-sensitive",
                        phase,
                        ref=ref,
                        field=f"{prefix}.matchValue",
                        suggestion=f"Use uppercase: {val.upper()!r}",
                    )
                )

    # AZ345: RequestHeader/Cookies selector lowercase
    if (
        isinstance(variable, str)
        and variable in {"RequestHeader", "Cookies"}
        and isinstance(cond.get("selector"), str)
    ):
        selector = cond.get("selector")
        if any(c.isupper() for c in selector):
            results.append(
                lint_result(
                    "AZ345",
                    Severity.INFO,
                    f"{prefix}: selector {selector!r} contains uppercase letters;"
                    " use lowercase for RFC-style header/cookie names",
                    phase,
                    ref=ref,
                    field=f"{prefix}.selector",
                    suggestion=f"Use lowercase: {selector.lower()!r}",
                )
            )

    # AZ320/AZ323: GeoMatch country codes
    if operator == "GeoMatch" and isinstance(match_value, list):
        for val in match_value:
            if isinstance(val, str) and not _COUNTRY_CODE_RE.match(val):
                results.append(
                    lint_result(
                        "AZ320",
                        Severity.WARNING,
                        f"{prefix}: unknown country code {val!r} in GeoMatch",
                        phase,
                        ref=ref,
                        field=f"{prefix}.matchValue",
                    )
                )
        if len(match_value) >= _MAX_GEO_COUNTRY_CODES:
            results.append(
                lint_result(
                    "AZ323",
                    Severity.WARNING,
                    f"{prefix}: GeoMatch has {len(match_value)} country codes"
                    " (likely matches almost all traffic)",
                    phase,
                    ref=ref,
                    field=f"{prefix}.matchValue",
                )
            )

    # AZ314: transforms
    transforms = cond.get("transforms")
    if isinstance(transforms, list):
        for t in transforms:
            if isinstance(t, str) and t not in _VALID_TRANSFORMS:
                results.append(
                    lint_result(
                        "AZ314",
                        Severity.ERROR,
                        f"{prefix}: invalid transform {t!r}",
                        phase,
                        ref=ref,
                        field=f"{prefix}.transforms",
                        suggestion=f"Expected one of: {', '.join(sorted(_VALID_TRANSFORMS))}",
                    )
                )

    # AZ328: AG-only transform used with Front Door
    if _WAF_TYPE.get() == "front_door" and isinstance(transforms, list):
        for t in transforms:
            if isinstance(t, str) and t in _AG_ONLY_TRANSFORMS:
                results.append(
                    lint_result(
                        "AZ328",
                        Severity.ERROR,
                        f"{prefix}: transform {t!r} is only supported on"
                        " Application Gateway, not Front Door",
                        phase,
                        ref=ref,
                        field=f"{prefix}.transforms",
                    )
                )

    # AZ333: transforms on operators where they have no effect
    if (
        isinstance(transforms, list)
        and transforms
        and isinstance(operator, str)
        and operator in _NO_TRANSFORM_OPERATORS
    ):
        results.append(
            lint_result(
                "AZ333",
                Severity.WARNING,
                f"{prefix}: transforms have no effect with operator {operator!r}",
                phase,
                ref=ref,
                field=f"{prefix}.transforms",
                suggestion="Remove transforms or change the operator",
            )
        )

    # AZ335: empty string in matchValue (almost certainly a bug for string operators)
    if (
        isinstance(match_value, list)
        and operator in _STRING_OPERATORS
        and any(isinstance(v, str) and v == "" for v in match_value)
    ):
        results.append(
            lint_result(
                "AZ335",
                Severity.WARNING,
                f"{prefix}: matchValue contains an empty string",
                phase,
                ref=ref,
                field=f"{prefix}.matchValue",
                suggestion="Remove the empty string or replace with a meaningful value",
            )
        )

    # AZ334: duplicate matchValue entries
    if isinstance(match_value, list) and len(match_value) >= 2:
        seen_vals: set[str] = set()
        for val in match_value:
            if isinstance(val, str):
                lower = (
                    val.lower() if operator in _STRING_OPERATORS or operator == "IPMatch" else val
                )
                if lower in seen_vals:
                    results.append(
                        lint_result(
                            "AZ334",
                            Severity.WARNING,
                            f"{prefix}: duplicate matchValue entry {val!r}",
                            phase,
                            ref=ref,
                            field=f"{prefix}.matchValue",
                        )
                    )
                    break  # one per condition
                seen_vals.add(lower)

    # AZ330: Redundant/conflicting transforms
    if isinstance(transforms, list) and len(transforms) >= 2:
        transform_set = set(transforms)
        for a, b in _CONFLICTING_TRANSFORMS:
            if a in transform_set and b in transform_set:
                results.append(
                    lint_result(
                        "AZ330",
                        Severity.WARNING,
                        f"{prefix}: conflicting transforms {a} and {b} cancel each other",
                        phase,
                        ref=ref,
                        field=f"{prefix}.transforms",
                    )
                )
                break  # One warning per condition
        # Duplicate transforms
        if len(transforms) != len(transform_set):
            seen_t: set[str] = set()
            for t in transforms:
                if t in seen_t:
                    results.append(
                        lint_result(
                            "AZ330",
                            Severity.WARNING,
                            f"{prefix}: duplicate transform {t!r}",
                            phase,
                            ref=ref,
                            field=f"{prefix}.transforms",
                        )
                    )
                    break
                seen_t.add(t)

    # AZ331: matchValue type validation (all entries must be strings)
    if isinstance(match_value, list):
        for j, val in enumerate(match_value):
            if not isinstance(val, str):
                results.append(
                    lint_result(
                        "AZ331",
                        Severity.ERROR,
                        f"{prefix}: matchValue[{j}] must be a string, got {type(val).__name__}",
                        phase,
                        ref=ref,
                        field=f"{prefix}.matchValue[{j}]",
                    )
                )
                break  # One error per condition is enough

    # AZ332: Regex pattern length
    if operator == "RegEx" and isinstance(match_value, list):
        for val in match_value:
            if isinstance(val, str) and len(val) > _MAX_REGEX_PATTERN_LEN:
                results.append(
                    lint_result(
                        "AZ332",
                        Severity.WARNING,
                        f"{prefix}: regex pattern is {len(val)} chars,"
                        f" exceeding {_MAX_REGEX_PATTERN_LEN} (octorules guidance"
                        " — Azure publishes no regex length limit)",
                        phase,
                        ref=ref,
                        field=f"{prefix}.matchValue",
                    )
                )


def _check_cidr(val: str, results: list[LintResult], phase: str, ref: str, prefix: str) -> None:
    """AZ318/AZ337: Validate a single CIDR/IP value."""
    if "/" in val:
        # AZ337: Check for host bits set (returns normalized CIDR if present)
        normalized = normalize_host_bits(val)
        if normalized is not None:
            results.append(
                lint_result(
                    "AZ337",
                    Severity.WARNING,
                    f"{prefix}: CIDR has host bits set: {val!r} (did you mean {normalized}?)",
                    phase,
                    ref=ref,
                    field=f"{prefix}.matchValue",
                )
            )
            return
        # AZ318: Invalid CIDR (failed both strict and non-strict parsing)
        try:
            ipaddress.ip_network(val, strict=True)
        except ValueError:
            results.append(
                lint_result(
                    "AZ318",
                    Severity.WARNING,
                    f"{prefix}: invalid CIDR/IP {val!r}",
                    phase,
                    ref=ref,
                    field=f"{prefix}.matchValue",
                )
            )
    else:
        try:
            ipaddress.ip_address(val)
        except ValueError:
            results.append(
                lint_result(
                    "AZ318",
                    Severity.WARNING,
                    f"{prefix}: invalid CIDR/IP {val!r}",
                    phase,
                    ref=ref,
                    field=f"{prefix}.matchValue",
                )
            )


def _check_cidr_catch_all(
    val: str, results: list[LintResult], phase: str, ref: str, prefix: str
) -> None:
    """AZ322: Warn on catch-all CIDR ranges (0.0.0.0/0 or ::/0)."""
    if val in CATCH_ALL_CIDRS:
        results.append(
            lint_result(
                "AZ322",
                Severity.WARNING,
                f"{prefix}: {val} matches all traffic (catch-all CIDR)",
                phase,
                ref=ref,
                field=f"{prefix}.matchValue",
            )
        )


def _check_cidr_private(
    val: str, results: list[LintResult], phase: str, ref: str, prefix: str
) -> None:
    """AZ319: Warn when a private/reserved IP range is used in IPMatch.

    Uses strict containment (``val`` is a subset of a reserved range) —
    aligned with the other four providers.  The catch-all
    ``0.0.0.0/0`` / ``::/0`` case is handled separately by AZ322 so we
    don't double-flag it here.

    Severity is WARNING to match the peer rules WA162, GA320, CF530,
    BN305 — all reserved/bogon IP detectors should agree.
    """
    desc = is_reserved(val)
    if desc is None:
        return
    results.append(
        lint_result(
            "AZ319",
            Severity.WARNING,
            f"{prefix}: {val} is a {desc} range (typically not seen in public WAF traffic)",
            phase,
            ref=ref,
            field=f"{prefix}.matchValue",
        )
    )


def _check_redundant_cidrs(
    values: list[str], results: list[LintResult], phase: str, ref: str, prefix: str
) -> None:
    """AZ338: Detect overlapping CIDRs where one is a subnet of another.

    Uses find_overlapping_cidrs for O(n log n) sweep-line detection across
    both IPv4 and IPv6. Invalid CIDRs are silently skipped (AZ318 reports them).
    """
    items: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []

    for val in values:
        if not isinstance(val, str):
            continue
        try:
            if "/" in val:
                net = ipaddress.ip_network(val, strict=False)
            else:
                suffix = "/32" if ":" not in val else "/128"
                net = ipaddress.ip_network(val + suffix, strict=False)
        except ValueError:
            continue  # AZ318 handles invalid CIDRs
        items.append((val, net))

    # find_overlapping_cidrs returns all (value, net, parent_value, parent_net) tuples
    # where net is contained in or equal to parent_net. Report only the first.
    for val, net, parent_val, parent_net in find_overlapping_cidrs(items):
        if net == parent_net:
            # Exact duplicate (AZ334 handles this, but report for completeness)
            continue
        results.append(
            lint_result(
                "AZ338",
                Severity.WARNING,
                f"{prefix}: redundant CIDR in matchValue: {val} is a subnet of {parent_val}",
                phase,
                ref=ref,
                field=f"{prefix}.matchValue",
            )
        )
        return  # One warning per condition


def _check_duplicate_variable_operator(
    conditions: list[dict], results: list[LintResult], phase: str, ref: str
) -> None:
    """AZ336: Multiple conditions on same matchVariable+operator.

    Since conditions are ANDed, two IPMatch conditions on RemoteAddr mean
    the IP must be in BOTH lists (intersection), which is almost never the
    intent.  Users usually want OR (union), which requires separate rules.
    """
    seen: dict[tuple[str, str], int] = {}
    for cond in conditions:
        if not isinstance(cond, dict):
            continue
        var = cond.get("matchVariable", "")
        op = cond.get("operator", "")
        if not var or not op or op == "Any":
            continue
        key = (var, op)
        seen[key] = seen.get(key, 0) + 1

    for (var, op), count in seen.items():
        if count > 1:
            results.append(
                lint_result(
                    "AZ336",
                    Severity.WARNING,
                    f"Multiple conditions use {var}+{op} (AND logic = intersection,"
                    " not union); use separate rules for OR logic",
                    phase,
                    ref=ref,
                    field="matchConditions",
                )
            )


def _check_rate_fields_on_match_rule(
    rule: dict, results: list[LintResult], phase: str, ref: str
) -> None:
    """AZ411: Rate-limit fields on a MatchRule (ignored by Azure, likely confusion)."""
    if rule.get("ruleType") == "RateLimitRule":
        return
    rate_fields = []
    if "rateLimitDurationInMinutes" in rule:
        rate_fields.append("rateLimitDurationInMinutes")
    if "rateLimitThreshold" in rule:
        rate_fields.append("rateLimitThreshold")
    if "groupBy" in rule:
        group_by = rule["groupBy"]
        if isinstance(group_by, list) and group_by:
            rate_fields.append("groupBy")
    if rate_fields:
        results.append(
            lint_result(
                "AZ411",
                Severity.WARNING,
                f"Rate-limit fields ({', '.join(rate_fields)}) on a MatchRule"
                " are ignored; set ruleType to RateLimitRule or remove them",
                phase,
                ref=ref,
                field="ruleType",
            )
        )


def _check_rate_limit(rule: dict, results: list[LintResult], phase: str, ref: str) -> None:
    """AZ400-AZ403: Validate rate limit fields for RateLimitRule."""
    rule_type = rule.get("ruleType")
    if rule_type != "RateLimitRule":
        return

    # AZ400: rateLimitDurationInMinutes
    duration = rule.get("rateLimitDurationInMinutes")
    if duration is None:
        results.append(
            lint_result(
                "AZ400",
                Severity.ERROR,
                "RateLimitRule missing 'rateLimitDurationInMinutes'",
                phase,
                ref=ref,
                field="rateLimitDurationInMinutes",
            )
        )
    elif not is_strict_int(duration) or duration not in _VALID_RATE_DURATIONS:
        results.append(
            lint_result(
                "AZ400",
                Severity.ERROR,
                f"Invalid rateLimitDurationInMinutes: {duration!r}",
                phase,
                ref=ref,
                field="rateLimitDurationInMinutes",
                suggestion=f"Valid: {sorted(_VALID_RATE_DURATIONS)}",
            )
        )

    # AZ401/AZ403: rateLimitThreshold
    threshold = rule.get("rateLimitThreshold")
    if threshold is None:
        results.append(
            lint_result(
                "AZ401",
                Severity.ERROR,
                "RateLimitRule missing 'rateLimitThreshold'",
                phase,
                ref=ref,
                field="rateLimitThreshold",
            )
        )
    elif not is_strict_int(threshold):
        results.append(
            lint_result(
                "AZ401",
                Severity.ERROR,
                f"rateLimitThreshold must be an integer, got {type(threshold).__name__}",
                phase,
                ref=ref,
                field="rateLimitThreshold",
            )
        )
    elif threshold < _RATE_THRESHOLD_MIN:
        results.append(
            lint_result(
                "AZ403",
                Severity.ERROR,
                f"rateLimitThreshold ({threshold}) below minimum of {_RATE_THRESHOLD_MIN}",
                phase,
                ref=ref,
                field="rateLimitThreshold",
            )
        )

    # AZ402: groupBy
    group_by = rule.get("groupBy")
    if isinstance(group_by, list):
        for entry in group_by:
            if isinstance(entry, dict):
                var_name = entry.get("variableName", "")
                if var_name not in _VALID_GROUP_BY_VARIABLES:
                    results.append(
                        lint_result(
                            "AZ402",
                            Severity.ERROR,
                            f"Invalid groupBy variable {var_name!r}",
                            phase,
                            ref=ref,
                            field="groupBy",
                            suggestion=(
                                f"Expected one of: {', '.join(sorted(_VALID_GROUP_BY_VARIABLES))}"
                            ),
                        )
                    )


def _check_enabled_state(rule: dict, results: list[LintResult], phase: str, ref: str) -> None:
    """AZ005/AZ600: Validate enabledState value and info when disabled."""
    enabled_state = rule.get("enabledState")
    if enabled_state is None:
        return  # Optional field
    if enabled_state not in _VALID_ENABLED_STATES:
        results.append(
            lint_result(
                "AZ005",
                Severity.ERROR,
                f"Invalid enabledState {enabled_state!r}",
                phase,
                ref=ref,
                suggestion="Valid: ['Disabled', 'Enabled']",
                field="enabledState",
            )
        )
    elif enabled_state == "Disabled":
        results.append(
            lint_result(
                "AZ600",
                Severity.INFO,
                "Rule is disabled (enabledState: Disabled)",
                phase,
                ref=ref,
                field="enabledState",
            )
        )


def _check_rule_type(rule: dict, results: list[LintResult], phase: str, ref: str) -> None:
    """AZ006, AZ027: Validate ruleType value."""
    rule_type = rule.get("ruleType")
    if rule_type is None:
        return  # Optional field
    _check_whitespace_structural_field("ruleType", rule_type, results, phase, ref)
    if rule_type not in _VALID_RULE_TYPES:
        results.append(
            lint_result(
                "AZ006",
                Severity.ERROR,
                f"Invalid ruleType {rule_type!r}",
                phase,
                suggestion=f"Valid: {sorted(_VALID_RULE_TYPES)}",
                ref=ref,
                field="ruleType",
            )
        )


def _check_action_log(rule: dict, results: list[LintResult], phase: str, ref: str) -> None:
    """AZ601: Info when action is Log (doesn't block or allow)."""
    if rule.get("action") == "Log":
        results.append(
            lint_result(
                "AZ601",
                Severity.INFO,
                "Log action does not block or allow -- traffic continues to next rule",
                phase,
                ref=ref,
                field="action",
            )
        )


def _check_unknown_fields(rule: dict, results: list[LintResult], phase: str, ref: str) -> None:
    """AZ020: Warn on unknown top-level fields."""
    for key in rule:
        if key not in _VALID_RULE_FIELDS:
            results.append(
                lint_result(
                    "AZ020",
                    Severity.WARNING,
                    f"Unknown top-level rule field {key!r}",
                    phase,
                    ref=ref,
                    field=key,
                )
            )


# ---------------------------------------------------------------------------
# Cross-rule checks
# ---------------------------------------------------------------------------
def _check_duplicate_priorities(
    seen: dict[int, list[str]], results: list[LintResult], phase: str
) -> None:
    """AZ101: Duplicate priorities."""
    for priority, refs in find_duplicate_priorities(seen):
        results.append(
            lint_result(
                "AZ101",
                Severity.ERROR,
                f"Duplicate priority {priority}: {', '.join(refs)}",
                phase,
            )
        )


def _check_duplicate_refs(seen: dict[str, int], results: list[LintResult], phase: str) -> None:
    """AZ022: Duplicate refs."""
    for ref, count in sorted(seen.items()):
        if count > 1 and ref:
            results.append(
                lint_result(
                    "AZ022",
                    Severity.ERROR,
                    f"Duplicate ref {ref!r} appears {count} times",
                    phase,
                    ref=ref,
                )
            )


def _check_priority_gaps(seen: dict[int, list[str]], results: list[LintResult], phase: str) -> None:
    """AZ102: Non-contiguous priorities (info)."""
    gap = find_first_priority_gap(seen.keys())
    if gap is not None:
        results.append(
            lint_result(
                "AZ102",
                Severity.INFO,
                f"Non-contiguous priorities: gap between {gap[0]} and {gap[1]}",
                phase,
            )
        )


def _is_catch_all_condition(cond: dict) -> bool:
    """True if a single condition matches all traffic."""
    if not isinstance(cond, dict):
        return False
    operator = cond.get("operator")
    negate = cond.get("negateCondition", False)
    if operator == "Any" and not negate:
        return True
    # IPMatch with 0.0.0.0/0 or ::/0 is effectively Any
    if operator == "IPMatch" and not negate:
        values = cond.get("matchValue", [])
        if isinstance(values, list) and any(v in CATCH_ALL_CIDRS for v in values):
            return True
    return False


def _is_catch_all_rule(rule: dict) -> bool:
    """True if a rule matches all traffic.

    A rule is catch-all when ALL conditions match everything (since conditions
    are ANDed).  Each condition is catch-all if it uses ``Any`` operator or
    ``IPMatch`` with ``0.0.0.0/0`` or ``::/0``.
    """
    conditions = rule.get("matchConditions")
    if not isinstance(conditions, list) or not conditions:
        return False
    return all(_is_catch_all_condition(c) for c in conditions)


def _check_catch_all_and_dead_rules(
    rules: list[dict], results: list[LintResult], phase: str
) -> None:
    """AZ340/AZ341: Detect catch-all rules and unreachable rules after them.

    A catch-all rule (all conditions use ``Any`` operator) with a terminal
    action (Allow, Block, Redirect, JSChallenge) prevents lower-priority
    rules from executing.
    """
    _TERMINAL_ACTIONS = frozenset({"Allow", "Block", "Redirect", "JSChallenge"})

    # Sort by priority to evaluate in execution order
    priority_rules = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        priority = rule.get("priority")
        if is_strict_int(priority) and priority >= 1:
            priority_rules.append((priority, rule))
    priority_rules.sort(key=lambda x: x[0])

    first_catch_all_priority: int | None = None
    first_catch_all_ref = ""

    for priority, rule in priority_rules:
        ref = str(rule.get("ref", ""))
        action = rule.get("action", "")

        if first_catch_all_priority is not None and priority > first_catch_all_priority:
            results.append(
                lint_result(
                    "AZ341",
                    Severity.WARNING,
                    f"Rule is unreachable: catch-all rule {first_catch_all_ref!r}"
                    f" at priority {first_catch_all_priority} blocks all subsequent rules",
                    phase,
                    ref=ref,
                )
            )
            continue

        if _is_catch_all_rule(rule) and action in _TERMINAL_ACTIONS:
            results.append(
                lint_result(
                    "AZ340",
                    Severity.WARNING,
                    f"Catch-all rule matches all traffic with action {action!r}",
                    phase,
                    ref=ref,
                    suggestion="Ensure this is intentional; all lower-priority rules"
                    " will be unreachable",
                )
            )
            if first_catch_all_priority is None:
                first_catch_all_priority = priority
                first_catch_all_ref = ref


def _check_rate_without_condition(
    rule: dict, results: list[LintResult], phase: str, ref: str
) -> None:
    """AZ410: Rate-limit rule where all conditions use Any (matches all traffic)."""
    if rule.get("ruleType") != "RateLimitRule":
        return
    if _is_catch_all_rule(rule):
        results.append(
            lint_result(
                "AZ410",
                Severity.WARNING,
                "RateLimitRule matches all traffic (all conditions use Any operator);"
                " consider adding a meaningful condition",
                phase,
                ref=ref,
                field="matchConditions",
            )
        )


def _check_all_disabled(rules: list[dict], results: list[LintResult], phase: str) -> None:
    """AZ602: Warn when all rules in a phase are disabled."""
    if not rules:
        return
    valid_rules = [r for r in rules if isinstance(r, dict)]
    if not valid_rules:
        return
    if all(r.get("enabledState") == "Disabled" for r in valid_rules):
        results.append(
            lint_result(
                "AZ602",
                Severity.WARNING,
                f"All {len(valid_rules)} rules in phase are disabled",
                phase,
            )
        )


def _check_allow_bypasses_managed(rules: list[dict], results: list[LintResult], phase: str) -> None:
    """AZ603: Info when an Allow catch-all rule bypasses all managed rules."""
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if rule.get("action") != "Allow":
            continue
        if _is_catch_all_rule(rule):
            ref = str(rule.get("ref", ""))
            results.append(
                lint_result(
                    "AZ603",
                    Severity.INFO,
                    "Allow catch-all rule bypasses all managed rules (OWASP DRS, bot protection)",
                    phase,
                    ref=ref,
                    suggestion="Ensure this is intentional; managed rules will not evaluate"
                    " for matched traffic",
                )
            )


def _check_cross_rule_cidr_overlaps(
    rules: list[dict], results: list[LintResult], phase: str
) -> None:
    """AZ339: Detect CIDR overlap across rules in the same phase.

    Azure WAF rules use inline IP arrays per ``IPMatch`` condition.  When two
    rules in the same policy reference overlapping CIDRs on the same
    ``matchVariable``, the broader rule shadows the narrower one (rules are
    evaluated by priority).  Without this check, that shadowing is silent.

    Algorithm: collect every CIDR from ``IPMatch`` conditions across all
    rules, group by ``(matchVariable, ip_version)``, sweep-line in
    ``O(n log n)``.  Catch-all entries (``0.0.0.0/0`` / ``::/0``) are
    excluded — those are AZ322's domain.  Each contained CIDR is reported
    once against the rule whose broader CIDR contains it.

    Mirrors CF478 (Cloudflare), WA164 (AWS), GA305 (Google), BN307 (Bunny).
    """
    # Collect: (rule_ref, match_variable, cidr_str, parsed_network)
    entries: list[tuple[str, str, str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        ref = str(rule.get("ref", ""))
        for cond in rule.get("matchConditions", []) or []:
            if not isinstance(cond, dict):
                continue
            if cond.get("operator") != "IPMatch":
                continue
            mvar = str(cond.get("matchVariable", ""))
            for val in cond.get("matchValue", []) or []:
                if not isinstance(val, str):
                    continue
                if val in CATCH_ALL_CIDRS:
                    continue  # AZ322's domain
                try:
                    if "/" in val:
                        net = ipaddress.ip_network(val, strict=False)
                    else:
                        suffix = "/32" if ":" not in val else "/128"
                        net = ipaddress.ip_network(val + suffix, strict=False)
                except ValueError:
                    continue  # AZ318 handles invalid CIDRs
                entries.append((ref, mvar, val, net))

    if len(entries) < 2:
        return

    # Group by (match_variable, ip_version). IPv4 and IPv6 can't overlap;
    # neither can different match variables (RemoteAddr vs SocketAddr are
    # distinct enforcement points).
    from collections import defaultdict

    groups: dict[
        tuple[str, int],
        list[tuple[str, str, ipaddress.IPv4Network | ipaddress.IPv6Network]],
    ] = defaultdict(list)
    for ref, mvar, cidr, net in entries:
        groups[(mvar, net.version)].append((ref, cidr, net))

    seen_pairs: set[tuple[str, str, str, str]] = set()
    for items in groups.values():
        if len(items) < 2:
            continue
        # Sort: broadest first when network addresses are equal — that
        # places the containing CIDR on the active stack before any
        # contained ones.
        items_sorted = sorted(items, key=lambda x: (int(x[2].network_address), x[2].prefixlen))
        active: list[tuple[str, str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
        for ref, cidr, net in items_sorted:
            while active and int(active[-1][2].broadcast_address) < int(net.network_address):
                active.pop()
            if active:
                parent_ref, parent_cidr, parent_net = active[-1]
                # Same rule contributing both entries is AZ338's domain
                # (within-rule redundancy). Skip here to avoid double-flag.
                if parent_ref != ref:
                    pair_key = (parent_ref, parent_cidr, ref, cidr)
                    if pair_key not in seen_pairs:
                        seen_pairs.add(pair_key)
                        if net == parent_net:
                            msg = (
                                f"Duplicate CIDR across rules: {cidr!r} in"
                                f" {ref!r} also appears in {parent_ref!r}"
                            )
                        else:
                            msg = (
                                f"Overlapping CIDR across rules: {cidr!r} in"
                                f" {ref!r} is contained in {parent_cidr!r} from"
                                f" {parent_ref!r}"
                            )
                        results.append(
                            lint_result(
                                "AZ339",
                                Severity.WARNING,
                                msg,
                                phase,
                                ref=ref,
                                field="matchConditions.matchValue",
                                suggestion=(
                                    "Remove the redundant rule, or reorder so"
                                    f" {ref!r} (narrower) takes priority over"
                                    f" {parent_ref!r}"
                                ),
                            )
                        )
            active.append((ref, cidr, net))


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def validate_rules(rules: list[dict], *, phase: str = "") -> list[LintResult]:
    """Validate normalised Azure WAF rules.

    Returns a list of :class:`LintResult` objects (empty = valid).
    """
    results: list[LintResult] = []
    seen_priorities: dict[int, list[str]] = {}
    seen_refs: dict[str, int] = {}

    for rule in rules:
        if not isinstance(rule, dict):
            results.append(lint_result("AZ023", Severity.ERROR, "Rule entry is not a dict", phase))
            continue

        ref = _check_ref(rule, results, phase)
        if ref:
            seen_refs[ref] = seen_refs.get(ref, 0) + 1

        _check_priority(rule, results, phase, ref, seen_priorities)
        _check_action(rule, results, phase, ref)
        _check_match_conditions(rule, results, phase, ref)

        _check_rate_limit(rule, results, phase, ref)
        _check_rate_without_condition(rule, results, phase, ref)
        _check_rate_fields_on_match_rule(rule, results, phase, ref)
        _check_enabled_state(rule, results, phase, ref)
        _check_rule_type(rule, results, phase, ref)
        _check_action_log(rule, results, phase, ref)
        _check_unknown_fields(rule, results, phase, ref)

    # Cross-rule checks
    _check_duplicate_priorities(seen_priorities, results, phase)
    _check_duplicate_refs(seen_refs, results, phase)
    _check_priority_gaps(seen_priorities, results, phase)
    _check_catch_all_and_dead_rules(rules, results, phase)
    _check_all_disabled(rules, results, phase)
    _check_allow_bypasses_managed(rules, results, phase)
    _check_cross_rule_cidr_overlaps(rules, results, phase)
    # Note: AZ500 (regex limit) and AZ501 (total rule count) are checked
    # in the linter plugin as cross-phase checks, since Azure limits are
    # per-policy not per-phase.

    return results


# ---------------------------------------------------------------------------
# Managed rule set validation
# ---------------------------------------------------------------------------

# Valid ruleSetType values (Azure built-in managed rule sets).
_VALID_RULE_SET_TYPES = frozenset(
    {
        # Microsoft DRS (Default Rule Set) — Front Door + App Gateway
        "Microsoft_DefaultRuleSet",
        # OWASP CRS — App Gateway
        "OWASP_CRS",
        # Bot Manager — Front Door
        "Microsoft_BotManagerRuleSet",
        # Bot Protection — App Gateway
        "BotProtection",
    }
)

# ruleSetAction is Front Door only (AG doesn't support it).
_VALID_RULE_SET_ACTIONS = frozenset({"Block", "Log", "Redirect"})

# Valid actions for individual managed rule overrides.
_VALID_OVERRIDE_ACTIONS = frozenset(
    {"Allow", "Block", "Log", "Redirect", "AnomalyScoring", "None", "JSChallenge"}
)

# Override actions restricted to Front Door (not valid for App Gateway).
_FD_ONLY_OVERRIDE_ACTIONS = frozenset({"Redirect"})


def _check_managed_ref(rule: dict, results: list[LintResult], phase: str) -> str:
    """AZ700: Managed rule set must have a valid ref (ruleSetType)."""
    ref = rule.get("ref")
    if ref is None or ref == "":
        results.append(
            lint_result(
                "AZ700", Severity.ERROR, "Managed rule set missing 'ref'", phase, field="ref"
            )
        )
        return ""
    return str(ref)


def _check_rule_set_type(rule: dict, results: list[LintResult], phase: str, ref: str) -> None:
    """AZ701: Validate ruleSetType value."""
    rst = rule.get("ruleSetType")
    if rst is None or rst == "":
        results.append(
            lint_result(
                "AZ701",
                Severity.ERROR,
                "Managed rule set missing 'ruleSetType'",
                phase,
                ref=ref,
                field="ruleSetType",
            )
        )
        return
    if not isinstance(rst, str):
        results.append(
            lint_result(
                "AZ701",
                Severity.ERROR,
                f"ruleSetType must be a string, got {type(rst).__name__}",
                phase,
                ref=ref,
                field="ruleSetType",
            )
        )
        return
    if rst not in _VALID_RULE_SET_TYPES:
        results.append(
            lint_result(
                "AZ701",
                Severity.WARNING,
                f"Unknown ruleSetType {rst!r}",
                phase,
                ref=ref,
                field="ruleSetType",
                suggestion=f"Known types: {', '.join(sorted(_VALID_RULE_SET_TYPES))}",
            )
        )


def _check_rule_set_version(rule: dict, results: list[LintResult], phase: str, ref: str) -> None:
    """AZ701: Validate ruleSetVersion (must be a non-empty string)."""
    ver = rule.get("ruleSetVersion")
    if ver is None or ver == "":
        results.append(
            lint_result(
                "AZ701",
                Severity.ERROR,
                "Managed rule set missing 'ruleSetVersion'",
                phase,
                ref=ref,
                field="ruleSetVersion",
            )
        )
        return
    if not isinstance(ver, str):
        results.append(
            lint_result(
                "AZ701",
                Severity.ERROR,
                f"ruleSetVersion must be a string, got {type(ver).__name__}",
                phase,
                ref=ref,
                field="ruleSetVersion",
            )
        )


def _check_rule_set_action(rule: dict, results: list[LintResult], phase: str, ref: str) -> None:
    """AZ702: Validate ruleSetAction (Front Door only)."""
    action = rule.get("ruleSetAction")
    if action is None:
        return  # Optional — AG doesn't have it
    waf_type = _WAF_TYPE.get()
    if waf_type == "app_gateway":
        results.append(
            lint_result(
                "AZ705",
                Severity.WARNING,
                "ruleSetAction is only supported on Front Door, not Application Gateway",
                phase,
                ref=ref,
                field="ruleSetAction",
            )
        )
        return
    if not isinstance(action, str) or action not in _VALID_RULE_SET_ACTIONS:
        results.append(
            lint_result(
                "AZ702",
                Severity.ERROR,
                f"Invalid ruleSetAction {action!r}",
                phase,
                ref=ref,
                suggestion=f"Valid: {sorted(_VALID_RULE_SET_ACTIONS)}",
                field="ruleSetAction",
            )
        )


def _check_managed_enabled_state(
    override: dict, results: list[LintResult], phase: str, ref: str, path: str
) -> None:
    """AZ703: Validate enabledState in a rule override."""
    state = override.get("enabledState")
    if state is None:
        return
    if state not in _VALID_ENABLED_STATES:
        results.append(
            lint_result(
                "AZ703",
                Severity.ERROR,
                f"{path}: invalid enabledState {state!r}",
                phase,
                suggestion="Valid: ['Disabled', 'Enabled']",
                ref=ref,
                field=f"{path}.enabledState",
            )
        )


def _check_managed_rule_override(
    override: dict, results: list[LintResult], phase: str, ref: str, path: str
) -> None:
    """AZ706/AZ707: Validate an individual rule override entry.

    Each entry must have a ``ruleId`` (non-empty string).  ``enabledState``
    and ``action`` are optional but validated when present.
    """
    # AZ706: ruleId must be a non-empty string
    rule_id = override.get("ruleId")
    if rule_id is None or rule_id == "":
        results.append(
            lint_result(
                "AZ706",
                Severity.ERROR,
                f"{path}: missing or empty ruleId",
                phase,
                ref=ref,
                field=f"{path}.ruleId",
            )
        )
    elif not isinstance(rule_id, str):
        results.append(
            lint_result(
                "AZ706",
                Severity.ERROR,
                f"{path}: ruleId must be a string, got {type(rule_id).__name__}",
                phase,
                ref=ref,
                field=f"{path}.ruleId",
            )
        )

    # AZ703: enabledState (delegated to existing helper)
    _check_managed_enabled_state(override, results, phase, ref, path)

    # AZ707: action (optional — validate when present)
    action = override.get("action")
    if action is not None:
        if not isinstance(action, str) or action not in _VALID_OVERRIDE_ACTIONS:
            results.append(
                lint_result(
                    "AZ707",
                    Severity.ERROR,
                    f"{path}: invalid action {action!r}",
                    phase,
                    suggestion=f"Valid: {sorted(_VALID_OVERRIDE_ACTIONS)}",
                    ref=ref,
                    field=f"{path}.action",
                )
            )
        # AZ708: FD-only override action used with App Gateway
        elif _WAF_TYPE.get() == "app_gateway" and action in _FD_ONLY_OVERRIDE_ACTIONS:
            results.append(
                lint_result(
                    "AZ708",
                    Severity.WARNING,
                    f"{path}: action {action!r} is only supported on"
                    " Front Door, not Application Gateway",
                    phase,
                    ref=ref,
                    field=f"{path}.action",
                )
            )


def _check_rule_group_overrides(
    rule: dict, results: list[LintResult], phase: str, ref: str
) -> None:
    """AZ704: Validate ruleGroupOverrides structure."""
    overrides = rule.get("ruleGroupOverrides")
    if overrides is None:
        return  # Optional
    if not isinstance(overrides, list):
        results.append(
            lint_result(
                "AZ704",
                Severity.ERROR,
                f"ruleGroupOverrides must be a list, got {type(overrides).__name__}",
                phase,
                ref=ref,
                field="ruleGroupOverrides",
            )
        )
        return
    for i, group in enumerate(overrides):
        if not isinstance(group, dict):
            results.append(
                lint_result(
                    "AZ704",
                    Severity.ERROR,
                    f"ruleGroupOverrides[{i}] must be a dict, got {type(group).__name__}",
                    phase,
                    ref=ref,
                    field=f"ruleGroupOverrides[{i}]",
                )
            )
            continue
        name = group.get("ruleGroupName")
        if not isinstance(name, str) or not name:
            results.append(
                lint_result(
                    "AZ704",
                    Severity.ERROR,
                    f"ruleGroupOverrides[{i}]: missing or empty ruleGroupName",
                    phase,
                    ref=ref,
                    field=f"ruleGroupOverrides[{i}].ruleGroupName",
                )
            )
        # Validate individual rule overrides within the group
        rules_list = group.get("rules")
        if rules_list is not None:
            if not isinstance(rules_list, list):
                results.append(
                    lint_result(
                        "AZ704",
                        Severity.ERROR,
                        f"ruleGroupOverrides[{i}].rules must be a list,"
                        f" got {type(rules_list).__name__}",
                        phase,
                        ref=ref,
                        field=f"ruleGroupOverrides[{i}].rules",
                    )
                )
            else:
                for j, rule_override in enumerate(rules_list):
                    if not isinstance(rule_override, dict):
                        continue
                    path = f"ruleGroupOverrides[{i}].rules[{j}]"
                    _check_managed_rule_override(rule_override, results, phase, ref, path)


def validate_managed_rules(rules: list[dict], *, phase: str = "") -> list[LintResult]:
    """Validate normalised Azure WAF managed rule sets.

    Returns a list of :class:`LintResult` objects (empty = valid).
    """
    results: list[LintResult] = []
    seen_refs: dict[str, int] = {}

    for rule in rules:
        if not isinstance(rule, dict):
            continue

        ref = _check_managed_ref(rule, results, phase)
        if ref:
            seen_refs[ref] = seen_refs.get(ref, 0) + 1

        _check_rule_set_type(rule, results, phase, ref)
        _check_rule_set_version(rule, results, phase, ref)
        _check_rule_set_action(rule, results, phase, ref)
        _check_rule_group_overrides(rule, results, phase, ref)

    # Cross-rule: duplicate refs
    for ref, count in sorted(seen_refs.items()):
        if count > 1 and ref:
            results.append(
                lint_result(
                    "AZ700",
                    Severity.ERROR,
                    f"Duplicate managed rule set ref {ref!r} appears {count} times",
                    phase,
                    ref=ref,
                )
            )

    return results
