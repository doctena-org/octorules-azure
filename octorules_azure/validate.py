"""Offline validation for Azure WAF rules.

Operates on the normalised internal form (Front Door canonical), so the
same validation logic works for both Front Door and Application Gateway.
"""

import ipaddress
import re
from contextvars import ContextVar

from octorules.linter.engine import LintResult, Severity


def _result(
    rule_id: str,
    severity: Severity,
    message: str,
    phase: str,
    ref: str = "",
    *,
    field: str = "",
    suggestion: str = "",
) -> LintResult:
    """Create a LintResult with common defaults."""
    return LintResult(
        rule_id=rule_id,
        severity=severity,
        message=message,
        phase=phase,
        ref=ref,
        field=field,
        suggestion=suggestion,
    )


def _is_strict_int(val: object) -> bool:
    """True if *val* is an int but not a bool."""
    return isinstance(val, int) and not isinstance(val, bool)


# ---------------------------------------------------------------------------
# Azure WAF constants
# ---------------------------------------------------------------------------
_MAX_MATCH_CONDITIONS = 10
_MAX_STRING_MATCH_VALUES = 10
_MAX_IP_MATCH_VALUES = 600
_MAX_NAME_LEN = 128
_FD_MAX_PRIORITY = 100
_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*$")

_VALID_ACTIONS = frozenset({"Allow", "Block", "Log", "Redirect", "AnomalyScoring", "JSChallenge"})

# waf_type-aware validation: features restricted to one WAF type.
_FD_ONLY_ACTIONS = frozenset({"Redirect", "AnomalyScoring", "JSChallenge"})
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
_RATE_THRESHOLD_MIN = 10
_RATE_THRESHOLD_MAX = 1_000_000

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
_CATCH_ALL_CIDRS = frozenset({"0.0.0.0/0", "::/0"})

# RFC 1918 + RFC 6598 + link-local + loopback.
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

# Transform pairs that conflict or are redundant when applied together.
_CONFLICTING_TRANSFORMS = frozenset(
    {
        ("Lowercase", "Uppercase"),
        ("Uppercase", "Lowercase"),
    }
)

# Maximum regex pattern length (Azure doesn't document a hard limit, but
# patterns over 256 chars are likely problematic and indicate configuration errors).
_MAX_REGEX_PATTERN_LEN = 256

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
    """AZ001, AZ010, AZ022: Validate ref field."""
    ref = rule.get("ref")
    if ref is None or ref == "":
        results.append(_result("AZ001", Severity.ERROR, "Rule missing 'ref'", phase, field="ref"))
        return ""
    ref_str = str(ref)
    if len(ref_str) > _MAX_NAME_LEN:
        results.append(
            _result(
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
            _result(
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
        results.append(_result("AZ002", Severity.ERROR, "Rule missing 'priority'", phase, ref=ref))
        return
    if not _is_strict_int(priority) or priority < 1:
        results.append(
            _result(
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

    # AZ103: Front Door priority range (1-100)
    if _WAF_TYPE.get() == "front_door" and priority > _FD_MAX_PRIORITY:
        results.append(
            _result(
                "AZ103",
                Severity.WARNING,
                f"Priority {priority} exceeds the Front Door maximum of {_FD_MAX_PRIORITY}",
                phase,
                ref=ref,
                field="priority",
            )
        )


def _check_action(rule: dict, results: list[LintResult], phase: str, ref: str) -> None:
    """AZ003, AZ200: Validate action field."""
    action = rule.get("action")
    if action is None or action == "":
        results.append(_result("AZ003", Severity.ERROR, "Rule missing 'action'", phase, ref=ref))
        return
    if not isinstance(action, str):
        results.append(
            _result(
                "AZ200",
                Severity.ERROR,
                f"action must be a string, got {type(action).__name__}",
                phase,
                ref=ref,
                field="action",
            )
        )
        return
    if action not in _VALID_ACTIONS:
        results.append(
            _result(
                "AZ200",
                Severity.ERROR,
                f"Invalid action {action!r}; expected one of: {', '.join(sorted(_VALID_ACTIONS))}",
                phase,
                ref=ref,
                field="action",
            )
        )
        return

    # AZ201: FD-only action used with App Gateway
    if _WAF_TYPE.get() == "app_gateway" and action in _FD_ONLY_ACTIONS:
        results.append(
            _result(
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
            _result(
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
            _result(
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
            _result(
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
            _result(
                "AZ301",
                Severity.ERROR,
                f"matchConditions has {len(conditions)} entries,"
                f" exceeding the maximum of {_MAX_MATCH_CONDITIONS}",
                phase,
                ref=ref,
                field="matchConditions",
            )
        )

    for i, cond in enumerate(conditions):
        if not isinstance(cond, dict):
            results.append(
                _result(
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
            _result(
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
            _result(
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
            _result(
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
                _result(
                    "AZ321",
                    Severity.WARNING,
                    f"{prefix}: selector {selector!r} is set but {variable} does not use selectors",
                    phase,
                    ref=ref,
                    field=f"{prefix}.selector",
                    suggestion="Remove selector or use RequestHeader/Cookies/PostArgs",
                )
            )

    # AZ315/AZ316: selector
    if isinstance(variable, str) and variable in _SELECTOR_VARIABLES:
        selector = cond.get("selector")
        if selector is None:
            results.append(
                _result(
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
                _result(
                    "AZ316",
                    Severity.WARNING,
                    f"{prefix}: selector is empty for {variable}",
                    phase,
                    ref=ref,
                    field=f"{prefix}.selector",
                )
            )

    # AZ311: operator
    operator = cond.get("operator")
    if not isinstance(operator, str) or not operator:
        results.append(
            _result(
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
            _result(
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
            _result(
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
            _result(
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
            _result(
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
            _result(
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
                _result(
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
                        _result(
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
                    _result(
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
                        _result(
                            "AZ317",
                            Severity.ERROR,
                            f"{prefix}: invalid regex pattern {val!r}: {exc}",
                            phase,
                            ref=ref,
                            field=f"{prefix}.matchValue",
                        )
                    )

    # AZ320/AZ323: GeoMatch country codes
    if operator == "GeoMatch" and isinstance(match_value, list):
        for val in match_value:
            if isinstance(val, str) and not _COUNTRY_CODE_RE.match(val):
                results.append(
                    _result(
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
                _result(
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
                    _result(
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
                    _result(
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
            _result(
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
            _result(
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
                        _result(
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
                    _result(
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
                        _result(
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
                    _result(
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
                    _result(
                        "AZ332",
                        Severity.WARNING,
                        f"{prefix}: regex pattern is {len(val)} chars,"
                        f" exceeding recommended limit of {_MAX_REGEX_PATTERN_LEN}",
                        phase,
                        ref=ref,
                        field=f"{prefix}.matchValue",
                    )
                )


def _check_cidr(val: str, results: list[LintResult], phase: str, ref: str, prefix: str) -> None:
    """AZ318/AZ337: Validate a single CIDR/IP value."""
    if "/" in val:
        try:
            ipaddress.ip_network(val, strict=True)
        except ValueError:
            # Host bits set — try non-strict to see if it's a normalizable CIDR
            try:
                net = ipaddress.ip_network(val, strict=False)
                results.append(
                    _result(
                        "AZ337",
                        Severity.WARNING,
                        f"{prefix}: CIDR has host bits set: {val!r} (did you mean {net}?)",
                        phase,
                        ref=ref,
                        field=f"{prefix}.matchValue",
                    )
                )
            except ValueError:
                results.append(
                    _result(
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
                _result(
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
    if val in _CATCH_ALL_CIDRS:
        results.append(
            _result(
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
    """AZ319: Info when private/reserved IP range is used in IPMatch."""
    try:
        if "/" in val:
            network = ipaddress.ip_network(val, strict=False)
        else:
            suffix = "/32" if ":" not in val else "/128"
            network = ipaddress.ip_network(val + suffix, strict=False)
    except ValueError:
        return  # AZ318 handles invalid CIDRs
    for private in _PRIVATE_NETWORKS:
        if network.version == private.version and (
            network.subnet_of(private) or private.subnet_of(network)
        ):
            results.append(
                _result(
                    "AZ319",
                    Severity.INFO,
                    f"{prefix}: {val} overlaps with private/reserved IP range {private}"
                    " (typically not seen in public WAF traffic)",
                    phase,
                    ref=ref,
                    field=f"{prefix}.matchValue",
                )
            )
            return


def _check_redundant_cidrs(
    values: list[str], results: list[LintResult], phase: str, ref: str, prefix: str
) -> None:
    """AZ338: Detect overlapping CIDRs where one is a subnet of another.

    Parses all valid CIDRs/IPs in *values*, groups by IP version, and checks
    each pair for subnet_of relationships.  Invalid CIDRs are silently
    skipped (AZ318 already reports them).
    """
    v4_nets: list[tuple[str, ipaddress.IPv4Network]] = []
    v6_nets: list[tuple[str, ipaddress.IPv6Network]] = []

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

        if isinstance(net, ipaddress.IPv4Network):
            v4_nets.append((val, net))
        else:
            v6_nets.append((val, net))

    for group in (v4_nets, v6_nets):
        for i, (raw_a, net_a) in enumerate(group):
            for raw_b, net_b in group[i + 1 :]:
                if net_a == net_b:
                    continue  # AZ334 handles exact duplicates
                if net_b.subnet_of(net_a):
                    results.append(
                        _result(
                            "AZ338",
                            Severity.WARNING,
                            f"{prefix}: redundant CIDR in matchValue:"
                            f" {raw_b} is a subnet of {raw_a}",
                            phase,
                            ref=ref,
                            field=f"{prefix}.matchValue",
                        )
                    )
                    return  # One warning per condition
                if net_a.subnet_of(net_b):
                    results.append(
                        _result(
                            "AZ338",
                            Severity.WARNING,
                            f"{prefix}: redundant CIDR in matchValue:"
                            f" {raw_a} is a subnet of {raw_b}",
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
                _result(
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
            _result(
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
            _result(
                "AZ400",
                Severity.ERROR,
                "RateLimitRule missing 'rateLimitDurationInMinutes'",
                phase,
                ref=ref,
                field="rateLimitDurationInMinutes",
            )
        )
    elif not _is_strict_int(duration) or duration not in _VALID_RATE_DURATIONS:
        results.append(
            _result(
                "AZ400",
                Severity.ERROR,
                f"rateLimitDurationInMinutes must be 1 or 5, got {duration!r}",
                phase,
                ref=ref,
                field="rateLimitDurationInMinutes",
            )
        )

    # AZ401/AZ403: rateLimitThreshold
    threshold = rule.get("rateLimitThreshold")
    if threshold is None:
        results.append(
            _result(
                "AZ401",
                Severity.ERROR,
                "RateLimitRule missing 'rateLimitThreshold'",
                phase,
                ref=ref,
                field="rateLimitThreshold",
            )
        )
    elif not _is_strict_int(threshold):
        results.append(
            _result(
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
            _result(
                "AZ403",
                Severity.ERROR,
                f"rateLimitThreshold ({threshold}) below minimum of {_RATE_THRESHOLD_MIN}",
                phase,
                ref=ref,
                field="rateLimitThreshold",
            )
        )
    elif threshold > _RATE_THRESHOLD_MAX:
        results.append(
            _result(
                "AZ401",
                Severity.ERROR,
                f"rateLimitThreshold ({threshold}) exceeds maximum of {_RATE_THRESHOLD_MAX}",
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
                        _result(
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
            _result(
                "AZ005",
                Severity.ERROR,
                f"Invalid enabledState {enabled_state!r}; expected 'Enabled' or 'Disabled'",
                phase,
                ref=ref,
                field="enabledState",
            )
        )
    elif enabled_state == "Disabled":
        results.append(
            _result(
                "AZ600",
                Severity.INFO,
                "Rule is disabled (enabledState: Disabled)",
                phase,
                ref=ref,
                field="enabledState",
            )
        )


def _check_rule_type(rule: dict, results: list[LintResult], phase: str, ref: str) -> None:
    """AZ006: Validate ruleType value."""
    rule_type = rule.get("ruleType")
    if rule_type is None:
        return  # Optional field
    if rule_type not in _VALID_RULE_TYPES:
        results.append(
            _result(
                "AZ006",
                Severity.ERROR,
                f"Invalid ruleType {rule_type!r}; expected 'MatchRule' or 'RateLimitRule'",
                phase,
                ref=ref,
                field="ruleType",
            )
        )


def _check_action_log(rule: dict, results: list[LintResult], phase: str, ref: str) -> None:
    """AZ601: Info when action is Log (doesn't block or allow)."""
    if rule.get("action") == "Log":
        results.append(
            _result(
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
                _result(
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
    for priority, refs in sorted(seen.items()):
        if len(refs) > 1:
            results.append(
                _result(
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
                _result(
                    "AZ022",
                    Severity.ERROR,
                    f"Duplicate ref {ref!r} appears {count} times",
                    phase,
                    ref=ref,
                )
            )


def _check_priority_gaps(seen: dict[int, list[str]], results: list[LintResult], phase: str) -> None:
    """AZ102: Non-contiguous priorities (info)."""
    priorities = sorted(seen.keys())
    if len(priorities) < 2:
        return
    for i in range(1, len(priorities)):
        if priorities[i] != priorities[i - 1] + 1:
            results.append(
                _result(
                    "AZ102",
                    Severity.INFO,
                    f"Non-contiguous priorities: gap between {priorities[i - 1]}"
                    f" and {priorities[i]}",
                    phase,
                )
            )
            return  # Only report first gap


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
        if isinstance(values, list) and any(v in _CATCH_ALL_CIDRS for v in values):
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
        if _is_strict_int(priority) and priority >= 1:
            priority_rules.append((priority, rule))
    priority_rules.sort(key=lambda x: x[0])

    first_catch_all_priority: int | None = None
    first_catch_all_ref = ""

    for priority, rule in priority_rules:
        ref = str(rule.get("ref", ""))
        action = rule.get("action", "")

        if first_catch_all_priority is not None and priority > first_catch_all_priority:
            results.append(
                _result(
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
                _result(
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
            _result(
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
            _result(
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
                _result(
                    "AZ603",
                    Severity.INFO,
                    "Allow catch-all rule bypasses all managed rules (OWASP DRS, bot protection)",
                    phase,
                    ref=ref,
                    suggestion="Ensure this is intentional; managed rules will not evaluate"
                    " for matched traffic",
                )
            )


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
_VALID_OVERRIDE_ACTIONS = frozenset({"Allow", "Block", "Log", "Redirect", "AnomalyScoring"})


def _check_managed_ref(rule: dict, results: list[LintResult], phase: str) -> str:
    """AZ700: Managed rule set must have a valid ref (ruleSetType)."""
    ref = rule.get("ref")
    if ref is None or ref == "":
        results.append(
            _result("AZ700", Severity.ERROR, "Managed rule set missing 'ref'", phase, field="ref")
        )
        return ""
    return str(ref)


def _check_rule_set_type(rule: dict, results: list[LintResult], phase: str, ref: str) -> None:
    """AZ701: Validate ruleSetType value."""
    rst = rule.get("ruleSetType")
    if rst is None or rst == "":
        results.append(
            _result(
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
            _result(
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
            _result(
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
            _result(
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
            _result(
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
            _result(
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
            _result(
                "AZ702",
                Severity.ERROR,
                f"Invalid ruleSetAction {action!r}; expected one of: "
                f"{', '.join(sorted(_VALID_RULE_SET_ACTIONS))}",
                phase,
                ref=ref,
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
            _result(
                "AZ703",
                Severity.ERROR,
                f"{path}: invalid enabledState {state!r}; expected 'Enabled' or 'Disabled'",
                phase,
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
            _result(
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
            _result(
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
                _result(
                    "AZ707",
                    Severity.ERROR,
                    f"{path}: invalid action {action!r}; expected one of: "
                    f"{', '.join(sorted(_VALID_OVERRIDE_ACTIONS))}",
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
            _result(
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
                _result(
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
                _result(
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
                    _result(
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
                _result(
                    "AZ700",
                    Severity.ERROR,
                    f"Duplicate managed rule set ref {ref!r} appears {count} times",
                    phase,
                    ref=ref,
                )
            )

    return results
