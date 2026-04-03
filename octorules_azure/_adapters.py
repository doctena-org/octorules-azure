"""Internal adapters for Front Door WAF vs Application Gateway WAF.

Each adapter normalises the SDK-specific rule model to a common internal
representation (Front Door canonical form) and provides methods for API
interaction.  The provider delegates all SDK-specific work to the active
adapter.

Canonical internal form (Front Door field names):
  - ``matchVariable`` (string) + ``selector``
  - ``negateCondition`` (correct spelling)
  - ``matchValue`` (singular)
  - ``enabledState`` ("Enabled" / "Disabled")
  - ``ruleType`` ("MatchRule" / "RateLimitRule")
  - ``RegEx`` (Front Door casing for operator)
"""

from __future__ import annotations

import copy
import logging
from typing import Any

from octorules.config import ConfigError
from octorules.provider.utils import denormalize_fields, normalize_fields, to_plain_dict

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Front Door match-variable names (canonical)
# ---------------------------------------------------------------------------
_FD_MATCH_VARIABLES = frozenset(
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

# App Gateway -> Front Door variable name mapping
_AG_TO_FD_VARIABLE = {
    "RequestHeaders": "RequestHeader",
    "RequestCookies": "Cookies",
}
_FD_TO_AG_VARIABLE = {v: k for k, v in _AG_TO_FD_VARIABLE.items()}

# App Gateway rate-limit duration enums <-> Front Door integer minutes
_AG_DURATION_TO_MINUTES = {"OneMin": 1, "FiveMins": 5}
_MINUTES_TO_AG_DURATION = {v: k for k, v in _AG_DURATION_TO_MINUTES.items()}

# Operator casing: App Gateway uses "Regex", Front Door uses "RegEx"
_AG_OPERATOR_MAP = {"Regex": "RegEx"}
_FD_OPERATOR_MAP = {"RegEx": "Regex"}


# Field mapping: Azure ``name`` -> octorules ``ref``
_AZURE_NAME_MAP = {"name": "ref"}


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
def _normalize_name(rule: dict) -> dict:
    """Rename ``name`` -> ``ref`` using the shared utility."""
    d = dict(rule)
    d.setdefault("name", "")
    return normalize_fields(d, _AZURE_NAME_MAP)


def _denormalize_name(rule: dict) -> dict:
    """Rename ``ref`` -> ``name`` using the shared utility."""
    d = dict(rule)
    d.setdefault("ref", "")
    return denormalize_fields(d, _AZURE_NAME_MAP)


def classify_phase(rule: dict) -> str:
    """Return the Azure phase id for a rule (works for both WAF types)."""
    if rule.get("ruleType") == "RateLimitRule":
        return "azure_waf_rate"
    return "azure_waf_custom"


# ---------------------------------------------------------------------------
# Front Door Adapter
# ---------------------------------------------------------------------------
class FrontDoorAdapter:
    """Adapter for Azure Front Door WAF (Premium/Standard).

    SDK: ``azure.mgmt.frontdoor.FrontDoorManagementClient``
    """

    waf_type = "front_door"

    def get_client(self, credential: Any, subscription_id: str, **kwargs: Any) -> Any:
        """Create a Front Door management client."""
        from azure.mgmt.frontdoor import FrontDoorManagementClient

        return FrontDoorManagementClient(credential, subscription_id, **kwargs)

    def list_policies(self, client: Any, resource_group: str) -> list[str]:
        """List all Front Door WAF policy names in a resource group."""
        policies = client.policies.list(resource_group)
        return [to_plain_dict(p).get("name", "") for p in policies]

    def get_policy(self, client: Any, resource_group: str, policy_name: str) -> dict:
        """Fetch a Front Door WAF policy as a plain dict."""
        policy = client.policies.get(resource_group, policy_name)
        return to_plain_dict(policy)

    def put_policy(self, client: Any, resource_group: str, policy_name: str, policy: Any) -> dict:
        """Write a Front Door WAF policy (full PUT, async LRO)."""
        poller = client.policies.begin_create_or_update(resource_group, policy_name, policy)
        result = poller.result()
        return to_plain_dict(result)

    def extract_custom_rules(self, policy: dict) -> list[dict]:
        """Extract custom rules from a Front Door policy dict."""
        custom_rules = policy.get("custom_rules") or {}
        return list(custom_rules.get("rules") or [])

    def replace_custom_rules(self, policy: dict, rules: list[dict]) -> dict:
        """Return a copy of *policy* with custom rules replaced."""
        p = copy.deepcopy(policy)
        if "custom_rules" not in p:
            p["custom_rules"] = {}
        p["custom_rules"]["rules"] = rules
        return p

    def extract_etag(self, policy: dict) -> str:
        """Extract ETag from a Front Door policy."""
        return policy.get("etag", "")

    def normalize_rule(self, rule: dict) -> dict:
        """Convert a Front Door SDK rule dict to canonical internal form."""
        d = to_plain_dict(rule)
        d = _normalize_name(d)
        # Front Door uses the canonical form natively — minimal transformation.
        # Ensure match conditions are plain dicts.
        conditions = d.get("match_conditions")
        if isinstance(conditions, list):
            normalised: list[dict] = []
            for cond in conditions:
                c = to_plain_dict(cond)
                normalised.append(
                    {
                        "matchVariable": c.get("match_variable", ""),
                        "selector": c.get("selector"),
                        "operator": c.get("operator", ""),
                        "negateCondition": bool(c.get("negate_condition", False)),
                        "matchValue": list(c.get("match_value") or []),
                        "transforms": list(c.get("transforms") or []),
                    }
                )
            d["matchConditions"] = normalised
            d.pop("match_conditions", None)
        # Normalise top-level fields from SDK snake_case to canonical form
        d = _normalise_fd_top_level(d)
        return d

    def denormalize_rule(self, rule: dict) -> dict:
        """Convert canonical internal form back to Front Door SDK format."""
        d = _denormalize_name(dict(rule))
        # Convert matchConditions back to SDK snake_case
        conditions = d.pop("matchConditions", [])
        sdk_conditions: list[dict] = []
        for cond in conditions:
            sdk_conditions.append(
                {
                    "match_variable": cond.get("matchVariable", ""),
                    "selector": cond.get("selector"),
                    "operator": cond.get("operator", ""),
                    "negate_condition": cond.get("negateCondition", False),
                    "match_value": cond.get("matchValue", []),
                    "transforms": cond.get("transforms", []),
                }
            )
        d["match_conditions"] = sdk_conditions
        # Convert top-level fields back to SDK snake_case
        d = _denormalise_fd_top_level(d)
        return d


def _normalise_fd_top_level(d: dict) -> dict:
    """Map Front Door SDK snake_case fields to canonical camelCase.

    Returns a new dict — does NOT mutate *d*.
    """
    _FD_NORM_MAP = {
        "rule_type": "ruleType",
        "enabled_state": "enabledState",
        "rate_limit_duration_in_minutes": "rateLimitDurationInMinutes",
        "rate_limit_threshold": "rateLimitThreshold",
        "group_by": "groupBy",
    }
    out: dict = {}
    for k, v in d.items():
        out[_FD_NORM_MAP.get(k, k)] = v
    # Normalise groupBy entries
    group_by = out.get("groupBy")
    if isinstance(group_by, list):
        out["groupBy"] = [
            {"variableName": to_plain_dict(entry).get("variable_name", "")} for entry in group_by
        ]
    return out


def _denormalise_fd_top_level(d: dict) -> dict:
    """Map canonical camelCase fields back to Front Door SDK snake_case.

    Returns a new dict — does NOT mutate *d*.
    """
    _FD_DENORM_MAP = {
        "ruleType": "rule_type",
        "enabledState": "enabled_state",
        "rateLimitDurationInMinutes": "rate_limit_duration_in_minutes",
        "rateLimitThreshold": "rate_limit_threshold",
        "groupBy": "group_by",
    }
    out: dict = {}
    for k, v in d.items():
        out[_FD_DENORM_MAP.get(k, k)] = v
    # Denormalise groupBy entries
    group_by = out.get("group_by")
    if isinstance(group_by, list):
        out["group_by"] = [{"variable_name": entry.get("variableName", "")} for entry in group_by]
    return out


# ---------------------------------------------------------------------------
# Application Gateway Adapter
# ---------------------------------------------------------------------------
class AppGatewayAdapter:
    """Adapter for Azure Application Gateway WAF (WAF_v2).

    SDK: ``azure.mgmt.network.NetworkManagementClient``

    Handles the key API differences from Front Door:
    - ``matchVariables`` (array of objects) vs ``matchVariable`` (string)
    - ``negationConditon`` (typo) vs ``negateCondition``
    - ``matchValues`` (plural) vs ``matchValue`` (singular)
    - ``RequestHeaders``/``RequestCookies`` vs ``RequestHeader``/``Cookies``
    - ``state`` vs ``enabledState``
    - ``Regex`` vs ``RegEx`` operator casing
    - Rate limit duration: enum strings vs integer minutes
    """

    waf_type = "app_gateway"

    def get_client(self, credential: Any, subscription_id: str, **kwargs: Any) -> Any:
        """Create a Network management client."""
        from azure.mgmt.network import NetworkManagementClient

        return NetworkManagementClient(credential, subscription_id, **kwargs)

    def list_policies(self, client: Any, resource_group: str) -> list[str]:
        """List all App Gateway WAF policy names in a resource group."""
        policies = client.web_application_firewall_policies.list(resource_group)
        return [to_plain_dict(p).get("name", "") for p in policies]

    def get_policy(self, client: Any, resource_group: str, policy_name: str) -> dict:
        """Fetch an App Gateway WAF policy as a plain dict."""
        policy = client.web_application_firewall_policies.get(resource_group, policy_name)
        return to_plain_dict(policy)

    def put_policy(self, client: Any, resource_group: str, policy_name: str, policy: Any) -> dict:
        """Write an App Gateway WAF policy (full PUT, synchronous)."""
        result = client.web_application_firewall_policies.create_or_update(
            resource_group, policy_name, policy
        )
        return to_plain_dict(result)

    def extract_custom_rules(self, policy: dict) -> list[dict]:
        """Extract custom rules from an App Gateway policy dict."""
        return list(policy.get("custom_rules") or [])

    def replace_custom_rules(self, policy: dict, rules: list[dict]) -> dict:
        """Return a copy of *policy* with custom rules replaced."""
        p = copy.deepcopy(policy)
        p["custom_rules"] = rules
        return p

    def extract_etag(self, policy: dict) -> str:
        """Extract ETag from an App Gateway policy."""
        return policy.get("etag", "")

    def normalize_rule(self, rule: dict) -> dict:
        """Convert an App Gateway SDK rule dict to canonical internal form.

        Flattens ``match_variables`` array to ``matchVariable`` string,
        fixes ``negation_conditon`` typo, maps variable names and operator
        casing, and converts rate limit duration enums to integer minutes.
        """
        d = to_plain_dict(rule)
        d = _normalize_name(d)

        # Normalise match conditions
        conditions = d.get("match_conditions")
        if isinstance(conditions, list):
            normalised: list[dict] = []
            for cond in conditions:
                c = to_plain_dict(cond)
                normalised.append(_normalise_ag_condition(c))
            d["matchConditions"] = normalised
            d.pop("match_conditions", None)

        # Normalise top-level fields
        d = _normalise_ag_top_level(d)

        return d

    def denormalize_rule(self, rule: dict) -> dict:
        """Convert canonical internal form back to App Gateway SDK format."""
        d = _denormalize_name(dict(rule))

        # Denormalise match conditions
        conditions = d.pop("matchConditions", [])
        sdk_conditions: list[dict] = []
        for cond in conditions:
            sdk_conditions.append(_denormalise_ag_condition(cond))
        d["match_conditions"] = sdk_conditions

        # Denormalise top-level fields
        d = _denormalise_ag_top_level(d)

        return d


def _normalise_ag_condition(c: dict) -> dict:
    """Normalise a single App Gateway match condition to canonical form."""
    # Flatten matchVariables array to matchVariable + selector
    match_variables = c.get("match_variables", [])
    if isinstance(match_variables, list) and match_variables:
        first = to_plain_dict(match_variables[0])
        variable_name = first.get("variable_name", "")
        selector = first.get("selector")
    else:
        variable_name = ""
        selector = None

    # Map App Gateway variable names to Front Door names
    variable_name = _AG_TO_FD_VARIABLE.get(variable_name, variable_name)

    # Map operator casing
    operator = c.get("operator", "")
    operator = _AG_OPERATOR_MAP.get(operator, operator)

    # Handle the negationConditon typo — SDK uses negation_conditon (snake_case)
    negate = c.get("negation_conditon", c.get("negation_condition", False))

    # Map matchValues (plural) to matchValue (singular)
    match_values = list(c.get("match_values") or [])

    transforms = list(c.get("transforms") or [])

    return {
        "matchVariable": variable_name,
        "selector": selector,
        "operator": operator,
        "negateCondition": bool(negate),
        "matchValue": match_values,
        "transforms": transforms,
    }


def _denormalise_ag_condition(cond: dict) -> dict:
    """Denormalise a canonical match condition to App Gateway SDK format."""
    variable_name = cond.get("matchVariable", "")
    # Map Front Door variable names back to App Gateway names
    variable_name = _FD_TO_AG_VARIABLE.get(variable_name, variable_name)

    selector = cond.get("selector")

    # Map operator casing back
    operator = cond.get("operator", "")
    operator = _FD_OPERATOR_MAP.get(operator, operator)

    return {
        "match_variables": [{"variable_name": variable_name, "selector": selector}],
        "operator": operator,
        "negation_conditon": cond.get("negateCondition", False),
        "match_values": cond.get("matchValue", []),
        "transforms": cond.get("transforms", []),
    }


def _normalise_ag_top_level(d: dict) -> dict:
    """Map App Gateway SDK fields to canonical form.

    Returns a new dict — does NOT mutate *d*.
    """
    _AG_NORM_MAP = {
        "state": "enabledState",
        "rule_type": "ruleType",
        "rate_limit_threshold": "rateLimitThreshold",
    }
    # Keys to skip (handled specially below).
    _AG_SKIP = {"rate_limit_duration", "group_by_user_session"}

    out: dict = {}
    for k, v in d.items():
        if k in _AG_SKIP:
            continue
        out[_AG_NORM_MAP.get(k, k)] = v

    # rate_limit_duration (enum) -> rateLimitDurationInMinutes (int)
    if "rate_limit_duration" in d:
        out["rateLimitDurationInMinutes"] = _AG_DURATION_TO_MINUTES.get(d["rate_limit_duration"], 0)

    # groupByUserSession -> groupBy
    group_by_session = d.get("group_by_user_session")
    if isinstance(group_by_session, list) and group_by_session:
        first_session = to_plain_dict(group_by_session[0])
        variables = first_session.get("group_by_variables", [])
        normalised = []
        for v in variables:
            v = to_plain_dict(v)
            name = v.get("variable_name", "")
            if name == "ClientAddr":
                name = "SocketAddr"
            normalised.append({"variableName": name})
        out["groupBy"] = normalised

    return out


def _denormalise_ag_top_level(d: dict) -> dict:
    """Map canonical form back to App Gateway SDK fields.

    Returns a new dict — does NOT mutate *d*.
    """
    _AG_DENORM_MAP = {
        "enabledState": "state",
        "ruleType": "rule_type",
        "rateLimitThreshold": "rate_limit_threshold",
    }
    # Keys to skip (handled specially below).
    _AG_SKIP = {"rateLimitDurationInMinutes", "groupBy"}

    out: dict = {}
    for k, v in d.items():
        if k in _AG_SKIP:
            continue
        out[_AG_DENORM_MAP.get(k, k)] = v

    # rateLimitDurationInMinutes (int) -> rate_limit_duration (enum)
    if "rateLimitDurationInMinutes" in d:
        minutes = d["rateLimitDurationInMinutes"]
        duration = _MINUTES_TO_AG_DURATION.get(minutes)
        if duration is None:
            log.warning("Unknown rateLimitDurationInMinutes %r, defaulting to FiveMins", minutes)
            duration = "FiveMins"
        out["rate_limit_duration"] = duration

    # groupBy -> group_by_user_session
    group_by = d.get("groupBy")
    if isinstance(group_by, list) and group_by:
        variables = []
        for entry in group_by:
            name = entry.get("variableName", "")
            if name == "SocketAddr":
                name = "ClientAddr"
            variables.append({"variable_name": name})
        out["group_by_user_session"] = [{"group_by_variables": variables}]

    return out


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------
def create_adapter(waf_type: str) -> FrontDoorAdapter | AppGatewayAdapter:
    """Create the appropriate adapter for the given WAF type.

    Args:
        waf_type: ``"front_door"`` or ``"app_gateway"``.

    Raises:
        ConfigError: If *waf_type* is not recognised.
    """
    if waf_type == "front_door":
        return FrontDoorAdapter()
    if waf_type == "app_gateway":
        return AppGatewayAdapter()
    raise ConfigError(f"Invalid waf_type: {waf_type!r} (must be 'front_door' or 'app_gateway')")
