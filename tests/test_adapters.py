"""Tests for Azure WAF adapters (Front Door + App Gateway)."""

import pytest
from octorules.config import ConfigError

from octorules_azure._adapters import (
    AppGatewayAdapter,
    FrontDoorAdapter,
    classify_phase,
    create_adapter,
)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------
class TestFactory:
    def test_front_door(self):
        adapter = create_adapter("front_door")
        assert isinstance(adapter, FrontDoorAdapter)

    def test_app_gateway(self):
        adapter = create_adapter("app_gateway")
        assert isinstance(adapter, AppGatewayAdapter)

    def test_invalid_raises_config_error(self):
        with pytest.raises(ConfigError, match="Invalid waf_type"):
            create_adapter("invalid")


# ---------------------------------------------------------------------------
# Phase classification
# ---------------------------------------------------------------------------
class TestClassifyPhase:
    def test_match_rule(self):
        assert classify_phase({"ruleType": "MatchRule"}) == "azure_waf_custom"

    def test_rate_limit_rule(self):
        assert classify_phase({"ruleType": "RateLimitRule"}) == "azure_waf_rate"

    def test_unknown_defaults_to_custom(self):
        assert classify_phase({"ruleType": "Unknown"}) == "azure_waf_custom"

    def test_missing_rule_type_defaults_to_custom(self):
        assert classify_phase({}) == "azure_waf_custom"


# ---------------------------------------------------------------------------
# Front Door Adapter -- Normalisation
# ---------------------------------------------------------------------------
class TestFrontDoorNormalize:
    def setup_method(self):
        self.adapter = FrontDoorAdapter()

    def test_normalizes_name_to_ref(self, fd_custom_rule):
        result = self.adapter.normalize_rule(fd_custom_rule)
        assert result["ref"] == "BlockBadIPs"
        assert "name" not in result

    def test_normalizes_match_conditions(self, fd_custom_rule):
        result = self.adapter.normalize_rule(fd_custom_rule)
        cond = result["matchConditions"][0]
        assert cond["matchVariable"] == "RemoteAddr"
        assert cond["operator"] == "IPMatch"
        assert cond["negateCondition"] is False
        assert cond["matchValue"] == ["192.168.1.0/24", "10.0.0.0/8"]

    def test_normalizes_top_level_fields(self, fd_custom_rule):
        result = self.adapter.normalize_rule(fd_custom_rule)
        assert result["ruleType"] == "MatchRule"
        assert result["enabledState"] == "Enabled"

    def test_normalizes_rate_limit_fields(self, fd_rate_rule):
        result = self.adapter.normalize_rule(fd_rate_rule)
        assert result["ruleType"] == "RateLimitRule"
        assert result["rateLimitDurationInMinutes"] == 1
        assert result["rateLimitThreshold"] == 100
        assert result["groupBy"] == [{"variableName": "SocketAddr"}]

    def test_roundtrip(self, fd_custom_rule):
        normalised = self.adapter.normalize_rule(fd_custom_rule)
        denormalised = self.adapter.denormalize_rule(normalised)
        assert denormalised["name"] == "BlockBadIPs"
        assert "ref" not in denormalised
        assert denormalised["rule_type"] == "MatchRule"
        assert denormalised["enabled_state"] == "Enabled"
        cond = denormalised["match_conditions"][0]
        assert cond["match_variable"] == "RemoteAddr"
        assert cond["match_value"] == ["192.168.1.0/24", "10.0.0.0/8"]

    def test_rate_limit_roundtrip(self, fd_rate_rule):
        normalised = self.adapter.normalize_rule(fd_rate_rule)
        denormalised = self.adapter.denormalize_rule(normalised)
        assert denormalised["rate_limit_duration_in_minutes"] == 1
        assert denormalised["rate_limit_threshold"] == 100
        group_by = denormalised["group_by"]
        assert group_by == [{"variable_name": "SocketAddr"}]


# ---------------------------------------------------------------------------
# App Gateway Adapter -- Normalisation
# ---------------------------------------------------------------------------
class TestAppGatewayNormalize:
    def setup_method(self):
        self.adapter = AppGatewayAdapter()

    def test_normalizes_name_to_ref(self, ag_custom_rule):
        result = self.adapter.normalize_rule(ag_custom_rule)
        assert result["ref"] == "BlockBadIPs"
        assert "name" not in result

    def test_flattens_match_variables(self, ag_custom_rule):
        result = self.adapter.normalize_rule(ag_custom_rule)
        cond = result["matchConditions"][0]
        # Should be flattened from matchVariables array to matchVariable string
        assert cond["matchVariable"] == "RemoteAddr"
        assert "matchVariables" not in cond

    def test_fixes_negation_typo(self, ag_custom_rule):
        result = self.adapter.normalize_rule(ag_custom_rule)
        cond = result["matchConditions"][0]
        assert cond["negateCondition"] is False
        assert "negationConditon" not in cond
        assert "negation_conditon" not in cond

    def test_maps_match_values_plural(self, ag_custom_rule):
        result = self.adapter.normalize_rule(ag_custom_rule)
        cond = result["matchConditions"][0]
        assert cond["matchValue"] == ["192.168.1.0/24", "10.0.0.0/8"]
        assert "matchValues" not in cond

    def test_maps_variable_names(self):
        """App Gateway 'RequestHeaders' -> Front Door 'RequestHeader'."""
        rule = {
            "name": "Test",
            "priority": 1,
            "state": "Enabled",
            "rule_type": "MatchRule",
            "match_conditions": [
                {
                    "match_variables": [
                        {"variable_name": "RequestHeaders", "selector": "User-Agent"}
                    ],
                    "operator": "Contains",
                    "negation_conditon": False,
                    "match_values": ["bot"],
                    "transforms": ["Lowercase"],
                }
            ],
            "action": "Block",
        }
        result = self.adapter.normalize_rule(rule)
        cond = result["matchConditions"][0]
        assert cond["matchVariable"] == "RequestHeader"
        assert cond["selector"] == "User-Agent"

    def test_maps_cookies_variable(self):
        """App Gateway 'RequestCookies' -> Front Door 'Cookies'."""
        rule = {
            "name": "Test",
            "priority": 1,
            "state": "Enabled",
            "rule_type": "MatchRule",
            "match_conditions": [
                {
                    "match_variables": [{"variable_name": "RequestCookies", "selector": "session"}],
                    "operator": "Contains",
                    "negation_conditon": False,
                    "match_values": ["malicious"],
                    "transforms": [],
                }
            ],
            "action": "Block",
        }
        result = self.adapter.normalize_rule(rule)
        assert result["matchConditions"][0]["matchVariable"] == "Cookies"

    def test_maps_regex_operator_casing(self):
        """App Gateway 'Regex' -> Front Door 'RegEx'."""
        rule = {
            "name": "Test",
            "priority": 1,
            "state": "Enabled",
            "rule_type": "MatchRule",
            "match_conditions": [
                {
                    "match_variables": [{"variable_name": "RequestUri", "selector": None}],
                    "operator": "Regex",
                    "negation_conditon": False,
                    "match_values": ["^/admin.*"],
                    "transforms": [],
                }
            ],
            "action": "Block",
        }
        result = self.adapter.normalize_rule(rule)
        assert result["matchConditions"][0]["operator"] == "RegEx"

    def test_normalizes_state_to_enabled_state(self, ag_custom_rule):
        result = self.adapter.normalize_rule(ag_custom_rule)
        assert result["enabledState"] == "Enabled"
        assert "state" not in result

    def test_normalizes_rate_limit_duration(self, ag_rate_rule):
        result = self.adapter.normalize_rule(ag_rate_rule)
        assert result["rateLimitDurationInMinutes"] == 1

    def test_normalizes_group_by(self, ag_rate_rule):
        result = self.adapter.normalize_rule(ag_rate_rule)
        # App Gateway ClientAddr -> Front Door SocketAddr
        assert result["groupBy"] == [{"variableName": "SocketAddr"}]

    def test_roundtrip(self, ag_custom_rule):
        normalised = self.adapter.normalize_rule(ag_custom_rule)
        denormalised = self.adapter.denormalize_rule(normalised)
        assert denormalised["name"] == "BlockBadIPs"
        assert denormalised["state"] == "Enabled"
        cond = denormalised["match_conditions"][0]
        assert cond["match_variables"] == [{"variable_name": "RemoteAddr", "selector": None}]
        assert cond["negation_conditon"] is False
        assert cond["match_values"] == ["192.168.1.0/24", "10.0.0.0/8"]

    def test_rate_limit_roundtrip(self, ag_rate_rule):
        normalised = self.adapter.normalize_rule(ag_rate_rule)
        denormalised = self.adapter.denormalize_rule(normalised)
        assert denormalised["rate_limit_duration"] == "OneMin"
        assert denormalised["rate_limit_threshold"] == 100
        session = denormalised["group_by_user_session"]
        assert session == [{"group_by_variables": [{"variable_name": "ClientAddr"}]}]

    def test_selector_roundtrip(self):
        """Header selector survives normalize -> denormalize roundtrip."""
        rule = {
            "name": "CheckUA",
            "priority": 5,
            "state": "Enabled",
            "rule_type": "MatchRule",
            "match_conditions": [
                {
                    "match_variables": [
                        {"variable_name": "RequestHeaders", "selector": "User-Agent"}
                    ],
                    "operator": "Contains",
                    "negation_conditon": False,
                    "match_values": ["bot"],
                    "transforms": ["Lowercase"],
                }
            ],
            "action": "Block",
        }
        normalised = self.adapter.normalize_rule(rule)
        assert normalised["matchConditions"][0]["matchVariable"] == "RequestHeader"
        assert normalised["matchConditions"][0]["selector"] == "User-Agent"

        denormalised = self.adapter.denormalize_rule(normalised)
        cond = denormalised["match_conditions"][0]
        assert cond["match_variables"] == [
            {"variable_name": "RequestHeaders", "selector": "User-Agent"}
        ]
        assert cond["operator"] == "Contains"
        assert cond["match_values"] == ["bot"]
        assert cond["transforms"] == ["Lowercase"]

    def test_denormalize_maps_variable_names_back(self):
        """Front Door 'RequestHeader' -> App Gateway 'RequestHeaders'."""
        normalised = {
            "ref": "Test",
            "matchConditions": [
                {
                    "matchVariable": "RequestHeader",
                    "selector": "User-Agent",
                    "operator": "Contains",
                    "negateCondition": False,
                    "matchValue": ["bot"],
                    "transforms": [],
                }
            ],
            "ruleType": "MatchRule",
            "enabledState": "Enabled",
            "action": "Block",
        }
        adapter = AppGatewayAdapter()
        denormalised = adapter.denormalize_rule(normalised)
        cond = denormalised["match_conditions"][0]
        assert cond["match_variables"][0]["variable_name"] == "RequestHeaders"

    def test_denormalize_maps_regex_operator_back(self):
        """Front Door 'RegEx' -> App Gateway 'Regex'."""
        normalised = {
            "ref": "Test",
            "matchConditions": [
                {
                    "matchVariable": "RequestUri",
                    "selector": None,
                    "operator": "RegEx",
                    "negateCondition": False,
                    "matchValue": ["^/admin"],
                    "transforms": [],
                }
            ],
            "ruleType": "MatchRule",
            "enabledState": "Enabled",
            "action": "Block",
        }
        adapter = AppGatewayAdapter()
        denormalised = adapter.denormalize_rule(normalised)
        assert denormalised["match_conditions"][0]["operator"] == "Regex"


# ---------------------------------------------------------------------------
# Cross-adapter normalisation consistency
# ---------------------------------------------------------------------------
class TestNormalizationConsistency:
    """Verify that equivalent rules from both WAF types produce identical
    canonical forms after normalisation."""

    def test_equivalent_custom_rules(self, fd_custom_rule, ag_custom_rule):
        fd = FrontDoorAdapter().normalize_rule(fd_custom_rule)
        ag = AppGatewayAdapter().normalize_rule(ag_custom_rule)
        # Both should have same ref, action, matchConditions, ruleType
        assert fd["ref"] == ag["ref"]
        assert fd["action"] == ag["action"]
        assert fd["ruleType"] == ag["ruleType"]
        assert fd["matchConditions"] == ag["matchConditions"]

    def test_equivalent_rate_rules(self, fd_rate_rule, ag_rate_rule):
        fd = FrontDoorAdapter().normalize_rule(fd_rate_rule)
        ag = AppGatewayAdapter().normalize_rule(ag_rate_rule)
        assert fd["ref"] == ag["ref"]
        assert fd["rateLimitDurationInMinutes"] == ag["rateLimitDurationInMinutes"]
        assert fd["rateLimitThreshold"] == ag["rateLimitThreshold"]
        assert fd["groupBy"] == ag["groupBy"]


# ---------------------------------------------------------------------------
# Adapter policy operations
# ---------------------------------------------------------------------------
class TestFrontDoorPolicyOps:
    def setup_method(self):
        self.adapter = FrontDoorAdapter()

    def test_extract_custom_rules(self):
        policy = {
            "custom_rules": {
                "rules": [{"name": "r1"}, {"name": "r2"}],
            }
        }
        assert self.adapter.extract_custom_rules(policy) == [{"name": "r1"}, {"name": "r2"}]

    def test_extract_empty_custom_rules(self):
        assert self.adapter.extract_custom_rules({}) == []
        assert self.adapter.extract_custom_rules({"custom_rules": None}) == []
        assert self.adapter.extract_custom_rules({"custom_rules": {}}) == []

    def test_replace_custom_rules_preserves_managed(self):
        policy = {
            "custom_rules": {"rules": [{"name": "old"}]},
            "managed_rules": {"managed_rule_sets": [{"type": "DRS"}]},
            "policy_settings": {"mode": "Prevention"},
        }
        updated = self.adapter.replace_custom_rules(policy, [{"name": "new"}])
        assert updated["custom_rules"]["rules"] == [{"name": "new"}]
        assert updated["managed_rules"] == {"managed_rule_sets": [{"type": "DRS"}]}
        assert updated["policy_settings"] == {"mode": "Prevention"}
        # Original should be unchanged
        assert policy["custom_rules"]["rules"] == [{"name": "old"}]


class TestAppGatewayPolicyOps:
    def setup_method(self):
        self.adapter = AppGatewayAdapter()

    def test_extract_custom_rules(self):
        policy = {"custom_rules": [{"name": "r1"}, {"name": "r2"}]}
        assert self.adapter.extract_custom_rules(policy) == [{"name": "r1"}, {"name": "r2"}]

    def test_extract_empty_custom_rules(self):
        assert self.adapter.extract_custom_rules({}) == []
        assert self.adapter.extract_custom_rules({"custom_rules": None}) == []

    def test_replace_custom_rules_preserves_managed(self):
        policy = {
            "custom_rules": [{"name": "old"}],
            "managed_rules": {"managed_rule_sets": [{"type": "OWASP"}]},
        }
        updated = self.adapter.replace_custom_rules(policy, [{"name": "new"}])
        assert updated["custom_rules"] == [{"name": "new"}]
        assert updated["managed_rules"] == {"managed_rule_sets": [{"type": "OWASP"}]}
        assert policy["custom_rules"] == [{"name": "old"}]


# ---------------------------------------------------------------------------
# Adapter edge cases
# ---------------------------------------------------------------------------
class TestAdapterEdgeCases:
    def test_fd_normalize_missing_match_conditions(self):
        """Rule with no match_conditions key."""
        adapter = FrontDoorAdapter()
        rule = {"name": "NoConditions", "priority": 1, "action": "Block"}
        result = adapter.normalize_rule(rule)
        assert result["ref"] == "NoConditions"
        assert "matchConditions" not in result

    def test_ag_normalize_missing_match_conditions(self):
        adapter = AppGatewayAdapter()
        rule = {"name": "NoConditions", "priority": 1, "action": "Block"}
        result = adapter.normalize_rule(rule)
        assert result["ref"] == "NoConditions"

    def test_fd_normalize_empty_match_conditions(self):
        adapter = FrontDoorAdapter()
        rule = {"name": "Empty", "priority": 1, "match_conditions": []}
        result = adapter.normalize_rule(rule)
        assert result["matchConditions"] == []

    def test_ag_normalize_empty_match_variables(self):
        """App Gateway condition with empty match_variables array."""
        adapter = AppGatewayAdapter()
        rule = {
            "name": "EmptyVars",
            "priority": 1,
            "state": "Enabled",
            "rule_type": "MatchRule",
            "match_conditions": [
                {
                    "match_variables": [],
                    "operator": "Any",
                    "negation_conditon": False,
                    "match_values": [],
                    "transforms": [],
                }
            ],
            "action": "Block",
        }
        result = adapter.normalize_rule(rule)
        cond = result["matchConditions"][0]
        assert cond["matchVariable"] == ""  # graceful fallback

    def test_fd_denormalize_empty_rule(self):
        adapter = FrontDoorAdapter()
        result = adapter.denormalize_rule({"ref": "X"})
        assert result["name"] == "X"
        assert result["match_conditions"] == []

    def test_ag_denormalize_empty_rule(self):
        adapter = AppGatewayAdapter()
        result = adapter.denormalize_rule({"ref": "X"})
        assert result["name"] == "X"
        assert result["match_conditions"] == []

    def test_fd_rate_limit_missing_group_by(self):
        """Front Door rule without group_by should normalize without error."""
        adapter = FrontDoorAdapter()
        rule = {
            "name": "Rate",
            "priority": 1,
            "rule_type": "RateLimitRule",
            "rate_limit_duration_in_minutes": 5,
            "rate_limit_threshold": 200,
            "match_conditions": [],
            "action": "Block",
        }
        result = adapter.normalize_rule(rule)
        assert result["rateLimitDurationInMinutes"] == 5
        assert "groupBy" not in result

    def test_ag_five_min_duration_roundtrip(self):
        adapter = AppGatewayAdapter()
        rule = {
            "name": "Rate5",
            "priority": 1,
            "state": "Enabled",
            "rule_type": "RateLimitRule",
            "match_conditions": [],
            "action": "Block",
            "rate_limit_duration": "FiveMins",
            "rate_limit_threshold": 500,
        }
        normalised = adapter.normalize_rule(rule)
        assert normalised["rateLimitDurationInMinutes"] == 5
        denormalised = adapter.denormalize_rule(normalised)
        assert denormalised["rate_limit_duration"] == "FiveMins"

    def test_ag_multiple_match_variables_takes_first(self):
        """AG condition with >1 match_variables entry -- only first is used."""
        adapter = AppGatewayAdapter()
        rule = {
            "name": "Multi",
            "priority": 1,
            "state": "Enabled",
            "rule_type": "MatchRule",
            "match_conditions": [
                {
                    "match_variables": [
                        {"variable_name": "RemoteAddr", "selector": None},
                        {"variable_name": "RequestUri", "selector": None},
                    ],
                    "operator": "IPMatch",
                    "negation_conditon": False,
                    "match_values": ["1.2.3.4"],
                    "transforms": [],
                }
            ],
            "action": "Block",
        }
        result = adapter.normalize_rule(rule)
        # Only first variable is taken
        assert result["matchConditions"][0]["matchVariable"] == "RemoteAddr"

    def test_fd_cookies_passthrough(self):
        """FD adapter preserves Cookies variable name (no mapping needed)."""
        adapter = FrontDoorAdapter()
        rule = {
            "name": "CookieCheck",
            "priority": 1,
            "enabled_state": "Enabled",
            "rule_type": "MatchRule",
            "match_conditions": [
                {
                    "match_variable": "Cookies",
                    "selector": "session",
                    "operator": "Contains",
                    "negate_condition": False,
                    "match_value": ["evil"],
                    "transforms": [],
                }
            ],
            "action": "Block",
        }
        result = adapter.normalize_rule(rule)
        assert result["matchConditions"][0]["matchVariable"] == "Cookies"
        denorm = adapter.denormalize_rule(result)
        assert denorm["match_conditions"][0]["match_variable"] == "Cookies"
