"""Tests for Azure WAF managed rule set phase (adapter, provider, validation)."""

from unittest.mock import MagicMock

from octorules.provider.base import PhaseRulesResult, Scope

from octorules_azure._adapters import AppGatewayAdapter, FrontDoorAdapter
from octorules_azure.provider import AzureWafProvider
from octorules_azure.validate import set_waf_type, validate_managed_rules
from tests.conftest import _make_ag_policy, _make_fd_policy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _ids(results):
    """Extract rule IDs from a list of LintResults."""
    return [r.rule_id for r in results]


def _managed_rule_set(
    rule_set_type="Microsoft_DefaultRuleSet",
    rule_set_version="2.1",
    **overrides,
) -> dict:
    """Build a canonical (normalised) managed rule set dict for testing."""
    base = {
        "ref": rule_set_type,
        "ruleSetType": rule_set_type,
        "ruleSetVersion": rule_set_version,
    }
    base.update(overrides)
    return base


def _make_provider(client=None, waf_type="front_door", **kwargs):
    """Create provider with mock client."""
    return AzureWafProvider(
        subscription_id="sub-123",
        resource_group="rg-test",
        waf_type=waf_type,
        client=client or MagicMock(),
        **kwargs,
    )


# ===========================================================================
# Adapter tests -- Front Door
# ===========================================================================
class TestFrontDoorExtractManagedRules:
    def setup_method(self):
        self.adapter = FrontDoorAdapter()

    def test_extract_managed_rules(self):
        policy = _make_fd_policy(
            managed_rules={
                "managed_rule_sets": [
                    {"rule_set_type": "Microsoft_DefaultRuleSet", "rule_set_version": "2.1"},
                ]
            }
        )
        result = self.adapter.extract_managed_rules(policy)
        assert len(result) == 1
        assert result[0]["rule_set_type"] == "Microsoft_DefaultRuleSet"

    def test_extract_managed_rules_empty(self):
        policy = _make_fd_policy(managed_rules={"managed_rule_sets": []})
        assert self.adapter.extract_managed_rules(policy) == []

    def test_extract_managed_rules_missing_key(self):
        policy = _make_fd_policy()
        policy.pop("managed_rules", None)
        assert self.adapter.extract_managed_rules(policy) == []

    def test_extract_managed_rules_none_value(self):
        policy = _make_fd_policy()
        policy["managed_rules"] = None
        assert self.adapter.extract_managed_rules(policy) == []


class TestFrontDoorReplaceManagedRules:
    def setup_method(self):
        self.adapter = FrontDoorAdapter()

    def test_replace_managed_rules_preserves_custom_and_settings(self):
        policy = _make_fd_policy(
            custom_rules=[{"name": "keep"}],
            managed_rules={"managed_rule_sets": [{"rule_set_type": "old"}]},
        )
        new_rules = [{"rule_set_type": "new"}]
        updated = self.adapter.replace_managed_rules(policy, new_rules)
        # Managed rules replaced
        assert updated["managed_rules"]["managed_rule_sets"] == new_rules
        # Custom rules and policy settings preserved
        assert updated["custom_rules"]["rules"] == [{"name": "keep"}]
        assert updated["policy_settings"]["mode"] == "Prevention"
        # Original unchanged
        assert policy["managed_rules"]["managed_rule_sets"] == [{"rule_set_type": "old"}]

    def test_replace_managed_rules_creates_managed_key(self):
        policy = {"custom_rules": {"rules": []}}
        updated = self.adapter.replace_managed_rules(policy, [{"rule_set_type": "new"}])
        assert updated["managed_rules"]["managed_rule_sets"] == [{"rule_set_type": "new"}]


class TestFrontDoorNormalizeManagedRule:
    def setup_method(self):
        self.adapter = FrontDoorAdapter()

    def test_basic_normalization(self):
        raw = {
            "rule_set_type": "Microsoft_DefaultRuleSet",
            "rule_set_version": "2.1",
            "rule_set_action": "Block",
        }
        result = self.adapter.normalize_managed_rule(raw)
        assert result["ref"] == "Microsoft_DefaultRuleSet"
        assert result["ruleSetType"] == "Microsoft_DefaultRuleSet"
        assert result["ruleSetVersion"] == "2.1"
        assert result["ruleSetAction"] == "Block"

    def test_with_rule_group_overrides_and_exclusions(self):
        raw = {
            "rule_set_type": "Microsoft_DefaultRuleSet",
            "rule_set_version": "2.1",
            "rule_set_action": "Block",
            "rule_group_overrides": [
                {
                    "rule_group_name": "SQLI",
                    "exclusions": [
                        {
                            "match_variable": "RequestHeaderNames",
                            "selector_match_operator": "Equals",
                            "selector": "x-custom",
                        }
                    ],
                    "rules": [
                        {
                            "rule_id": "942100",
                            "enabled_state": "Disabled",
                            "action": "Log",
                            "exclusions": [
                                {
                                    "match_variable": "QueryStringArgNames",
                                    "selector_match_operator": "Equals",
                                    "selector": "q",
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        result = self.adapter.normalize_managed_rule(raw)
        assert result["ref"] == "Microsoft_DefaultRuleSet"
        assert result["ruleSetAction"] == "Block"
        assert len(result["ruleGroupOverrides"]) == 1

        group = result["ruleGroupOverrides"][0]
        assert group["ruleGroupName"] == "SQLI"
        assert len(group["exclusions"]) == 1
        assert group["exclusions"][0]["selector"] == "x-custom"

        rule = group["rules"][0]
        assert rule["ruleId"] == "942100"
        assert rule["enabledState"] == "Disabled"
        assert rule["action"] == "Log"
        assert len(rule["exclusions"]) == 1

    def test_without_rule_set_action(self):
        """ruleSetAction is optional on FD -- should be absent from result."""
        raw = {
            "rule_set_type": "Microsoft_DefaultRuleSet",
            "rule_set_version": "2.1",
        }
        result = self.adapter.normalize_managed_rule(raw)
        assert "ruleSetAction" not in result

    def test_empty_overrides_omitted(self):
        raw = {
            "rule_set_type": "Microsoft_DefaultRuleSet",
            "rule_set_version": "2.1",
            "rule_group_overrides": [],
        }
        result = self.adapter.normalize_managed_rule(raw)
        assert "ruleGroupOverrides" not in result

    def test_set_level_exclusions(self):
        """Top-level exclusions on a managed rule set are preserved."""
        raw = {
            "rule_set_type": "Microsoft_DefaultRuleSet",
            "rule_set_version": "2.1",
            "rule_set_action": "Block",
            "exclusions": [
                {
                    "match_variable": "RequestHeaderNames",
                    "selector_match_operator": "Equals",
                    "selector": "x-custom",
                }
            ],
        }
        result = self.adapter.normalize_managed_rule(raw)
        assert len(result["exclusions"]) == 1
        assert result["exclusions"][0]["selector"] == "x-custom"

    def test_empty_exclusions_omitted(self):
        raw = {
            "rule_set_type": "Microsoft_DefaultRuleSet",
            "rule_set_version": "2.1",
            "exclusions": [],
        }
        result = self.adapter.normalize_managed_rule(raw)
        assert "exclusions" not in result


class TestFrontDoorDenormalizeManagedRule:
    def setup_method(self):
        self.adapter = FrontDoorAdapter()

    def test_basic_denormalization(self):
        canonical = {
            "ref": "Microsoft_DefaultRuleSet",
            "ruleSetType": "Microsoft_DefaultRuleSet",
            "ruleSetVersion": "2.1",
            "ruleSetAction": "Block",
        }
        result = self.adapter.denormalize_managed_rule(canonical)
        assert result["rule_set_type"] == "Microsoft_DefaultRuleSet"
        assert result["rule_set_version"] == "2.1"
        assert result["rule_set_action"] == "Block"

    def test_with_overrides(self):
        canonical = {
            "ref": "Microsoft_DefaultRuleSet",
            "ruleSetType": "Microsoft_DefaultRuleSet",
            "ruleSetVersion": "2.1",
            "ruleGroupOverrides": [
                {
                    "ruleGroupName": "SQLI",
                    "rules": [
                        {
                            "ruleId": "942100",
                            "enabledState": "Disabled",
                            "action": "Log",
                        }
                    ],
                }
            ],
        }
        result = self.adapter.denormalize_managed_rule(canonical)
        assert len(result["rule_group_overrides"]) == 1
        group = result["rule_group_overrides"][0]
        assert group["rule_group_name"] == "SQLI"
        assert group["rules"][0]["rule_id"] == "942100"
        assert group["rules"][0]["enabled_state"] == "Disabled"

    def test_without_action_omits_key(self):
        canonical = {
            "ref": "Microsoft_DefaultRuleSet",
            "ruleSetType": "Microsoft_DefaultRuleSet",
            "ruleSetVersion": "2.1",
        }
        result = self.adapter.denormalize_managed_rule(canonical)
        assert "rule_set_action" not in result

    def test_set_level_exclusions(self):
        """Set-level exclusions are written back to SDK format."""
        canonical = {
            "ref": "Microsoft_DefaultRuleSet",
            "ruleSetType": "Microsoft_DefaultRuleSet",
            "ruleSetVersion": "2.1",
            "exclusions": [
                {
                    "match_variable": "RequestHeaderNames",
                    "selector_match_operator": "Equals",
                    "selector": "x-custom",
                }
            ],
        }
        result = self.adapter.denormalize_managed_rule(canonical)
        assert len(result["exclusions"]) == 1
        assert result["exclusions"][0]["selector"] == "x-custom"

    def test_without_exclusions_omits_key(self):
        canonical = {
            "ref": "Microsoft_DefaultRuleSet",
            "ruleSetType": "Microsoft_DefaultRuleSet",
            "ruleSetVersion": "2.1",
        }
        result = self.adapter.denormalize_managed_rule(canonical)
        assert "exclusions" not in result


class TestFrontDoorManagedRuleRoundTrip:
    def setup_method(self):
        self.adapter = FrontDoorAdapter()

    def test_roundtrip_basic(self):
        raw = {
            "rule_set_type": "Microsoft_DefaultRuleSet",
            "rule_set_version": "2.1",
            "rule_set_action": "Block",
        }
        normalised = self.adapter.normalize_managed_rule(raw)
        denormalised = self.adapter.denormalize_managed_rule(normalised)
        assert denormalised["rule_set_type"] == raw["rule_set_type"]
        assert denormalised["rule_set_version"] == raw["rule_set_version"]
        assert denormalised["rule_set_action"] == raw["rule_set_action"]

    def test_roundtrip_with_overrides(self):
        raw = {
            "rule_set_type": "Microsoft_DefaultRuleSet",
            "rule_set_version": "2.1",
            "rule_set_action": "Block",
            "rule_group_overrides": [
                {
                    "rule_group_name": "SQLI",
                    "exclusions": [
                        {
                            "match_variable": "RequestHeaderNames",
                            "selector_match_operator": "Equals",
                            "selector": "x-custom",
                        }
                    ],
                    "rules": [
                        {
                            "rule_id": "942100",
                            "enabled_state": "Disabled",
                            "action": "Log",
                            "exclusions": [
                                {
                                    "match_variable": "QueryStringArgNames",
                                    "selector_match_operator": "Equals",
                                    "selector": "q",
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        normalised = self.adapter.normalize_managed_rule(raw)
        denormalised = self.adapter.denormalize_managed_rule(normalised)
        assert denormalised["rule_set_type"] == "Microsoft_DefaultRuleSet"
        assert denormalised["rule_set_version"] == "2.1"
        assert denormalised["rule_set_action"] == "Block"
        group = denormalised["rule_group_overrides"][0]
        assert group["rule_group_name"] == "SQLI"
        assert len(group["exclusions"]) == 1
        assert group["rules"][0]["rule_id"] == "942100"
        assert group["rules"][0]["enabled_state"] == "Disabled"
        assert len(group["rules"][0]["exclusions"]) == 1

    def test_roundtrip_with_set_level_exclusions(self):
        raw = {
            "rule_set_type": "Microsoft_DefaultRuleSet",
            "rule_set_version": "2.1",
            "exclusions": [
                {
                    "match_variable": "RequestHeaderNames",
                    "selector_match_operator": "Equals",
                    "selector": "x-token",
                }
            ],
        }
        normalised = self.adapter.normalize_managed_rule(raw)
        assert len(normalised["exclusions"]) == 1
        denormalised = self.adapter.denormalize_managed_rule(normalised)
        assert denormalised["exclusions"] == raw["exclusions"]


# ===========================================================================
# Adapter tests -- Application Gateway
# ===========================================================================
class TestAppGatewayExtractManagedRules:
    def setup_method(self):
        self.adapter = AppGatewayAdapter()

    def test_extract_managed_rules(self):
        policy = _make_ag_policy(
            managed_rules={
                "managed_rule_sets": [
                    {"rule_set_type": "OWASP_CRS", "rule_set_version": "3.2"},
                ]
            }
        )
        result = self.adapter.extract_managed_rules(policy)
        assert len(result) == 1
        assert result[0]["rule_set_type"] == "OWASP_CRS"

    def test_extract_managed_rules_empty(self):
        policy = _make_ag_policy(managed_rules={"managed_rule_sets": []})
        assert self.adapter.extract_managed_rules(policy) == []

    def test_extract_managed_rules_missing_key(self):
        policy = _make_ag_policy()
        policy.pop("managed_rules", None)
        assert self.adapter.extract_managed_rules(policy) == []


class TestAppGatewayReplaceManagedRules:
    def setup_method(self):
        self.adapter = AppGatewayAdapter()

    def test_replace_managed_rules_preserves_custom(self):
        policy = _make_ag_policy(
            custom_rules=[{"name": "keep"}],
            managed_rules={"managed_rule_sets": [{"rule_set_type": "old"}]},
        )
        new_rules = [{"rule_set_type": "new"}]
        updated = self.adapter.replace_managed_rules(policy, new_rules)
        assert updated["managed_rules"]["managed_rule_sets"] == new_rules
        assert updated["custom_rules"] == [{"name": "keep"}]
        assert updated["policy_settings"]["mode"] == "Prevention"
        # Original unchanged
        assert policy["managed_rules"]["managed_rule_sets"] == [{"rule_set_type": "old"}]


class TestAppGatewayNormalizeManagedRule:
    def setup_method(self):
        self.adapter = AppGatewayAdapter()

    def test_basic_normalization(self):
        """AG format uses 'state' not 'enabled_state' in rule overrides."""
        raw = {
            "rule_set_type": "OWASP_CRS",
            "rule_set_version": "3.2",
            "rule_group_overrides": [
                {
                    "rule_group_name": "REQUEST-942-APPLICATION-ATTACK-SQLI",
                    "rules": [
                        {
                            "rule_id": "942100",
                            "state": "Disabled",
                            "action": "Log",
                        }
                    ],
                }
            ],
        }
        result = self.adapter.normalize_managed_rule(raw)
        assert result["ref"] == "OWASP_CRS"
        assert result["ruleSetType"] == "OWASP_CRS"
        assert result["ruleSetVersion"] == "3.2"
        # AG should NOT have ruleSetAction
        assert "ruleSetAction" not in result
        # state -> enabledState in canonical form
        group = result["ruleGroupOverrides"][0]
        assert group["ruleGroupName"] == "REQUEST-942-APPLICATION-ATTACK-SQLI"
        rule = group["rules"][0]
        assert rule["ruleId"] == "942100"
        assert rule["enabledState"] == "Disabled"
        assert rule["action"] == "Log"

    def test_without_overrides(self):
        raw = {
            "rule_set_type": "OWASP_CRS",
            "rule_set_version": "3.2",
        }
        result = self.adapter.normalize_managed_rule(raw)
        assert result["ref"] == "OWASP_CRS"
        assert "ruleGroupOverrides" not in result
        assert "ruleSetAction" not in result

    def test_set_level_exclusions(self):
        """Top-level exclusions on an AG managed rule set are preserved."""
        raw = {
            "rule_set_type": "OWASP_CRS",
            "rule_set_version": "3.2",
            "exclusions": [
                {
                    "match_variable": "RequestArgNames",
                    "selector_match_operator": "Equals",
                    "selector": "q",
                }
            ],
        }
        result = self.adapter.normalize_managed_rule(raw)
        assert len(result["exclusions"]) == 1
        assert result["exclusions"][0]["selector"] == "q"

    def test_empty_exclusions_omitted(self):
        raw = {
            "rule_set_type": "OWASP_CRS",
            "rule_set_version": "3.2",
            "exclusions": [],
        }
        result = self.adapter.normalize_managed_rule(raw)
        assert "exclusions" not in result


class TestAppGatewayDenormalizeManagedRule:
    def setup_method(self):
        self.adapter = AppGatewayAdapter()

    def test_basic_denormalization(self):
        """Canonical enabledState maps back to AG 'state'."""
        canonical = {
            "ref": "OWASP_CRS",
            "ruleSetType": "OWASP_CRS",
            "ruleSetVersion": "3.2",
            "ruleGroupOverrides": [
                {
                    "ruleGroupName": "REQUEST-942-APPLICATION-ATTACK-SQLI",
                    "rules": [
                        {
                            "ruleId": "942100",
                            "enabledState": "Disabled",
                            "action": "Log",
                        }
                    ],
                }
            ],
        }
        result = self.adapter.denormalize_managed_rule(canonical)
        assert result["rule_set_type"] == "OWASP_CRS"
        assert result["rule_set_version"] == "3.2"
        # AG should NOT have rule_set_action even if canonical had ruleSetAction
        assert "rule_set_action" not in result
        group = result["rule_group_overrides"][0]
        assert group["rule_group_name"] == "REQUEST-942-APPLICATION-ATTACK-SQLI"
        rule = group["rules"][0]
        assert rule["rule_id"] == "942100"
        assert rule["state"] == "Disabled"

    def test_skips_rule_set_action(self):
        """AG denormalize should skip ruleSetAction even if present in canonical form."""
        canonical = {
            "ref": "OWASP_CRS",
            "ruleSetType": "OWASP_CRS",
            "ruleSetVersion": "3.2",
            "ruleSetAction": "Block",  # should be ignored for AG
        }
        result = self.adapter.denormalize_managed_rule(canonical)
        assert "rule_set_action" not in result

    def test_set_level_exclusions(self):
        """Set-level exclusions are written back to AG SDK format."""
        canonical = {
            "ref": "OWASP_CRS",
            "ruleSetType": "OWASP_CRS",
            "ruleSetVersion": "3.2",
            "exclusions": [
                {
                    "match_variable": "RequestArgNames",
                    "selector_match_operator": "Equals",
                    "selector": "q",
                }
            ],
        }
        result = self.adapter.denormalize_managed_rule(canonical)
        assert len(result["exclusions"]) == 1
        assert result["exclusions"][0]["selector"] == "q"

    def test_without_exclusions_omits_key(self):
        canonical = {
            "ref": "OWASP_CRS",
            "ruleSetType": "OWASP_CRS",
            "ruleSetVersion": "3.2",
        }
        result = self.adapter.denormalize_managed_rule(canonical)
        assert "exclusions" not in result


class TestAppGatewayManagedRuleRoundTrip:
    def setup_method(self):
        self.adapter = AppGatewayAdapter()

    def test_roundtrip_basic(self):
        raw = {
            "rule_set_type": "OWASP_CRS",
            "rule_set_version": "3.2",
        }
        normalised = self.adapter.normalize_managed_rule(raw)
        denormalised = self.adapter.denormalize_managed_rule(normalised)
        assert denormalised["rule_set_type"] == raw["rule_set_type"]
        assert denormalised["rule_set_version"] == raw["rule_set_version"]

    def test_roundtrip_with_overrides(self):
        raw = {
            "rule_set_type": "OWASP_CRS",
            "rule_set_version": "3.2",
            "rule_group_overrides": [
                {
                    "rule_group_name": "REQUEST-942-APPLICATION-ATTACK-SQLI",
                    "exclusions": [
                        {
                            "match_variable": "RequestArgNames",
                            "selector_match_operator": "Equals",
                            "selector": "q",
                        }
                    ],
                    "rules": [
                        {
                            "rule_id": "942100",
                            "state": "Disabled",
                            "action": "Log",
                        }
                    ],
                }
            ],
        }
        normalised = self.adapter.normalize_managed_rule(raw)
        denormalised = self.adapter.denormalize_managed_rule(normalised)
        assert denormalised["rule_set_type"] == "OWASP_CRS"
        assert denormalised["rule_set_version"] == "3.2"
        group = denormalised["rule_group_overrides"][0]
        assert group["rule_group_name"] == "REQUEST-942-APPLICATION-ATTACK-SQLI"
        assert group["rules"][0]["rule_id"] == "942100"
        assert group["rules"][0]["state"] == "Disabled"

    def test_roundtrip_with_set_level_exclusions(self):
        raw = {
            "rule_set_type": "OWASP_CRS",
            "rule_set_version": "3.2",
            "exclusions": [
                {
                    "match_variable": "RequestArgNames",
                    "selector_match_operator": "Equals",
                    "selector": "token",
                }
            ],
        }
        normalised = self.adapter.normalize_managed_rule(raw)
        assert len(normalised["exclusions"]) == 1
        denormalised = self.adapter.denormalize_managed_rule(normalised)
        assert denormalised["exclusions"] == raw["exclusions"]


# ===========================================================================
# Provider tests
# ===========================================================================
class TestGetPhaseRulesManaged:
    def test_returns_normalized_managed_rules(self):
        client = MagicMock()
        p = _make_provider(client=client)
        policy = _make_fd_policy(
            managed_rules={
                "managed_rule_sets": [
                    {
                        "rule_set_type": "Microsoft_DefaultRuleSet",
                        "rule_set_version": "2.1",
                        "rule_set_action": "Block",
                    },
                ]
            }
        )
        client.policies.get.return_value = policy
        rules = p.get_phase_rules(Scope(zone_id="my-policy"), "azure_waf_managed")
        assert len(rules) == 1
        assert rules[0]["ref"] == "Microsoft_DefaultRuleSet"
        assert rules[0]["ruleSetType"] == "Microsoft_DefaultRuleSet"
        assert rules[0]["ruleSetVersion"] == "2.1"
        assert rules[0]["ruleSetAction"] == "Block"

    def test_empty_managed_returns_empty(self):
        client = MagicMock()
        p = _make_provider(client=client)
        policy = _make_fd_policy(managed_rules={"managed_rule_sets": []})
        client.policies.get.return_value = policy
        rules = p.get_phase_rules(Scope(zone_id="my-policy"), "azure_waf_managed")
        assert rules == []


class TestPutPhaseRulesManaged:
    def test_denormalizes_and_replaces_managed_rules(self):
        client = MagicMock()
        p = _make_provider(client=client)
        # Existing policy with managed rules
        policy = _make_fd_policy(
            custom_rules=[{"name": "keep", "rule_type": "MatchRule"}],
            managed_rules={
                "managed_rule_sets": [
                    {"rule_set_type": "old", "rule_set_version": "1.0"},
                ]
            },
        )
        client.policies.get.return_value = policy
        poller = MagicMock()
        poller.result.return_value = policy
        client.policies.begin_create_or_update.return_value = poller

        new_rules = [
            {
                "ref": "Microsoft_DefaultRuleSet",
                "ruleSetType": "Microsoft_DefaultRuleSet",
                "ruleSetVersion": "2.1",
                "ruleSetAction": "Block",
            }
        ]
        count = p.put_phase_rules(Scope(zone_id="my-policy"), "azure_waf_managed", new_rules)
        assert count == 1

        # Verify the PUT was called with updated managed rules
        call_args = client.policies.begin_create_or_update.call_args
        updated_policy = call_args[0][2]
        managed = updated_policy["managed_rules"]["managed_rule_sets"]
        assert len(managed) == 1
        assert managed[0]["rule_set_type"] == "Microsoft_DefaultRuleSet"
        assert managed[0]["rule_set_version"] == "2.1"
        # Custom rules should be preserved
        assert updated_policy["custom_rules"]["rules"] == [
            {"name": "keep", "rule_type": "MatchRule"}
        ]


class TestGetAllPhaseRulesIncludesManaged:
    def test_result_contains_managed_phase(self):
        client = MagicMock()
        p = _make_provider(client=client)
        policy = {
            "custom_rules": {
                "rules": [
                    {
                        "name": "C1",
                        "priority": 1,
                        "rule_type": "MatchRule",
                        "enabled_state": "Enabled",
                        "match_conditions": [
                            {
                                "match_variable": "RemoteAddr",
                                "selector": None,
                                "operator": "IPMatch",
                                "negate_condition": False,
                                "match_value": ["1.2.3.4"],
                                "transforms": [],
                            }
                        ],
                        "action": "Block",
                    },
                ]
            },
            "managed_rules": {
                "managed_rule_sets": [
                    {
                        "rule_set_type": "Microsoft_DefaultRuleSet",
                        "rule_set_version": "2.1",
                        "rule_set_action": "Block",
                    },
                ]
            },
        }
        client.policies.get.return_value = policy
        result = p.get_all_phase_rules(Scope(zone_id="my-policy"))
        assert isinstance(result, PhaseRulesResult)
        assert "azure_waf_custom" in result
        assert "azure_waf_managed" in result
        assert len(result["azure_waf_managed"]) == 1
        assert result["azure_waf_managed"][0]["ref"] == "Microsoft_DefaultRuleSet"
        assert result.failed_phases == []

    def test_empty_managed_not_in_result(self):
        client = MagicMock()
        p = _make_provider(client=client)
        policy = {
            "custom_rules": {
                "rules": [
                    {
                        "name": "C1",
                        "priority": 1,
                        "rule_type": "MatchRule",
                        "enabled_state": "Enabled",
                        "match_conditions": [
                            {
                                "match_variable": "RemoteAddr",
                                "selector": None,
                                "operator": "IPMatch",
                                "negate_condition": False,
                                "match_value": ["1.2.3.4"],
                                "transforms": [],
                            }
                        ],
                        "action": "Block",
                    },
                ]
            },
            "managed_rules": {"managed_rule_sets": []},
        }
        client.policies.get.return_value = policy
        result = p.get_all_phase_rules(Scope(zone_id="my-policy"))
        assert "azure_waf_managed" not in result
        assert "azure_waf_custom" in result


# ===========================================================================
# Validation tests
# ===========================================================================
class TestValidateManagedRulesValid:
    def test_valid_managed_rule(self):
        rules = [_managed_rule_set()]
        assert validate_managed_rules(rules) == []

    def test_multiple_valid_managed_rules(self):
        rules = [
            _managed_rule_set(rule_set_type="Microsoft_DefaultRuleSet"),
            _managed_rule_set(rule_set_type="Microsoft_BotManagerRuleSet"),
        ]
        assert validate_managed_rules(rules) == []


class TestValidateManagedRef:
    """AZ700: Managed rule set must have a valid ref."""

    def test_missing_ref(self):
        rule = _managed_rule_set()
        del rule["ref"]
        results = validate_managed_rules([rule])
        assert "AZ700" in _ids(results)

    def test_empty_ref(self):
        rule = _managed_rule_set()
        rule["ref"] = ""
        results = validate_managed_rules([rule])
        assert "AZ700" in _ids(results)

    def test_duplicate_refs(self):
        rules = [
            _managed_rule_set(rule_set_type="Microsoft_DefaultRuleSet"),
            _managed_rule_set(rule_set_type="Microsoft_DefaultRuleSet"),
        ]
        results = validate_managed_rules(rules)
        ids = _ids(results)
        assert "AZ700" in ids  # duplicate ref


class TestValidateRuleSetType:
    """AZ701: ruleSetType validation."""

    def test_missing_rule_set_type(self):
        rule = _managed_rule_set()
        del rule["ruleSetType"]
        results = validate_managed_rules([rule])
        assert "AZ701" in _ids(results)

    def test_empty_rule_set_type(self):
        rule = _managed_rule_set()
        rule["ruleSetType"] = ""
        results = validate_managed_rules([rule])
        assert "AZ701" in _ids(results)

    def test_non_string_rule_set_type(self):
        rule = _managed_rule_set()
        rule["ruleSetType"] = 123
        results = validate_managed_rules([rule])
        assert "AZ701" in _ids(results)
        # Should be ERROR severity
        az701 = [r for r in results if r.rule_id == "AZ701"]
        assert az701[0].severity.name == "ERROR"

    def test_unknown_rule_set_type_warns(self):
        rule = _managed_rule_set(rule_set_type="UnknownRuleSet")
        results = validate_managed_rules([rule])
        az701 = [r for r in results if r.rule_id == "AZ701"]
        assert len(az701) == 1
        assert az701[0].severity.name == "WARNING"


class TestValidateRuleSetAction:
    """AZ702: ruleSetAction (Front Door only)."""

    def test_valid_rule_set_action(self):
        set_waf_type("front_door")
        rule = _managed_rule_set(ruleSetAction="Block")
        results = validate_managed_rules([rule])
        assert "AZ702" not in _ids(results)

    def test_rule_set_action_on_app_gateway(self):
        """ruleSetAction is FD-only; should warn on AG (AZ705)."""
        set_waf_type("app_gateway")
        rule = _managed_rule_set(ruleSetAction="Block")
        results = validate_managed_rules([rule])
        assert "AZ705" in _ids(results)
        az705 = [r for r in results if r.rule_id == "AZ705"]
        assert az705[0].severity.name == "WARNING"

    def test_invalid_rule_set_action(self):
        set_waf_type("front_door")
        rule = _managed_rule_set(ruleSetAction="InvalidAction")
        results = validate_managed_rules([rule])
        assert "AZ702" in _ids(results)

    def test_missing_rule_set_action_ok(self):
        """ruleSetAction is optional -- missing should not produce errors."""
        set_waf_type("front_door")
        rule = _managed_rule_set()
        results = validate_managed_rules([rule])
        assert "AZ702" not in _ids(results)


class TestValidateManagedEnabledState:
    """AZ703: enabledState in rule overrides."""

    def test_invalid_enabled_state_in_override(self):
        rule = _managed_rule_set(
            ruleGroupOverrides=[
                {
                    "ruleGroupName": "SQLI",
                    "rules": [
                        {
                            "ruleId": "942100",
                            "enabledState": "BadValue",
                        }
                    ],
                }
            ],
        )
        results = validate_managed_rules([rule])
        assert "AZ703" in _ids(results)

    def test_valid_enabled_state_in_override(self):
        rule = _managed_rule_set(
            ruleGroupOverrides=[
                {
                    "ruleGroupName": "SQLI",
                    "rules": [
                        {
                            "ruleId": "942100",
                            "enabledState": "Disabled",
                        }
                    ],
                }
            ],
        )
        results = validate_managed_rules([rule])
        assert "AZ703" not in _ids(results)

    def test_missing_enabled_state_ok(self):
        """enabledState is optional in overrides."""
        rule = _managed_rule_set(
            ruleGroupOverrides=[
                {
                    "ruleGroupName": "SQLI",
                    "rules": [
                        {
                            "ruleId": "942100",
                        }
                    ],
                }
            ],
        )
        results = validate_managed_rules([rule])
        assert "AZ703" not in _ids(results)


class TestValidateRuleGroupOverrides:
    """AZ704: ruleGroupOverrides structure."""

    def test_non_list_overrides(self):
        rule = _managed_rule_set(ruleGroupOverrides="bad")
        results = validate_managed_rules([rule])
        assert "AZ704" in _ids(results)

    def test_non_dict_entry(self):
        rule = _managed_rule_set(ruleGroupOverrides=["bad"])
        results = validate_managed_rules([rule])
        assert "AZ704" in _ids(results)

    def test_missing_rule_group_name(self):
        rule = _managed_rule_set(
            ruleGroupOverrides=[{"rules": []}],
        )
        results = validate_managed_rules([rule])
        assert "AZ704" in _ids(results)

    def test_empty_rule_group_name(self):
        rule = _managed_rule_set(
            ruleGroupOverrides=[{"ruleGroupName": "", "rules": []}],
        )
        results = validate_managed_rules([rule])
        assert "AZ704" in _ids(results)

    def test_valid_rule_group_overrides(self):
        rule = _managed_rule_set(
            ruleGroupOverrides=[
                {
                    "ruleGroupName": "SQLI",
                    "rules": [
                        {"ruleId": "942100", "enabledState": "Disabled"},
                    ],
                }
            ],
        )
        results = validate_managed_rules([rule])
        assert "AZ704" not in _ids(results)

    def test_non_list_rules_in_group(self):
        rule = _managed_rule_set(
            ruleGroupOverrides=[
                {"ruleGroupName": "SQLI", "rules": "bad"},
            ],
        )
        results = validate_managed_rules([rule])
        assert "AZ704" in _ids(results)

    def test_none_overrides_ok(self):
        """ruleGroupOverrides is optional."""
        rule = _managed_rule_set()
        results = validate_managed_rules([rule])
        assert "AZ704" not in _ids(results)


class TestValidateRuleOverrideRuleId:
    """AZ706: ruleId validation in rule overrides."""

    def test_missing_rule_id(self):
        rule = _managed_rule_set(
            ruleGroupOverrides=[
                {
                    "ruleGroupName": "SQLI",
                    "rules": [
                        {"enabledState": "Disabled"},
                    ],
                }
            ],
        )
        results = validate_managed_rules([rule])
        assert "AZ706" in _ids(results)

    def test_empty_rule_id(self):
        rule = _managed_rule_set(
            ruleGroupOverrides=[
                {
                    "ruleGroupName": "SQLI",
                    "rules": [
                        {"ruleId": "", "enabledState": "Disabled"},
                    ],
                }
            ],
        )
        results = validate_managed_rules([rule])
        assert "AZ706" in _ids(results)

    def test_non_string_rule_id(self):
        rule = _managed_rule_set(
            ruleGroupOverrides=[
                {
                    "ruleGroupName": "SQLI",
                    "rules": [
                        {"ruleId": 942100, "enabledState": "Disabled"},
                    ],
                }
            ],
        )
        results = validate_managed_rules([rule])
        assert "AZ706" in _ids(results)

    def test_valid_rule_id(self):
        rule = _managed_rule_set(
            ruleGroupOverrides=[
                {
                    "ruleGroupName": "SQLI",
                    "rules": [
                        {"ruleId": "942100", "enabledState": "Disabled"},
                    ],
                }
            ],
        )
        results = validate_managed_rules([rule])
        assert "AZ706" not in _ids(results)


class TestValidateRuleOverrideAction:
    """AZ707: action validation in rule overrides."""

    def test_invalid_action_in_override(self):
        rule = _managed_rule_set(
            ruleGroupOverrides=[
                {
                    "ruleGroupName": "SQLI",
                    "rules": [
                        {"ruleId": "942100", "action": "InvalidAction"},
                    ],
                }
            ],
        )
        results = validate_managed_rules([rule])
        assert "AZ707" in _ids(results)
        az707 = [r for r in results if r.rule_id == "AZ707"]
        assert az707[0].severity.name == "ERROR"

    def test_non_string_action_in_override(self):
        rule = _managed_rule_set(
            ruleGroupOverrides=[
                {
                    "ruleGroupName": "SQLI",
                    "rules": [
                        {"ruleId": "942100", "action": 123},
                    ],
                }
            ],
        )
        results = validate_managed_rules([rule])
        assert "AZ707" in _ids(results)

    def test_valid_action_in_override(self):
        rule = _managed_rule_set(
            ruleGroupOverrides=[
                {
                    "ruleGroupName": "SQLI",
                    "rules": [
                        {"ruleId": "942100", "action": "Block"},
                    ],
                }
            ],
        )
        results = validate_managed_rules([rule])
        assert "AZ707" not in _ids(results)

    def test_missing_action_ok(self):
        """action is optional in rule overrides."""
        rule = _managed_rule_set(
            ruleGroupOverrides=[
                {
                    "ruleGroupName": "SQLI",
                    "rules": [
                        {"ruleId": "942100", "enabledState": "Disabled"},
                    ],
                }
            ],
        )
        results = validate_managed_rules([rule])
        assert "AZ707" not in _ids(results)
