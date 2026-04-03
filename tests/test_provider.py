"""Tests for AzureWafProvider."""

from unittest.mock import MagicMock, patch

import pytest
from azure.core.exceptions import (
    ClientAuthenticationError,
    HttpResponseError,
    ResourceNotFoundError,
    ServiceRequestError,
)
from octorules.config import ConfigError
from octorules.provider.exceptions import (
    ProviderAuthError,
    ProviderConnectionError,
    ProviderError,
)

from octorules_azure.provider import AzureWafProvider


def _make_provider(client=None, waf_type="front_door", **kwargs):
    """Create provider with mock client."""
    return AzureWafProvider(
        subscription_id="sub-123",
        resource_group="rg-test",
        waf_type=waf_type,
        client=client or MagicMock(),
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------
class TestConfig:
    def test_missing_subscription_id(self):
        with pytest.raises(ConfigError, match="subscription_id"):
            AzureWafProvider(
                subscription_id="",
                resource_group="rg",
                waf_type="front_door",
                client=MagicMock(),
            )

    def test_missing_resource_group(self):
        with pytest.raises(ConfigError, match="resource_group"):
            AzureWafProvider(
                subscription_id="sub",
                resource_group="",
                waf_type="front_door",
                client=MagicMock(),
            )

    def test_invalid_waf_type(self):
        with pytest.raises(ConfigError, match="Invalid waf_type"):
            AzureWafProvider(
                subscription_id="sub",
                resource_group="rg",
                waf_type="invalid",
                client=MagicMock(),
            )

    def test_valid_front_door(self):
        p = _make_provider(waf_type="front_door")
        assert p._adapter.waf_type == "front_door"

    def test_valid_app_gateway(self):
        p = _make_provider(waf_type="app_gateway")
        assert p._adapter.waf_type == "app_gateway"

    @patch.dict(
        "os.environ",
        {"AZURE_SUBSCRIPTION_ID": "env-sub", "AZURE_RESOURCE_GROUP": "env-rg"},
    )
    def test_env_var_fallback(self):
        p = AzureWafProvider(waf_type="front_door", client=MagicMock())
        assert p._subscription_id == "env-sub"
        assert p._resource_group == "env-rg"

    @patch.dict(
        "os.environ",
        {
            "AZURE_SUBSCRIPTION_ID": "s",
            "AZURE_RESOURCE_GROUP": "r",
            "AZURE_WAF_TYPE": "app_gateway",
        },
    )
    def test_waf_type_env_var_fallback(self):
        p = AzureWafProvider(client=MagicMock())
        assert p._adapter.waf_type == "app_gateway"


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------
class TestProperties:
    def test_max_workers(self):
        p = _make_provider(max_workers=4)
        assert p.max_workers == 4

    def test_max_workers_default(self):
        p = _make_provider()
        assert p.max_workers == 1

    def test_account_id(self):
        p = _make_provider()
        assert p.account_id == "sub-123"

    def test_account_name(self):
        p = _make_provider()
        assert p.account_name is None

    def test_zone_plans(self):
        p = _make_provider()
        assert p.zone_plans == {}

    def test_supports(self):
        assert AzureWafProvider.SUPPORTS == frozenset({"zone_discovery"})


# ---------------------------------------------------------------------------
# Zone resolution
# ---------------------------------------------------------------------------
class TestResolveZoneId:
    def test_found(self):
        client = MagicMock()
        p = _make_provider(client=client)
        # Mock get_policy to succeed (policy exists)
        client.policies.get.return_value = MagicMock()
        zone_id = p.resolve_zone_id("my-policy")
        assert zone_id == "my-policy"

    def test_not_found(self):
        client = MagicMock()
        p = _make_provider(client=client)
        client.policies.get.side_effect = ResourceNotFoundError("not found")
        with pytest.raises(ConfigError, match="not found"):
            p.resolve_zone_id("missing-policy")


class TestListZones:
    def test_lists_policies(self):
        client = MagicMock()
        p = _make_provider(client=client)
        mock_p1 = MagicMock()
        mock_p1.__iter__ = MagicMock(return_value=iter([]))
        # Mock list to return policy-like objects
        policy1 = {"name": "policy-a"}
        policy2 = {"name": "policy-b"}
        client.policies.list.return_value = [policy1, policy2]
        result = p.list_zones()
        assert result == ["policy-a", "policy-b"]


# ---------------------------------------------------------------------------
# Phase rules
# ---------------------------------------------------------------------------
class TestGetPhaseRules:
    def _setup(self):
        client = MagicMock()
        p = _make_provider(client=client)
        policy = {
            "custom_rules": {
                "rules": [
                    {
                        "name": "Custom1",
                        "priority": 1,
                        "enabled_state": "Enabled",
                        "rule_type": "MatchRule",
                        "match_conditions": [
                            {
                                "match_variable": "RemoteAddr",
                                "selector": None,
                                "operator": "IPMatch",
                                "negate_condition": False,
                                "match_value": ["10.0.0.0/8"],
                                "transforms": [],
                            }
                        ],
                        "action": "Block",
                    },
                    {
                        "name": "Rate1",
                        "priority": 10,
                        "enabled_state": "Enabled",
                        "rule_type": "RateLimitRule",
                        "match_conditions": [
                            {
                                "match_variable": "RequestUri",
                                "selector": None,
                                "operator": "Any",
                                "negate_condition": False,
                                "match_value": [],
                                "transforms": [],
                            }
                        ],
                        "action": "Block",
                        "rate_limit_duration_in_minutes": 5,
                        "rate_limit_threshold": 200,
                        "group_by": [],
                    },
                ]
            },
            "managed_rules": {},
        }
        client.policies.get.return_value = policy
        return p

    def test_custom_phase(self):
        from octorules.provider.base import Scope

        p = self._setup()
        rules = p.get_phase_rules(Scope(zone_id="my-policy"), "azure_waf_custom")
        assert len(rules) == 1
        assert rules[0]["ref"] == "Custom1"

    def test_rate_phase(self):
        from octorules.provider.base import Scope

        p = self._setup()
        rules = p.get_phase_rules(Scope(zone_id="my-policy"), "azure_waf_rate")
        assert len(rules) == 1
        assert rules[0]["ref"] == "Rate1"

    def test_unknown_phase_returns_empty(self):
        from octorules.provider.base import Scope

        p = self._setup()
        assert p.get_phase_rules(Scope(zone_id="my-policy"), "unknown_phase") == []


class TestGetAllPhaseRules:
    def test_splits_into_phases(self):
        from octorules.provider.base import Scope

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
                    {
                        "name": "R1",
                        "priority": 2,
                        "rule_type": "RateLimitRule",
                        "enabled_state": "Enabled",
                        "match_conditions": [
                            {
                                "match_variable": "RequestUri",
                                "selector": None,
                                "operator": "Any",
                                "negate_condition": False,
                                "match_value": [],
                                "transforms": [],
                            }
                        ],
                        "action": "Block",
                        "rate_limit_duration_in_minutes": 1,
                        "rate_limit_threshold": 100,
                        "group_by": [],
                    },
                ]
            },
        }
        client.policies.get.return_value = policy
        result = p.get_all_phase_rules(Scope(zone_id="my-policy"))
        assert "azure_waf_custom" in result
        assert "azure_waf_rate" in result
        assert len(result["azure_waf_custom"]) == 1
        assert len(result["azure_waf_rate"]) == 1
        assert result.failed_phases == []

    def test_filter_phases(self):
        from octorules.provider.base import Scope

        client = MagicMock()
        p = _make_provider(client=client)
        policy = {"custom_rules": {"rules": []}}
        client.policies.get.return_value = policy
        result = p.get_all_phase_rules(Scope(zone_id="p"), provider_ids=["azure_waf_custom"])
        assert result.failed_phases == []

    def test_ignores_non_azure_phase_ids(self):
        from octorules.provider.base import Scope

        client = MagicMock()
        p = _make_provider(client=client)
        result = p.get_all_phase_rules(Scope(zone_id="p"), provider_ids=["aws_waf_custom"])
        assert dict(result) == {}


# ---------------------------------------------------------------------------
# Put phase rules
# ---------------------------------------------------------------------------
class TestPutPhaseRules:
    def test_preserves_other_phases(self):
        from octorules.provider.base import Scope

        client = MagicMock()
        p = _make_provider(client=client)
        # Existing policy has both custom and rate rules
        policy = {
            "custom_rules": {
                "rules": [
                    {
                        "name": "ExistingCustom",
                        "priority": 1,
                        "rule_type": "MatchRule",
                        "enabled_state": "Enabled",
                        "match_conditions": [],
                        "action": "Block",
                    },
                    {
                        "name": "ExistingRate",
                        "priority": 10,
                        "rule_type": "RateLimitRule",
                        "enabled_state": "Enabled",
                        "match_conditions": [],
                        "action": "Block",
                        "rate_limit_duration_in_minutes": 1,
                        "rate_limit_threshold": 100,
                        "group_by": [],
                    },
                ]
            },
        }
        client.policies.get.return_value = policy

        poller = MagicMock()
        poller.result.return_value = policy
        client.policies.begin_create_or_update.return_value = poller

        # Replace only custom rules
        new_rules = [
            {
                "ref": "NewCustom",
                "priority": 5,
                "ruleType": "MatchRule",
                "enabledState": "Enabled",
                "matchConditions": [
                    {
                        "matchVariable": "RemoteAddr",
                        "selector": None,
                        "operator": "IPMatch",
                        "negateCondition": False,
                        "matchValue": ["1.2.3.4"],
                        "transforms": [],
                    }
                ],
                "action": "Allow",
            }
        ]
        count = p.put_phase_rules(Scope(zone_id="my-policy"), "azure_waf_custom", new_rules)
        assert count == 1

        # Verify the PUT was called with both rate (preserved) and new custom rules
        call_args = client.policies.begin_create_or_update.call_args
        updated_policy = call_args[0][2]
        all_rules = updated_policy["custom_rules"]["rules"]
        # Should have the preserved rate rule + the new custom rule
        assert len(all_rules) == 2


# ---------------------------------------------------------------------------
# Unsupported methods
# ---------------------------------------------------------------------------
class TestUnsupportedMethods:
    def test_list_custom_rulesets(self):
        from octorules.provider.base import Scope

        p = _make_provider()
        assert p.list_custom_rulesets(Scope(zone_id="z")) == []

    def test_get_custom_ruleset(self):
        from octorules.provider.base import Scope

        p = _make_provider()
        assert p.get_custom_ruleset(Scope(zone_id="z"), "id") == []

    def test_put_custom_ruleset_raises(self):
        from octorules.provider.base import Scope

        p = _make_provider()
        with pytest.raises(ConfigError, match="not supported"):
            p.put_custom_ruleset(Scope(zone_id="z"), "id", [])

    def test_create_custom_ruleset_raises(self):
        from octorules.provider.base import Scope

        p = _make_provider()
        with pytest.raises(ConfigError, match="not supported"):
            p.create_custom_ruleset(Scope(zone_id="z"), "name", "phase", 100)

    def test_delete_custom_ruleset_raises(self):
        from octorules.provider.base import Scope

        p = _make_provider()
        with pytest.raises(ConfigError, match="not supported"):
            p.delete_custom_ruleset(Scope(zone_id="z"), "id")

    def test_get_all_custom_rulesets(self):
        from octorules.provider.base import Scope

        p = _make_provider()
        assert p.get_all_custom_rulesets(Scope(zone_id="z")) == {}

    def test_list_lists(self):
        from octorules.provider.base import Scope

        p = _make_provider()
        assert p.list_lists(Scope(zone_id="z")) == []

    def test_create_list_raises(self):
        from octorules.provider.base import Scope

        p = _make_provider()
        with pytest.raises(ConfigError, match="not supported"):
            p.create_list(Scope(zone_id="z"), "name", "ip")

    def test_delete_list_raises(self):
        from octorules.provider.base import Scope

        p = _make_provider()
        with pytest.raises(ConfigError, match="not supported"):
            p.delete_list(Scope(zone_id="z"), "id")

    def test_update_list_description_raises(self):
        from octorules.provider.base import Scope

        p = _make_provider()
        with pytest.raises(ConfigError, match="not supported"):
            p.update_list_description(Scope(zone_id="z"), "id", "desc")

    def test_get_list_items(self):
        from octorules.provider.base import Scope

        p = _make_provider()
        assert p.get_list_items(Scope(zone_id="z"), "id") == []

    def test_put_list_items_raises(self):
        from octorules.provider.base import Scope

        p = _make_provider()
        with pytest.raises(ConfigError, match="not supported"):
            p.put_list_items(Scope(zone_id="z"), "id", [])

    def test_get_all_lists(self):
        from octorules.provider.base import Scope

        p = _make_provider()
        assert p.get_all_lists(Scope(zone_id="z")) == {}

    def test_poll_bulk_operation(self):
        from octorules.provider.base import Scope

        p = _make_provider()
        assert p.poll_bulk_operation(Scope(zone_id="z"), "op-id") == "completed"


# ---------------------------------------------------------------------------
# Error wrapping
# ---------------------------------------------------------------------------
@patch("octorules.retry.time.sleep")
class TestErrorWrapping:
    def test_auth_error(self, _sleep):
        client = MagicMock()
        p = _make_provider(client=client)
        client.policies.get.side_effect = ClientAuthenticationError("bad creds")
        with pytest.raises(ProviderAuthError):
            p.resolve_zone_id("test")

    def test_connection_error(self, _sleep):
        client = MagicMock()
        p = _make_provider(client=client)
        client.policies.get.side_effect = ServiceRequestError("no connection")
        with pytest.raises(ProviderConnectionError):
            p.resolve_zone_id("test")

    def test_generic_http_error(self, _sleep):
        client = MagicMock()
        p = _make_provider(client=client)
        client.policies.get.side_effect = HttpResponseError("server error")
        with pytest.raises(ProviderError):
            p.resolve_zone_id("test")

    def test_http_error_with_auth_code_classified_as_auth(self, _sleep):
        client = MagicMock()
        p = _make_provider(client=client)
        err = HttpResponseError("forbidden")
        err.error = MagicMock()
        err.error.code = "AuthorizationFailed"
        client.policies.get.side_effect = err
        with pytest.raises(ProviderAuthError):
            p.resolve_zone_id("test")


# ---------------------------------------------------------------------------
# ETag retry
# ---------------------------------------------------------------------------
class TestETagRetry:
    @patch("octorules.retry.time.sleep")
    def test_retries_on_412(self, _sleep):
        from octorules.provider.base import Scope

        client = MagicMock()
        p = _make_provider(client=client)

        # First GET+PUT fails with 412, second succeeds
        call_count = 0
        policy = {
            "custom_rules": {"rules": []},
            "managed_rules": {},
        }

        def mock_get(*args, **kwargs):
            return policy

        client.policies.get.side_effect = mock_get

        def mock_put(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                err = HttpResponseError("precondition failed")
                err.status_code = 412
                raise err
            poller = MagicMock()
            poller.result.return_value = policy
            return poller

        client.policies.begin_create_or_update.side_effect = mock_put

        count = p.put_phase_rules(Scope(zone_id="my-policy"), "azure_waf_custom", [])
        assert count == 0
        assert call_count == 2  # Retried once

    def test_non_412_propagates_immediately(self):
        from octorules.provider.base import Scope

        client = MagicMock()
        p = _make_provider(client=client)

        policy = {"custom_rules": {"rules": []}}
        client.policies.get.return_value = policy

        err = HttpResponseError("internal server error")
        err.status_code = 500
        client.policies.begin_create_or_update.side_effect = err

        with pytest.raises(ProviderError, match="internal server error"):
            p.put_phase_rules(Scope(zone_id="my-policy"), "azure_waf_custom", [])


# ---------------------------------------------------------------------------
# App Gateway code path
# ---------------------------------------------------------------------------
class TestAppGatewayProvider:
    def test_put_phase_rules_uses_create_or_update(self):
        """App Gateway uses synchronous create_or_update, not begin_create_or_update."""
        from octorules.provider.base import Scope

        client = MagicMock()
        p = _make_provider(client=client, waf_type="app_gateway")

        policy = {"custom_rules": [], "managed_rules": {}}
        client.web_application_firewall_policies.get.return_value = policy
        client.web_application_firewall_policies.create_or_update.return_value = policy

        count = p.put_phase_rules(Scope(zone_id="my-policy"), "azure_waf_custom", [])
        assert count == 0
        client.web_application_firewall_policies.create_or_update.assert_called_once()


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------
class TestProviderEdgeCases:
    def test_get_all_phase_rules_empty_policy(self):
        from octorules.provider.base import Scope

        client = MagicMock()
        p = _make_provider(client=client)
        client.policies.get.return_value = {"custom_rules": {"rules": []}}
        result = p.get_all_phase_rules(Scope(zone_id="p"))
        assert dict(result) == {}
        assert result.failed_phases == []

    def test_list_zones_empty(self):
        client = MagicMock()
        p = _make_provider(client=client)
        client.policies.list.return_value = []
        assert p.list_zones() == []

    def test_get_phase_rules_empty_policy(self):
        from octorules.provider.base import Scope

        client = MagicMock()
        p = _make_provider(client=client)
        client.policies.get.return_value = {"custom_rules": {"rules": []}}
        result = p.get_phase_rules(Scope(zone_id="p"), "azure_waf_custom")
        assert result == []

    def test_resolve_zone_id_returns_name(self):
        client = MagicMock()
        p = _make_provider(client=client)
        client.policies.get.return_value = MagicMock()
        assert p.resolve_zone_id("test-policy") == "test-policy"

    def test_get_all_phase_rules_with_both_phases(self):
        from octorules.provider.base import Scope

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
        }
        client.policies.get.return_value = policy
        result = p.get_all_phase_rules(Scope(zone_id="p"), provider_ids=None)
        assert "azure_waf_custom" in result
        assert len(result["azure_waf_custom"]) == 1

    def test_get_all_phase_rules_missing_custom_rules_key(self):
        from octorules.provider.base import Scope

        client = MagicMock()
        p = _make_provider(client=client)
        # Policy dict with no custom_rules key at all
        client.policies.get.return_value = {"managed_rules": {}}
        result = p.get_all_phase_rules(Scope(zone_id="p"))
        assert dict(result) == {}
        assert result.failed_phases == []


# ---------------------------------------------------------------------------
# Protocol compliance
# ---------------------------------------------------------------------------
class TestProtocolCompliance:
    def test_isinstance_base_provider(self):
        from octorules.provider.base import BaseProvider

        p = _make_provider()
        assert isinstance(p, BaseProvider)


# ---------------------------------------------------------------------------
# Transient retry
# ---------------------------------------------------------------------------
class TestTransientRetry:
    @patch("octorules.retry.time.sleep")
    def test_retries_on_500(self, _sleep):
        client = MagicMock()
        p = _make_provider(client=client)

        call_count = 0

        def mock_get(*a, **kw):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                err = HttpResponseError("server error")
                err.status_code = 500
                raise err
            return {"name": "p1"}

        client.policies.list.side_effect = lambda rg: [mock_get()]
        # Use resolve_zone_id which wraps with _retry_transient
        client.policies.get.side_effect = mock_get
        result = p.resolve_zone_id("p1")
        assert result == "p1"
        assert call_count == 2

    def test_auth_error_not_retried(self):
        client = MagicMock()
        p = _make_provider(client=client)
        client.policies.get.side_effect = ClientAuthenticationError("bad creds")
        with pytest.raises(ProviderAuthError):
            p.resolve_zone_id("test")

    @patch("octorules.retry.time.sleep")
    def test_retries_on_429(self, _sleep):
        client = MagicMock()
        p = _make_provider(client=client)

        call_count = 0

        def mock_get(*a, **kw):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                err = HttpResponseError("throttled")
                err.status_code = 429
                raise err
            return {"name": "p1"}

        client.policies.get.side_effect = mock_get
        result = p.resolve_zone_id("p1")
        assert result == "p1"
        assert call_count == 2


# ---------------------------------------------------------------------------
# ETag retry exhaustion
# ---------------------------------------------------------------------------
class TestETagExhaustion:
    @patch("octorules.retry.time.sleep")
    def test_all_retries_fail(self, _sleep):
        from octorules.provider.base import Scope

        client = MagicMock()
        p = _make_provider(client=client)

        policy = {"custom_rules": {"rules": []}, "managed_rules": {}}
        client.policies.get.return_value = policy

        err = HttpResponseError("precondition failed")
        err.status_code = 412
        client.policies.begin_create_or_update.side_effect = err

        with pytest.raises(ProviderError, match="precondition failed"):
            p.put_phase_rules(Scope(zone_id="my-policy"), "azure_waf_custom", [])

        # Should have tried 3 times (initial + 2 retries)
        assert client.policies.begin_create_or_update.call_count == 3


# ---------------------------------------------------------------------------
# Integration: normalize -> validate -> denormalize roundtrip
# ---------------------------------------------------------------------------
class TestNormalizeValidateDenormalize:
    def test_fd_roundtrip_passes_validation(self):
        from octorules_azure._adapters import FrontDoorAdapter
        from octorules_azure.validate import validate_rules

        adapter = FrontDoorAdapter()
        sdk_rule = {
            "name": "BlockIPs",
            "priority": 1,
            "enabled_state": "Enabled",
            "rule_type": "MatchRule",
            "match_conditions": [
                {
                    "match_variable": "RemoteAddr",
                    "selector": None,
                    "operator": "IPMatch",
                    "negate_condition": False,
                    "match_value": ["203.0.113.0/24"],
                    "transforms": [],
                }
            ],
            "action": "Block",
        }
        normalised = adapter.normalize_rule(sdk_rule)
        errors = [r for r in validate_rules([normalised]) if r.severity.value <= 2]
        assert errors == [], f"Validation errors: {errors}"
        denormalised = adapter.denormalize_rule(normalised)
        assert denormalised["name"] == "BlockIPs"

    def test_ag_roundtrip_passes_validation(self):
        from octorules_azure._adapters import AppGatewayAdapter
        from octorules_azure.validate import validate_rules

        adapter = AppGatewayAdapter()
        sdk_rule = {
            "name": "GeoBlock",
            "priority": 2,
            "state": "Enabled",
            "rule_type": "MatchRule",
            "match_conditions": [
                {
                    "match_variables": [{"variable_name": "RemoteAddr", "selector": None}],
                    "operator": "GeoMatch",
                    "negation_conditon": True,
                    "match_values": ["US", "CA"],
                    "transforms": [],
                }
            ],
            "action": "Block",
        }
        normalised = adapter.normalize_rule(sdk_rule)
        errors = [r for r in validate_rules([normalised]) if r.severity.value <= 2]
        assert errors == [], f"Validation errors: {errors}"
        denormalised = adapter.denormalize_rule(normalised)
        assert denormalised["name"] == "GeoBlock"
        assert denormalised["state"] == "Enabled"
        cond = denormalised["match_conditions"][0]
        assert cond["negation_conditon"] is True  # typo preserved


# ---------------------------------------------------------------------------
# Concurrent workers (Issue 3)
# ---------------------------------------------------------------------------
class TestConcurrentWorkers:
    def test_concurrent_get_phase_rules(self):
        from concurrent.futures import ThreadPoolExecutor

        from octorules.provider.base import Scope

        client = MagicMock()
        p = _make_provider(client=client, max_workers=4)
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
                                "match_value": ["203.0.113.0/24"],
                                "transforms": [],
                            }
                        ],
                        "action": "Block",
                    }
                ]
            },
        }
        client.policies.get.return_value = policy

        scope = Scope(zone_id="p")
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(p.get_phase_rules, scope, "azure_waf_custom") for _ in range(8)
            ]
            results = [f.result() for f in futures]

        assert all(len(r) == 1 for r in results)
        assert all(r[0]["ref"] == "C1" for r in results)

    def test_concurrent_resolve_zone_id(self):
        from concurrent.futures import ThreadPoolExecutor

        client = MagicMock()
        p = _make_provider(client=client, max_workers=4)
        client.policies.get.return_value = MagicMock()

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(p.resolve_zone_id, f"p{i}") for i in range(8)]
            results = [f.result() for f in futures]

        assert results == [f"p{i}" for i in range(8)]


# ---------------------------------------------------------------------------
# Connection errors (Issue 4)
# ---------------------------------------------------------------------------
@patch("octorules.retry.time.sleep")
class TestConnectionErrors:
    def test_service_request_error(self, _sleep):
        client = MagicMock()
        p = _make_provider(client=client)
        client.policies.get.side_effect = ServiceRequestError("DNS failure")
        with pytest.raises(ProviderConnectionError, match="DNS failure"):
            p.resolve_zone_id("test")

    def test_connection_error(self, _sleep):
        client = MagicMock()
        p = _make_provider(client=client)
        client.policies.get.side_effect = ConnectionError("refused")
        with pytest.raises(ProviderConnectionError, match="refused"):
            p.resolve_zone_id("test")

    def test_connection_error_on_list_zones(self, _sleep):
        client = MagicMock()
        p = _make_provider(client=client)
        client.policies.list.side_effect = ServiceRequestError("timeout")
        with pytest.raises(ProviderConnectionError):
            p.list_zones()


# ---------------------------------------------------------------------------
# Malformed responses (Issue 5)
# ---------------------------------------------------------------------------
class TestMalformedResponses:
    def test_policy_with_none_custom_rules(self):
        from octorules.provider.base import Scope

        client = MagicMock()
        p = _make_provider(client=client)
        client.policies.get.return_value = {"custom_rules": None}
        result = p.get_phase_rules(Scope(zone_id="p"), "azure_waf_custom")
        assert result == []

    def test_policy_missing_custom_rules_key(self):
        from octorules.provider.base import Scope

        client = MagicMock()
        p = _make_provider(client=client)
        client.policies.get.return_value = {"managed_rules": {}}
        result = p.get_phase_rules(Scope(zone_id="p"), "azure_waf_custom")
        assert result == []

    def test_rule_missing_name(self):
        from octorules.provider.base import Scope

        client = MagicMock()
        p = _make_provider(client=client)
        # Rule with no name field at all
        client.policies.get.return_value = {
            "custom_rules": {
                "rules": [
                    {
                        "priority": 1,
                        "rule_type": "MatchRule",
                        "enabled_state": "Enabled",
                        "match_conditions": [],
                        "action": "Block",
                    }
                ]
            }
        }
        rules = p.get_phase_rules(Scope(zone_id="p"), "azure_waf_custom")
        assert len(rules) == 1
        assert rules[0]["ref"] == ""  # name defaults to empty string

    def test_empty_custom_rules_dict(self):
        from octorules.provider.base import Scope

        client = MagicMock()
        p = _make_provider(client=client)
        client.policies.get.return_value = {"custom_rules": {}}
        result = p.get_phase_rules(Scope(zone_id="p"), "azure_waf_custom")
        assert result == []


# ---------------------------------------------------------------------------
# Auth error code coverage (Issue 6)
# ---------------------------------------------------------------------------
@patch("octorules.retry.time.sleep")
class TestAuthErrorCodes:
    @pytest.mark.parametrize(
        "code",
        [
            "AuthenticationFailed",
            "AuthorizationFailed",
            "InvalidAuthenticationTokenTenant",
            "LinkedAuthorizationFailed",
        ],
    )
    def test_all_auth_error_codes(self, _sleep, code):
        client = MagicMock()
        p = _make_provider(client=client)
        err = HttpResponseError(f"error: {code}")
        err.error = MagicMock()
        err.error.code = code
        client.policies.get.side_effect = err
        with pytest.raises(ProviderAuthError):
            p.resolve_zone_id("test")

    def test_non_auth_code_is_generic_error(self, _sleep):
        client = MagicMock()
        p = _make_provider(client=client)
        err = HttpResponseError("quota exceeded")
        err.error = MagicMock()
        err.error.code = "QuotaExceeded"
        err.status_code = 400
        client.policies.get.side_effect = err
        with pytest.raises(ProviderError):
            p.resolve_zone_id("test")


# ---------------------------------------------------------------------------
# list_zones comprehensive (Issue 7)
# ---------------------------------------------------------------------------
class TestListZonesComprehensive:
    def test_list_zones_success(self):
        client = MagicMock()
        p = _make_provider(client=client)
        client.policies.list.return_value = [
            {"name": "policy-a"},
            {"name": "policy-b"},
            {"name": "policy-c"},
        ]
        result = p.list_zones()
        assert result == ["policy-a", "policy-b", "policy-c"]

    def test_list_zones_empty(self):
        client = MagicMock()
        p = _make_provider(client=client)
        client.policies.list.return_value = []
        assert p.list_zones() == []

    @patch("octorules.retry.time.sleep")
    def test_list_zones_auth_error(self, _sleep):
        client = MagicMock()
        p = _make_provider(client=client)
        client.policies.list.side_effect = ClientAuthenticationError("forbidden")
        with pytest.raises(ProviderAuthError):
            p.list_zones()

    @patch("octorules.retry.time.sleep")
    def test_list_zones_connection_error(self, _sleep):
        client = MagicMock()
        p = _make_provider(client=client)
        client.policies.list.side_effect = ServiceRequestError("no connection")
        with pytest.raises(ProviderConnectionError):
            p.list_zones()
