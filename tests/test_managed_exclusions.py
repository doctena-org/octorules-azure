"""Tests for Azure WAF global managed-rule exclusions extension."""

from unittest.mock import MagicMock

from octorules.provider.base import Scope

from octorules_azure._managed_exclusions import (
    ManagedExclusionsFormatter,
    ManagedExclusionsPlan,
    _apply_managed_exclusions,
    _dump_managed_exclusions,
    _finalize_managed_exclusions,
    _prefetch_managed_exclusions,
    _validate_managed_exclusions,
    denormalize_managed_exclusions,
    diff_managed_exclusions,
    normalize_managed_exclusions,
)


def _scope(zone_id: str = "test-policy") -> Scope:
    return Scope(zone_id=zone_id, label="test-policy")


_SAMPLE_EXCLUSIONS = [
    {
        "match_variable": "RequestArgNames",
        "selector_match_operator": "Equals",
        "selector": "q",
    },
    {
        "match_variable": "RequestHeaderNames",
        "selector_match_operator": "StartsWith",
        "selector": "x-",
    },
]


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
class TestNormalize:
    def test_extracts_exclusions(self):
        policy = {"managed_rules": {"exclusions": _SAMPLE_EXCLUSIONS}}
        result = normalize_managed_exclusions(policy)
        assert len(result) == 2
        assert result[0]["selector"] == "q"

    def test_missing_managed_rules(self):
        assert normalize_managed_exclusions({}) == []

    def test_missing_exclusions(self):
        assert normalize_managed_exclusions({"managed_rules": {}}) == []

    def test_none_exclusions(self):
        assert normalize_managed_exclusions({"managed_rules": {"exclusions": None}}) == []

    def test_none_managed_rules(self):
        assert normalize_managed_exclusions({"managed_rules": None}) == []


class TestNormalizeDenormalizeRoundTrip:
    def test_round_trip_preserves_exclusions(self):
        """normalize -> denormalize preserves exclusion data."""
        exclusions = [
            {
                "match_variable": "RequestArgNames",
                "selector_match_operator": "Equals",
                "selector": "q",
            },
            {
                "match_variable": "RequestHeaderNames",
                "selector_match_operator": "StartsWith",
                "selector": "x-custom-",
            },
            {
                "match_variable": "RequestCookieNames",
                "selector_match_operator": "Contains",
                "selector": "session",
            },
        ]
        policy = {
            "managed_rules": {
                "managed_rule_sets": [{"rule_set_type": "DRS", "rule_set_version": "2.1"}],
                "exclusions": exclusions,
            }
        }
        normalized = normalize_managed_exclusions(policy)
        # Build a fresh policy and denormalize into it
        target_policy = {
            "managed_rules": {
                "managed_rule_sets": [{"rule_set_type": "DRS", "rule_set_version": "2.1"}],
            }
        }
        result = denormalize_managed_exclusions(target_policy, normalized)
        assert result["managed_rules"]["exclusions"] == exclusions
        # Existing keys are preserved
        assert result["managed_rules"]["managed_rule_sets"] == [
            {"rule_set_type": "DRS", "rule_set_version": "2.1"}
        ]


# ---------------------------------------------------------------------------
# Denormalization
# ---------------------------------------------------------------------------
class TestDenormalize:
    def test_writes_exclusions(self):
        policy = {"managed_rules": {"managed_rule_sets": [{"type": "DRS"}]}}
        result = denormalize_managed_exclusions(policy, _SAMPLE_EXCLUSIONS)
        assert result["managed_rules"]["exclusions"] == _SAMPLE_EXCLUSIONS
        # Should preserve existing keys
        assert result["managed_rules"]["managed_rule_sets"] == [{"type": "DRS"}]

    def test_creates_managed_rules_key(self):
        policy = {}
        result = denormalize_managed_exclusions(policy, _SAMPLE_EXCLUSIONS)
        assert result["managed_rules"]["exclusions"] == _SAMPLE_EXCLUSIONS

    def test_empty_exclusions(self):
        policy = {"managed_rules": {"exclusions": _SAMPLE_EXCLUSIONS}}
        result = denormalize_managed_exclusions(policy, [])
        assert result["managed_rules"]["exclusions"] == []


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------
class TestDiff:
    def test_no_changes(self):
        plan = diff_managed_exclusions(_SAMPLE_EXCLUSIONS, _SAMPLE_EXCLUSIONS)
        assert not plan.has_changes
        assert plan.total_changes == 0

    def test_with_changes(self):
        plan = diff_managed_exclusions([], _SAMPLE_EXCLUSIONS)
        assert plan.has_changes
        assert plan.total_changes == 1

    def test_different_exclusions(self):
        current = [_SAMPLE_EXCLUSIONS[0]]
        desired = [_SAMPLE_EXCLUSIONS[1]]
        plan = diff_managed_exclusions(current, desired)
        assert plan.has_changes


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
class TestDataModel:
    def test_plan_has_changes(self):
        plan = ManagedExclusionsPlan(current=[], desired=_SAMPLE_EXCLUSIONS)
        assert plan.has_changes
        assert plan.total_changes == 1

    def test_plan_no_changes(self):
        plan = ManagedExclusionsPlan(current=_SAMPLE_EXCLUSIONS, desired=_SAMPLE_EXCLUSIONS)
        assert not plan.has_changes
        assert plan.total_changes == 0

    def test_plan_empty(self):
        plan = ManagedExclusionsPlan()
        assert not plan.has_changes
        assert plan.total_changes == 0


# ---------------------------------------------------------------------------
# Prefetch hook
# ---------------------------------------------------------------------------
class TestPrefetchHook:
    def test_returns_none_when_no_config(self):
        result = _prefetch_managed_exclusions({}, _scope(), MagicMock())
        assert result is None

    def test_fetches_exclusions(self):
        provider = MagicMock()
        provider.get_managed_exclusions.return_value = _SAMPLE_EXCLUSIONS
        all_desired = {"azure_waf_managed_exclusions": [_SAMPLE_EXCLUSIONS[0]]}
        result = _prefetch_managed_exclusions(all_desired, _scope(), provider)
        assert result is not None
        current, desired = result
        assert len(current) == 2
        assert len(desired) == 1

    def test_api_failure_handled_gracefully(self):
        from octorules.provider.exceptions import ProviderError

        provider = MagicMock()
        provider.get_managed_exclusions.side_effect = ProviderError("API down")
        all_desired = {"azure_waf_managed_exclusions": _SAMPLE_EXCLUSIONS}
        result = _prefetch_managed_exclusions(all_desired, _scope(), provider)
        current, _desired = result
        assert current == []

    def test_auth_error_propagates(self):
        import pytest
        from octorules.provider.exceptions import ProviderAuthError

        provider = MagicMock()
        provider.get_managed_exclusions.side_effect = ProviderAuthError("forbidden")
        all_desired = {"azure_waf_managed_exclusions": _SAMPLE_EXCLUSIONS}
        with pytest.raises(ProviderAuthError):
            _prefetch_managed_exclusions(all_desired, _scope(), provider)


# ---------------------------------------------------------------------------
# Finalize hook
# ---------------------------------------------------------------------------
class TestFinalizeHook:
    def test_adds_plan_when_changes(self):
        zp = MagicMock()
        zp.extension_plans = {}

        ctx = ([], _SAMPLE_EXCLUSIONS)
        _finalize_managed_exclusions(zp, {}, _scope(), MagicMock(), ctx)
        assert "azure_waf_managed_exclusions" in zp.extension_plans
        plan = zp.extension_plans["azure_waf_managed_exclusions"][0]
        assert plan.has_changes

    def test_no_plan_when_no_changes(self):
        zp = MagicMock()
        zp.extension_plans = {}

        ctx = (_SAMPLE_EXCLUSIONS, _SAMPLE_EXCLUSIONS)
        _finalize_managed_exclusions(zp, {}, _scope(), MagicMock(), ctx)
        assert "azure_waf_managed_exclusions" not in zp.extension_plans

    def test_none_ctx_is_noop(self):
        zp = MagicMock()
        zp.extension_plans = {}
        _finalize_managed_exclusions(zp, {}, _scope(), MagicMock(), None)
        assert zp.extension_plans == {}


# ---------------------------------------------------------------------------
# Apply hook
# ---------------------------------------------------------------------------
class TestApplyHook:
    def test_apply_changes(self):
        provider = MagicMock()
        zp = MagicMock()
        plan = ManagedExclusionsPlan(current=[], desired=_SAMPLE_EXCLUSIONS)
        synced, error = _apply_managed_exclusions(zp, [plan], _scope(), provider)
        assert error is None
        assert "azure_waf_managed_exclusions" in synced
        provider.update_managed_exclusions.assert_called_once()
        call_args = provider.update_managed_exclusions.call_args
        assert call_args[0][1] == _SAMPLE_EXCLUSIONS

    def test_no_changes_skipped(self):
        provider = MagicMock()
        zp = MagicMock()
        plan = ManagedExclusionsPlan(current=_SAMPLE_EXCLUSIONS, desired=_SAMPLE_EXCLUSIONS)
        synced, error = _apply_managed_exclusions(zp, [plan], _scope(), provider)
        assert synced == []
        assert error is None
        provider.update_managed_exclusions.assert_not_called()

    def test_empty_plans(self):
        synced, error = _apply_managed_exclusions(MagicMock(), [], _scope(), MagicMock())
        assert synced == []
        assert error is None


# ---------------------------------------------------------------------------
# Validate extension
# ---------------------------------------------------------------------------
class TestValidateExtension:
    def test_valid_exclusions(self):
        desired = {"azure_waf_managed_exclusions": _SAMPLE_EXCLUSIONS}
        errors: list[str] = []
        _validate_managed_exclusions(desired, "zone", errors, [])
        assert errors == []

    def test_not_a_list(self):
        desired = {"azure_waf_managed_exclusions": "bad"}
        errors: list[str] = []
        _validate_managed_exclusions(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "must be a list" in errors[0]

    def test_non_dict_entry(self):
        desired = {"azure_waf_managed_exclusions": ["bad"]}
        errors: list[str] = []
        _validate_managed_exclusions(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "must be a dict" in errors[0]

    def test_no_config_is_ok(self):
        errors: list[str] = []
        _validate_managed_exclusions({}, "zone", errors, [])
        assert errors == []

    def test_empty_list_is_ok(self):
        desired = {"azure_waf_managed_exclusions": []}
        errors: list[str] = []
        _validate_managed_exclusions(desired, "zone", errors, [])
        assert errors == []

    def test_front_door_rejects_managed_exclusions(self):
        """Managed exclusions are AG-only; FD config should be rejected."""
        from octorules_azure.validate import set_waf_type

        set_waf_type("front_door")
        try:
            desired = {"azure_waf_managed_exclusions": _SAMPLE_EXCLUSIONS}
            errors: list[str] = []
            _validate_managed_exclusions(desired, "zone", errors, [])
            assert len(errors) == 1
            assert "not supported on Front Door" in errors[0]
        finally:
            set_waf_type("")

    def test_app_gateway_allows_managed_exclusions(self):
        """AG should pass validation for managed exclusions."""
        from octorules_azure.validate import set_waf_type

        set_waf_type("app_gateway")
        try:
            desired = {"azure_waf_managed_exclusions": _SAMPLE_EXCLUSIONS}
            errors: list[str] = []
            _validate_managed_exclusions(desired, "zone", errors, [])
            assert errors == []
        finally:
            set_waf_type("")


# ---------------------------------------------------------------------------
# Dump extension
# ---------------------------------------------------------------------------
class TestDumpExtension:
    def test_dump_returns_exclusions(self):
        provider = MagicMock()
        provider.get_managed_exclusions.return_value = _SAMPLE_EXCLUSIONS
        result = _dump_managed_exclusions(_scope(), provider, None)
        assert "azure_waf_managed_exclusions" in result
        assert len(result["azure_waf_managed_exclusions"]) == 2

    def test_dump_api_failure(self):
        from octorules.provider.exceptions import ProviderError

        provider = MagicMock()
        provider.get_managed_exclusions.side_effect = ProviderError("down")
        result = _dump_managed_exclusions(_scope(), provider, None)
        assert result is None

    def test_dump_empty_exclusions(self):
        provider = MagicMock()
        provider.get_managed_exclusions.return_value = []
        result = _dump_managed_exclusions(_scope(), provider, None)
        assert result is None

    def test_dump_auth_error_propagates(self):
        import pytest
        from octorules.provider.exceptions import ProviderAuthError

        provider = MagicMock()
        provider.get_managed_exclusions.side_effect = ProviderAuthError("forbidden")
        with pytest.raises(ProviderAuthError):
            _dump_managed_exclusions(_scope(), provider, None)


# ---------------------------------------------------------------------------
# Format extension -- format_text
# ---------------------------------------------------------------------------
class TestFormatText:
    def test_with_changes(self):
        fmt = ManagedExclusionsFormatter()
        plan = ManagedExclusionsPlan(current=[], desired=_SAMPLE_EXCLUSIONS)
        lines = fmt.format_text([plan], use_color=False)
        assert len(lines) == 1
        assert "managed_exclusions" in lines[0]
        assert "0 -> 2" in lines[0]
        assert lines[0].strip().startswith("~")

    def test_skips_no_change(self):
        fmt = ManagedExclusionsFormatter()
        plan = ManagedExclusionsPlan(current=_SAMPLE_EXCLUSIONS, desired=_SAMPLE_EXCLUSIONS)
        assert fmt.format_text([plan], use_color=False) == []

    def test_empty_plans(self):
        fmt = ManagedExclusionsFormatter()
        assert fmt.format_text([], use_color=False) == []


# ---------------------------------------------------------------------------
# Format extension -- format_json
# ---------------------------------------------------------------------------
class TestFormatJson:
    def test_with_changes(self):
        fmt = ManagedExclusionsFormatter()
        plan = ManagedExclusionsPlan(current=[], desired=_SAMPLE_EXCLUSIONS)
        result = fmt.format_json([plan])
        assert len(result) == 1
        assert result[0]["current"] == []
        assert result[0]["desired"] == _SAMPLE_EXCLUSIONS

    def test_skips_no_change(self):
        fmt = ManagedExclusionsFormatter()
        plan = ManagedExclusionsPlan(current=_SAMPLE_EXCLUSIONS, desired=_SAMPLE_EXCLUSIONS)
        assert fmt.format_json([plan]) == []

    def test_empty_plans(self):
        fmt = ManagedExclusionsFormatter()
        assert fmt.format_json([]) == []


# ---------------------------------------------------------------------------
# Format extension -- format_markdown
# ---------------------------------------------------------------------------
class TestFormatMarkdown:
    def test_with_changes(self):
        fmt = ManagedExclusionsFormatter()
        plan = ManagedExclusionsPlan(current=[], desired=_SAMPLE_EXCLUSIONS)
        lines = fmt.format_markdown([plan], pending_diffs=[])
        assert len(lines) == 1
        assert lines[0].startswith("| ~ |")
        assert "managed_exclusions" in lines[0]

    def test_skips_no_change(self):
        fmt = ManagedExclusionsFormatter()
        plan = ManagedExclusionsPlan(current=_SAMPLE_EXCLUSIONS, desired=_SAMPLE_EXCLUSIONS)
        assert fmt.format_markdown([plan], pending_diffs=[]) == []


# ---------------------------------------------------------------------------
# Format extension -- format_html
# ---------------------------------------------------------------------------
class TestFormatHtml:
    def test_with_changes(self):
        fmt = ManagedExclusionsFormatter()
        plan = ManagedExclusionsPlan(current=[], desired=_SAMPLE_EXCLUSIONS)
        lines: list[str] = []
        result = fmt.format_html([plan], lines)
        assert result == (0, 0, 1, 0)
        html = "\n".join(lines)
        assert "<table>" in html
        assert "Modify" in html
        assert "managed_exclusions" in html

    def test_skips_no_change(self):
        fmt = ManagedExclusionsFormatter()
        plan = ManagedExclusionsPlan(current=_SAMPLE_EXCLUSIONS, desired=_SAMPLE_EXCLUSIONS)
        lines: list[str] = []
        result = fmt.format_html([plan], lines)
        assert result == (0, 0, 0, 0)
        assert lines == []


# ---------------------------------------------------------------------------
# Format extension -- format_report
# ---------------------------------------------------------------------------
class TestFormatReport:
    def test_with_drift(self):
        fmt = ManagedExclusionsFormatter()
        plan = ManagedExclusionsPlan(current=[], desired=_SAMPLE_EXCLUSIONS)
        phases_data: list[dict] = []
        result = fmt.format_report([plan], zone_has_drift=False, phases_data=phases_data)
        assert result is True
        assert len(phases_data) == 1
        entry = phases_data[0]
        assert entry["phase"] == "managed_exclusions"
        assert entry["provider_id"] == "azure_waf_managed_exclusions"
        assert entry["status"] == "drifted"
        assert entry["modifies"] == 1

    def test_no_drift(self):
        fmt = ManagedExclusionsFormatter()
        phases_data: list[dict] = []
        result = fmt.format_report([], zone_has_drift=False, phases_data=phases_data)
        assert result is False
        assert phases_data == []


# ---------------------------------------------------------------------------
# Provider methods
# ---------------------------------------------------------------------------
class TestProviderGetManagedExclusions:
    def test_get_managed_exclusions_fd(self):
        from octorules_azure.provider import AzureWafProvider

        policy_dict = {
            "name": "test-policy",
            "managed_rules": {
                "managed_rule_sets": [],
                "exclusions": _SAMPLE_EXCLUSIONS,
            },
        }
        client = MagicMock()
        client.policies.get.return_value = policy_dict
        provider = AzureWafProvider(
            subscription_id="sub-123",
            resource_group="rg-test",
            waf_type="front_door",
            client=client,
        )
        result = provider.get_managed_exclusions(_scope())
        assert len(result) == 2
        assert result[0]["selector"] == "q"

    def test_get_managed_exclusions_ag(self):
        from octorules_azure.provider import AzureWafProvider

        policy_dict = {
            "name": "test-policy",
            "managed_rules": {
                "managed_rule_sets": [],
                "exclusions": _SAMPLE_EXCLUSIONS,
            },
        }
        client = MagicMock()
        client.web_application_firewall_policies.get.return_value = policy_dict
        provider = AzureWafProvider(
            subscription_id="sub-123",
            resource_group="rg-test",
            waf_type="app_gateway",
            client=client,
        )
        result = provider.get_managed_exclusions(_scope())
        assert len(result) == 2

    def test_empty_exclusions(self):
        from octorules_azure.provider import AzureWafProvider

        policy_dict = {
            "name": "test-policy",
            "managed_rules": {"managed_rule_sets": []},
        }
        client = MagicMock()
        client.policies.get.return_value = policy_dict
        provider = AzureWafProvider(
            subscription_id="sub-123",
            resource_group="rg-test",
            waf_type="front_door",
            client=client,
        )
        result = provider.get_managed_exclusions(_scope())
        assert result == []


class TestProviderUpdateManagedExclusions:
    def test_update_managed_exclusions_fd(self):
        from octorules_azure.provider import AzureWafProvider

        policy_data = {
            "name": "test-policy",
            "etag": '"etag-1"',
            "managed_rules": {
                "managed_rule_sets": [{"rule_set_type": "DRS"}],
                "exclusions": [],
            },
        }
        client = MagicMock()
        client.policies.get.return_value = policy_data
        client.policies.begin_create_or_update.return_value.result.return_value = policy_data
        provider = AzureWafProvider(
            subscription_id="sub-123",
            resource_group="rg-test",
            waf_type="front_door",
            client=client,
        )
        provider.update_managed_exclusions(_scope(), _SAMPLE_EXCLUSIONS)
        client.policies.begin_create_or_update.assert_called_once()
        call_args = client.policies.begin_create_or_update.call_args
        updated_policy = call_args[0][2]
        assert updated_policy["managed_rules"]["exclusions"] == _SAMPLE_EXCLUSIONS
        # Managed rule sets should be preserved
        assert updated_policy["managed_rules"]["managed_rule_sets"] == [{"rule_set_type": "DRS"}]

    def test_update_managed_exclusions_ag(self):
        from octorules_azure.provider import AzureWafProvider

        policy_data = {
            "name": "test-policy",
            "etag": '"etag-1"',
            "managed_rules": {
                "managed_rule_sets": [{"rule_set_type": "OWASP"}],
                "exclusions": [],
            },
        }
        client = MagicMock()
        client.web_application_firewall_policies.get.return_value = policy_data
        client.web_application_firewall_policies.create_or_update.return_value = policy_data
        provider = AzureWafProvider(
            subscription_id="sub-123",
            resource_group="rg-test",
            waf_type="app_gateway",
            client=client,
        )
        provider.update_managed_exclusions(_scope(), _SAMPLE_EXCLUSIONS)
        client.web_application_firewall_policies.create_or_update.assert_called_once()
        call_args = client.web_application_firewall_policies.create_or_update.call_args
        updated_policy = call_args[0][2]
        assert updated_policy["managed_rules"]["exclusions"] == _SAMPLE_EXCLUSIONS
