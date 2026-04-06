"""Tests for Azure WAF policy settings normalization and extension hooks."""

from unittest.mock import MagicMock

from octorules.provider.base import Scope

from octorules_azure._policy_settings import (
    PolicySettingsChange,
    PolicySettingsFormatter,
    PolicySettingsPlan,
    _apply_policy_settings,
    _dump_policy_settings,
    _finalize_policy_settings,
    _prefetch_policy_settings,
    _validate_policy_settings,
    denormalize_policy_settings,
    diff_policy_settings,
    normalize_policy_settings,
)


def _scope(zone_id: str = "test-policy") -> Scope:
    return Scope(zone_id=zone_id, label="test-policy")


# ---------------------------------------------------------------------------
# Normalization — Front Door
# ---------------------------------------------------------------------------
class TestNormalizeFrontDoor:
    def test_basic_fields(self):
        raw = {
            "enabled_state": "Enabled",
            "mode": "Prevention",
            "request_body_check": "Enabled",
        }
        result = normalize_policy_settings(raw, "front_door")
        assert result["enabled_state"] == "Enabled"
        assert result["mode"] == "Prevention"
        assert result["request_body_check"] is True

    def test_request_body_check_disabled(self):
        raw = {"request_body_check": "Disabled"}
        result = normalize_policy_settings(raw, "front_door")
        assert result["request_body_check"] is False

    def test_fd_specific_fields(self):
        raw = {
            "redirect_url": "https://example.com",
            "custom_block_response_status_code": 403,
            "custom_block_response_body": "blocked",
            "javascript_challenge_expiration_in_minutes": 30,
        }
        result = normalize_policy_settings(raw, "front_door")
        assert result["redirect_url"] == "https://example.com"
        assert result["custom_block_response_status_code"] == 403
        assert result["custom_block_response_body"] == "blocked"
        assert result["javascript_challenge_expiration_in_minutes"] == 30

    def test_fd_ignores_ag_fields(self):
        raw = {"max_request_body_size_in_kb": 128}
        result = normalize_policy_settings(raw, "front_door")
        assert "max_request_body_size_in_kb" not in result

    def test_log_scrubbing(self):
        raw = {"log_scrubbing": {"rules": [{"field": "RequestUri"}]}}
        result = normalize_policy_settings(raw, "front_door")
        assert result["log_scrubbing"] == {"rules": [{"field": "RequestUri"}]}

    def test_empty(self):
        assert normalize_policy_settings({}, "front_door") == {}

    def test_none_values_skipped(self):
        raw = {"enabled_state": None, "mode": "Prevention"}
        result = normalize_policy_settings(raw, "front_door")
        assert "enabled_state" not in result
        assert result["mode"] == "Prevention"


# ---------------------------------------------------------------------------
# Normalization — App Gateway
# ---------------------------------------------------------------------------
class TestNormalizeAppGateway:
    def test_basic_fields(self):
        raw = {
            "state": "Enabled",
            "mode": "Detection",
            "request_body_check": True,
        }
        result = normalize_policy_settings(raw, "app_gateway")
        assert result["enabled_state"] == "Enabled"
        assert result["mode"] == "Detection"
        assert result["request_body_check"] is True

    def test_request_body_check_false(self):
        raw = {"request_body_check": False}
        result = normalize_policy_settings(raw, "app_gateway")
        assert result["request_body_check"] is False

    def test_ag_specific_fields(self):
        raw = {
            "max_request_body_size_in_kb": 128,
            "file_upload_limit_in_mb": 100,
            "request_body_inspect_limit_in_kb": 128,
        }
        result = normalize_policy_settings(raw, "app_gateway")
        assert result["max_request_body_size_in_kb"] == 128
        assert result["file_upload_limit_in_mb"] == 100
        assert result["request_body_inspect_limit_in_kb"] == 128

    def test_ag_custom_block_response_fields(self):
        raw = {
            "custom_block_response_status_code": 403,
            "custom_block_response_body": "blocked",
        }
        result = normalize_policy_settings(raw, "app_gateway")
        assert result["custom_block_response_status_code"] == 403
        assert result["custom_block_response_body"] == "blocked"

    def test_ag_request_body_enforcement(self):
        raw = {"request_body_enforcement": True}
        result = normalize_policy_settings(raw, "app_gateway")
        assert result["request_body_enforcement"] is True

    def test_ag_request_body_enforcement_false(self):
        raw = {"request_body_enforcement": False}
        result = normalize_policy_settings(raw, "app_gateway")
        assert result["request_body_enforcement"] is False

    def test_ag_file_upload_enforcement(self):
        raw = {"file_upload_enforcement": True}
        result = normalize_policy_settings(raw, "app_gateway")
        assert result["file_upload_enforcement"] is True

    def test_ag_file_upload_enforcement_false(self):
        raw = {"file_upload_enforcement": False}
        result = normalize_policy_settings(raw, "app_gateway")
        assert result["file_upload_enforcement"] is False

    def test_ag_js_challenge_cookie_expiration(self):
        raw = {"js_challenge_cookie_expiration_in_mins": 30}
        result = normalize_policy_settings(raw, "app_gateway")
        assert result["js_challenge_cookie_expiration_in_mins"] == 30

    def test_ag_ignores_fd_fields(self):
        raw = {"redirect_url": "https://example.com"}
        result = normalize_policy_settings(raw, "app_gateway")
        assert "redirect_url" not in result

    def test_state_maps_to_enabled_state(self):
        """AG 'state' field normalizes to canonical 'enabled_state'."""
        raw = {"state": "Disabled"}
        result = normalize_policy_settings(raw, "app_gateway")
        assert result["enabled_state"] == "Disabled"


# ---------------------------------------------------------------------------
# Normalization round-trip
# ---------------------------------------------------------------------------
class TestRoundTrip:
    def test_front_door_round_trip(self):
        raw = {
            "enabled_state": "Enabled",
            "mode": "Prevention",
            "request_body_check": "Enabled",
            "redirect_url": "https://example.com",
            "custom_block_response_status_code": 403,
        }
        normalized = normalize_policy_settings(raw, "front_door")
        denormalized = denormalize_policy_settings(normalized, "front_door")
        assert denormalized["enabled_state"] == "Enabled"
        assert denormalized["mode"] == "Prevention"
        assert denormalized["request_body_check"] == "Enabled"
        assert denormalized["redirect_url"] == "https://example.com"
        assert denormalized["custom_block_response_status_code"] == 403

    def test_app_gateway_round_trip(self):
        raw = {
            "state": "Enabled",
            "mode": "Detection",
            "request_body_check": True,
            "max_request_body_size_in_kb": 128,
            "file_upload_limit_in_mb": 100,
        }
        normalized = normalize_policy_settings(raw, "app_gateway")
        denormalized = denormalize_policy_settings(normalized, "app_gateway")
        assert denormalized["state"] == "Enabled"
        assert denormalized["mode"] == "Detection"
        assert denormalized["request_body_check"] is True
        assert denormalized["max_request_body_size_in_kb"] == 128
        assert denormalized["file_upload_limit_in_mb"] == 100

    def test_app_gateway_round_trip_all_fields(self):
        raw = {
            "state": "Enabled",
            "mode": "Prevention",
            "request_body_check": True,
            "max_request_body_size_in_kb": 128,
            "file_upload_limit_in_mb": 100,
            "request_body_inspect_limit_in_kb": 128,
            "custom_block_response_status_code": 403,
            "custom_block_response_body": "blocked",
            "request_body_enforcement": True,
            "file_upload_enforcement": True,
            "js_challenge_cookie_expiration_in_mins": 30,
        }
        normalized = normalize_policy_settings(raw, "app_gateway")
        denormalized = denormalize_policy_settings(normalized, "app_gateway")
        assert denormalized["state"] == "Enabled"
        assert denormalized["mode"] == "Prevention"
        assert denormalized["request_body_check"] is True
        assert denormalized["max_request_body_size_in_kb"] == 128
        assert denormalized["file_upload_limit_in_mb"] == 100
        assert denormalized["request_body_inspect_limit_in_kb"] == 128
        assert denormalized["custom_block_response_status_code"] == 403
        assert denormalized["custom_block_response_body"] == "blocked"
        assert denormalized["request_body_enforcement"] is True
        assert denormalized["file_upload_enforcement"] is True
        assert denormalized["js_challenge_cookie_expiration_in_mins"] == 30


# ---------------------------------------------------------------------------
# Denormalization
# ---------------------------------------------------------------------------
class TestDenormalize:
    def test_partial_update_fd(self):
        """Only specified fields are included in the output."""
        settings = {"mode": "Detection"}
        result = denormalize_policy_settings(settings, "front_door")
        assert result == {"mode": "Detection"}
        assert "enabled_state" not in result
        assert "request_body_check" not in result

    def test_partial_update_ag(self):
        settings = {"enabled_state": "Disabled"}
        result = denormalize_policy_settings(settings, "app_gateway")
        assert result == {"state": "Disabled"}

    def test_request_body_check_fd(self):
        settings = {"request_body_check": False}
        result = denormalize_policy_settings(settings, "front_door")
        assert result["request_body_check"] == "Disabled"

    def test_request_body_check_ag(self):
        settings = {"request_body_check": True}
        result = denormalize_policy_settings(settings, "app_gateway")
        assert result["request_body_check"] is True

    def test_ag_custom_block_and_enforcement(self):
        settings = {
            "custom_block_response_status_code": 403,
            "custom_block_response_body": "blocked",
            "request_body_enforcement": True,
        }
        result = denormalize_policy_settings(settings, "app_gateway")
        assert result["custom_block_response_status_code"] == 403
        assert result["custom_block_response_body"] == "blocked"
        assert result["request_body_enforcement"] is True

    def test_ag_file_upload_enforcement(self):
        settings = {"file_upload_enforcement": True}
        result = denormalize_policy_settings(settings, "app_gateway")
        assert result["file_upload_enforcement"] is True

    def test_ag_js_challenge_cookie_expiration(self):
        settings = {"js_challenge_cookie_expiration_in_mins": 30}
        result = denormalize_policy_settings(settings, "app_gateway")
        assert result["js_challenge_cookie_expiration_in_mins"] == 30

    def test_ag_new_fields_not_on_fd(self):
        """AG-only fields should not appear in FD output."""
        for key in (
            "request_body_enforcement",
            "file_upload_enforcement",
            "js_challenge_cookie_expiration_in_mins",
        ):
            settings = {key: True}
            result = denormalize_policy_settings(settings, "front_door")
            assert key not in result, f"{key} should not appear in FD output"

    def test_empty(self):
        assert denormalize_policy_settings({}, "front_door") == {}
        assert denormalize_policy_settings({}, "app_gateway") == {}


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------
class TestDiffPolicySettings:
    def test_no_changes(self):
        settings = {"mode": "Prevention", "enabled_state": "Enabled"}
        plan = diff_policy_settings(settings, settings)
        assert not plan.has_changes
        assert plan.total_changes == 0

    def test_with_changes(self):
        current = {"mode": "Detection", "enabled_state": "Enabled"}
        desired = {"mode": "Prevention", "enabled_state": "Enabled"}
        plan = diff_policy_settings(current, desired)
        assert plan.has_changes
        assert plan.total_changes == 1
        assert plan.changes[0].field == "mode"
        assert plan.changes[0].current == "Detection"
        assert plan.changes[0].desired == "Prevention"

    def test_partial_desired(self):
        """Only keys present in desired produce changes."""
        current = {"mode": "Detection", "enabled_state": "Enabled", "request_body_check": True}
        desired = {"mode": "Prevention"}
        plan = diff_policy_settings(current, desired)
        assert plan.has_changes
        assert len(plan.changes) == 1
        assert plan.changes[0].field == "mode"

    def test_new_field(self):
        """Desired has a field not in current."""
        current = {"mode": "Prevention"}
        desired = {"mode": "Prevention", "enabled_state": "Disabled"}
        plan = diff_policy_settings(current, desired)
        assert plan.has_changes
        assert plan.changes[0].field == "enabled_state"
        assert plan.changes[0].current is None
        assert plan.changes[0].desired == "Disabled"

    def test_multiple_changes(self):
        current = {"enabled_state": "Enabled", "mode": "Detection"}
        desired = {"enabled_state": "Disabled", "mode": "Prevention"}
        plan = diff_policy_settings(current, desired)
        assert plan.total_changes == 2


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
class TestDataModel:
    def test_change_has_changes(self):
        c = PolicySettingsChange(field="mode", current="Detection", desired="Prevention")
        assert c.has_changes is True

    def test_change_no_changes(self):
        c = PolicySettingsChange(field="mode", current="Prevention", desired="Prevention")
        assert c.has_changes is False

    def test_plan_has_changes(self):
        plan = PolicySettingsPlan(changes=[PolicySettingsChange("mode", "Detection", "Prevention")])
        assert plan.has_changes is True
        assert plan.total_changes == 1

    def test_plan_empty(self):
        plan = PolicySettingsPlan()
        assert plan.has_changes is False
        assert plan.total_changes == 0


# ---------------------------------------------------------------------------
# Prefetch hook
# ---------------------------------------------------------------------------
class TestPrefetchHook:
    def test_returns_none_when_no_config(self):
        result = _prefetch_policy_settings({}, _scope(), MagicMock())
        assert result is None

    def test_fetches_settings(self):
        provider = MagicMock()
        provider.get_policy_settings.return_value = {
            "enabled_state": "Enabled",
            "mode": "Prevention",
        }
        all_desired = {"azure_waf_policy_settings": {"mode": "Detection"}}
        result = _prefetch_policy_settings(all_desired, _scope(), provider)
        assert result is not None
        current, desired = result
        assert current["enabled_state"] == "Enabled"
        assert desired["mode"] == "Detection"

    def test_api_failure_handled_gracefully(self):
        from octorules.provider.exceptions import ProviderError

        provider = MagicMock()
        provider.get_policy_settings.side_effect = ProviderError("API down")
        all_desired = {"azure_waf_policy_settings": {"mode": "Detection"}}
        result = _prefetch_policy_settings(all_desired, _scope(), provider)
        current, _desired = result
        assert current == {}

    def test_auth_error_propagates(self):
        import pytest
        from octorules.provider.exceptions import ProviderAuthError

        provider = MagicMock()
        provider.get_policy_settings.side_effect = ProviderAuthError("forbidden")
        all_desired = {"azure_waf_policy_settings": {"mode": "Detection"}}
        with pytest.raises(ProviderAuthError):
            _prefetch_policy_settings(all_desired, _scope(), provider)


# ---------------------------------------------------------------------------
# Finalize hook
# ---------------------------------------------------------------------------
class TestFinalizeHook:
    def test_adds_plan_when_changes(self):
        zp = MagicMock()
        zp.extension_plans = {}

        current = {"enabled_state": "Enabled", "mode": "Detection"}
        desired = {"mode": "Prevention"}
        ctx = (current, desired)

        _finalize_policy_settings(zp, {}, _scope(), MagicMock(), ctx)
        assert "azure_waf_policy_settings" in zp.extension_plans
        plan = zp.extension_plans["azure_waf_policy_settings"][0]
        assert plan.has_changes

    def test_no_plan_when_no_changes(self):
        zp = MagicMock()
        zp.extension_plans = {}

        current = {"mode": "Prevention"}
        desired = {"mode": "Prevention"}
        ctx = (current, desired)

        _finalize_policy_settings(zp, {}, _scope(), MagicMock(), ctx)
        assert "azure_waf_policy_settings" not in zp.extension_plans

    def test_none_ctx_is_noop(self):
        zp = MagicMock()
        zp.extension_plans = {}
        _finalize_policy_settings(zp, {}, _scope(), MagicMock(), None)
        assert zp.extension_plans == {}


# ---------------------------------------------------------------------------
# Apply hook
# ---------------------------------------------------------------------------
class TestApplyHook:
    def test_apply_changes(self):
        provider = MagicMock()
        zp = MagicMock()
        plan = PolicySettingsPlan(
            changes=[
                PolicySettingsChange("mode", "Detection", "Prevention"),
                PolicySettingsChange("enabled_state", "Enabled", "Disabled"),
            ]
        )
        synced, error = _apply_policy_settings(zp, [plan], _scope(), provider)
        assert error is None
        assert "azure_waf_policy_settings" in synced
        provider.update_policy_settings.assert_called_once()
        call_args = provider.update_policy_settings.call_args
        payload = call_args[0][1]
        assert payload["mode"] == "Prevention"
        assert payload["enabled_state"] == "Disabled"

    def test_no_changes_skipped(self):
        provider = MagicMock()
        zp = MagicMock()
        plan = PolicySettingsPlan(
            changes=[PolicySettingsChange("mode", "Prevention", "Prevention")]
        )
        synced, error = _apply_policy_settings(zp, [plan], _scope(), provider)
        assert synced == []
        assert error is None
        provider.update_policy_settings.assert_not_called()

    def test_empty_plans(self):
        synced, error = _apply_policy_settings(MagicMock(), [], _scope(), MagicMock())
        assert synced == []
        assert error is None


# ---------------------------------------------------------------------------
# Validate extension
# ---------------------------------------------------------------------------
class TestValidateExtension:
    def test_valid_settings(self):
        desired = {
            "azure_waf_policy_settings": {
                "mode": "Prevention",
                "enabled_state": "Enabled",
                "request_body_check": True,
            }
        }
        errors: list[str] = []
        _validate_policy_settings(desired, "zone", errors, [])
        assert errors == []

    def test_invalid_mode(self):
        desired = {"azure_waf_policy_settings": {"mode": "Aggressive"}}
        errors: list[str] = []
        _validate_policy_settings(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "mode" in errors[0]
        assert "Aggressive" in errors[0]

    def test_invalid_enabled_state(self):
        desired = {"azure_waf_policy_settings": {"enabled_state": "Maybe"}}
        errors: list[str] = []
        _validate_policy_settings(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "enabled_state" in errors[0]
        assert "Maybe" in errors[0]

    def test_invalid_request_body_check(self):
        desired = {"azure_waf_policy_settings": {"request_body_check": "yes"}}
        errors: list[str] = []
        _validate_policy_settings(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "request_body_check" in errors[0]

    def test_no_config_is_ok(self):
        errors: list[str] = []
        _validate_policy_settings({}, "zone", errors, [])
        assert errors == []

    def test_non_dict_config_is_ok(self):
        errors: list[str] = []
        _validate_policy_settings({"azure_waf_policy_settings": "not-a-dict"}, "zone", errors, [])
        assert errors == []

    def test_multiple_errors(self):
        desired = {
            "azure_waf_policy_settings": {
                "mode": "Aggressive",
                "enabled_state": "Maybe",
                "request_body_check": "yes",
            }
        }
        errors: list[str] = []
        _validate_policy_settings(desired, "zone", errors, [])
        assert len(errors) == 3


# ---------------------------------------------------------------------------
# Dump extension
# ---------------------------------------------------------------------------
class TestDumpExtension:
    def test_dump_returns_settings(self):
        provider = MagicMock()
        provider.get_policy_settings.return_value = {
            "enabled_state": "Enabled",
            "mode": "Prevention",
        }
        result = _dump_policy_settings(_scope(), provider, None)
        assert "azure_waf_policy_settings" in result
        assert result["azure_waf_policy_settings"]["mode"] == "Prevention"

    def test_dump_api_failure(self):
        from octorules.provider.exceptions import ProviderError

        provider = MagicMock()
        provider.get_policy_settings.side_effect = ProviderError("down")
        result = _dump_policy_settings(_scope(), provider, None)
        assert result is None

    def test_dump_empty_settings(self):
        provider = MagicMock()
        provider.get_policy_settings.return_value = {}
        result = _dump_policy_settings(_scope(), provider, None)
        assert result is None

    def test_dump_auth_error_propagates(self):
        import pytest
        from octorules.provider.exceptions import ProviderAuthError

        provider = MagicMock()
        provider.get_policy_settings.side_effect = ProviderAuthError("forbidden")
        with pytest.raises(ProviderAuthError):
            _dump_policy_settings(_scope(), provider, None)


# ---------------------------------------------------------------------------
# Format extension — format_text
# ---------------------------------------------------------------------------
class TestFormatText:
    def test_with_changes(self):
        fmt = PolicySettingsFormatter()
        plan = PolicySettingsPlan(
            changes=[
                PolicySettingsChange("mode", "Detection", "Prevention"),
                PolicySettingsChange("enabled_state", "Enabled", "Disabled"),
            ]
        )
        lines = fmt.format_text([plan], use_color=False)
        assert len(lines) == 2
        assert "policy_settings.mode" in lines[0]
        assert "'Detection'" in lines[0]
        assert "'Prevention'" in lines[0]
        assert lines[0].startswith("  ~ ")
        assert "policy_settings.enabled_state" in lines[1]
        assert "'Enabled'" in lines[1]
        assert "'Disabled'" in lines[1]

    def test_skips_no_change(self):
        fmt = PolicySettingsFormatter()
        plan = PolicySettingsPlan(
            changes=[PolicySettingsChange("mode", "Prevention", "Prevention")]
        )
        assert fmt.format_text([plan], use_color=False) == []

    def test_empty_plans(self):
        fmt = PolicySettingsFormatter()
        assert fmt.format_text([], use_color=False) == []

    def test_with_color(self):
        fmt = PolicySettingsFormatter()
        plan = PolicySettingsPlan(changes=[PolicySettingsChange("mode", "Detection", "Prevention")])
        lines = fmt.format_text([plan], use_color=True)
        assert len(lines) == 1
        assert "\033[" in lines[0]
        assert "policy_settings.mode" in lines[0]


# ---------------------------------------------------------------------------
# Format extension — format_json
# ---------------------------------------------------------------------------
class TestFormatJson:
    def test_with_changes(self):
        fmt = PolicySettingsFormatter()
        plan = PolicySettingsPlan(
            changes=[
                PolicySettingsChange("mode", "Detection", "Prevention"),
                PolicySettingsChange("enabled_state", "Enabled", "Disabled"),
            ]
        )
        result = fmt.format_json([plan])
        assert len(result) == 1
        changes = result[0]["changes"]
        assert len(changes) == 2
        assert changes[0]["field"] == "mode"
        assert changes[0]["current"] == "Detection"
        assert changes[0]["desired"] == "Prevention"
        assert changes[1]["field"] == "enabled_state"
        assert changes[1]["current"] == "Enabled"
        assert changes[1]["desired"] == "Disabled"

    def test_skips_no_change(self):
        fmt = PolicySettingsFormatter()
        plan = PolicySettingsPlan(
            changes=[PolicySettingsChange("mode", "Prevention", "Prevention")]
        )
        assert fmt.format_json([plan]) == []

    def test_empty_plans(self):
        fmt = PolicySettingsFormatter()
        assert fmt.format_json([]) == []


# ---------------------------------------------------------------------------
# Format extension — format_markdown
# ---------------------------------------------------------------------------
class TestFormatMarkdown:
    def test_with_changes(self):
        fmt = PolicySettingsFormatter()
        plan = PolicySettingsPlan(
            changes=[
                PolicySettingsChange("mode", "Detection", "Prevention"),
            ]
        )
        lines = fmt.format_markdown([plan], pending_diffs=[])
        assert len(lines) == 1
        assert lines[0].startswith("| ~ |")
        assert "policy_settings.mode" in lines[0]
        assert "'Detection'" in lines[0]
        assert "'Prevention'" in lines[0]

    def test_skips_no_change(self):
        fmt = PolicySettingsFormatter()
        plan = PolicySettingsPlan(
            changes=[PolicySettingsChange("mode", "Prevention", "Prevention")]
        )
        assert fmt.format_markdown([plan], pending_diffs=[]) == []

    def test_empty_plans(self):
        fmt = PolicySettingsFormatter()
        assert fmt.format_markdown([], pending_diffs=[]) == []


# ---------------------------------------------------------------------------
# Format extension — format_html
# ---------------------------------------------------------------------------
class TestFormatHtml:
    def test_with_changes(self):
        fmt = PolicySettingsFormatter()
        plan = PolicySettingsPlan(
            changes=[
                PolicySettingsChange("mode", "Detection", "Prevention"),
                PolicySettingsChange("enabled_state", "Enabled", "Disabled"),
            ]
        )
        lines: list[str] = []
        result = fmt.format_html([plan], lines)
        assert result == (0, 0, 2, 0)
        html = "\n".join(lines)
        assert "<table>" in html
        assert "</table>" in html
        assert "Modify" in html
        assert "policy_settings.mode" in html
        assert "policy_settings.enabled_state" in html
        assert "&rarr;" in html
        assert "Updates=2" in html

    def test_skips_no_change(self):
        fmt = PolicySettingsFormatter()
        plan = PolicySettingsPlan(
            changes=[PolicySettingsChange("mode", "Prevention", "Prevention")]
        )
        lines: list[str] = []
        result = fmt.format_html([plan], lines)
        assert result == (0, 0, 0, 0)
        assert lines == []

    def test_empty_plans(self):
        fmt = PolicySettingsFormatter()
        lines: list[str] = []
        result = fmt.format_html([], lines)
        assert result == (0, 0, 0, 0)
        assert lines == []

    def test_escapes_special_chars(self):
        fmt = PolicySettingsFormatter()
        plan = PolicySettingsPlan(changes=[PolicySettingsChange("mode", "<script>", "Prevention")])
        lines: list[str] = []
        fmt.format_html([plan], lines)
        html = "\n".join(lines)
        assert "&lt;script&gt;" in html
        assert "<script>" not in html.replace("&lt;script&gt;", "")


# ---------------------------------------------------------------------------
# Format extension — format_report
# ---------------------------------------------------------------------------
class TestFormatReport:
    def test_with_drift(self):
        fmt = PolicySettingsFormatter()
        plan = PolicySettingsPlan(
            changes=[
                PolicySettingsChange("mode", "Detection", "Prevention"),
                PolicySettingsChange("enabled_state", "Enabled", "Disabled"),
            ]
        )
        phases_data: list[dict] = []
        result = fmt.format_report([plan], zone_has_drift=False, phases_data=phases_data)
        assert result is True
        assert len(phases_data) == 1
        entry = phases_data[0]
        assert entry["phase"] == "policy_settings"
        assert entry["provider_id"] == "azure_waf_policy_settings"
        assert entry["status"] == "drifted"
        assert entry["modifies"] == 2
        assert entry["adds"] == 0
        assert entry["removes"] == 0

    def test_preserves_incoming_drift(self):
        fmt = PolicySettingsFormatter()
        plan = PolicySettingsPlan(
            changes=[PolicySettingsChange("mode", "Prevention", "Prevention")]
        )
        phases_data: list[dict] = []
        result = fmt.format_report([plan], zone_has_drift=True, phases_data=phases_data)
        assert result is True
        assert phases_data == []

    def test_no_drift(self):
        fmt = PolicySettingsFormatter()
        phases_data: list[dict] = []
        result = fmt.format_report([], zone_has_drift=False, phases_data=phases_data)
        assert result is False
        assert phases_data == []


# ---------------------------------------------------------------------------
# Format extension — format_plan and count_changes
# ---------------------------------------------------------------------------
class TestFormatPlanAndCount:
    def test_format_plan(self):
        fmt = PolicySettingsFormatter()
        plan = PolicySettingsPlan(changes=[PolicySettingsChange("mode", "Detection", "Prevention")])
        lines = fmt.format_plan([plan], "my-policy")
        assert len(lines) == 1
        assert "my-policy" in lines[0]
        assert "Detection" in lines[0]
        assert "Prevention" in lines[0]

    def test_count_changes(self):
        fmt = PolicySettingsFormatter()
        plan = PolicySettingsPlan(
            changes=[
                PolicySettingsChange("mode", "Detection", "Prevention"),
                PolicySettingsChange("enabled_state", "Enabled", "Enabled"),  # no change
                PolicySettingsChange("request_body_check", True, False),
            ]
        )
        assert fmt.count_changes([plan]) == 2

    def test_empty(self):
        fmt = PolicySettingsFormatter()
        assert fmt.format_plan([], "z") == []
        assert fmt.count_changes([]) == 0


# ---------------------------------------------------------------------------
# Provider methods
# ---------------------------------------------------------------------------
class TestProviderGetPolicySettings:
    def test_get_policy_settings_fd(self):
        from octorules_azure.provider import AzureWafProvider

        policy_dict = {
            "name": "test-policy",
            "policy_settings": {
                "enabled_state": "Enabled",
                "mode": "Prevention",
                "request_body_check": "Enabled",
            },
        }
        client = MagicMock()
        # to_plain_dict checks isinstance(obj, dict) first, so return a dict
        client.policies.get.return_value = policy_dict
        provider = AzureWafProvider(
            subscription_id="sub-123",
            resource_group="rg-test",
            waf_type="front_door",
            client=client,
        )
        scope = _scope()
        result = provider.get_policy_settings(scope)
        assert result["enabled_state"] == "Enabled"
        assert result["mode"] == "Prevention"
        assert result["request_body_check"] is True

    def test_get_policy_settings_ag(self):
        from octorules_azure.provider import AzureWafProvider

        policy_dict = {
            "name": "test-policy",
            "policy_settings": {
                "state": "Enabled",
                "mode": "Detection",
                "request_body_check": True,
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
        scope = _scope()
        result = provider.get_policy_settings(scope)
        assert result["enabled_state"] == "Enabled"
        assert result["mode"] == "Detection"
        assert result["request_body_check"] is True


class TestProviderUpdatePolicySettings:
    def test_update_policy_settings_fd(self):
        from octorules_azure.provider import AzureWafProvider

        policy_data = {
            "name": "test-policy",
            "etag": '"etag-1"',
            "policy_settings": {
                "enabled_state": "Enabled",
                "mode": "Detection",
            },
        }
        client = MagicMock()
        # get_policy returns a dict (to_plain_dict passes dicts through)
        client.policies.get.return_value = policy_data
        # put_policy calls begin_create_or_update which returns a poller;
        # poller.result() returns the updated policy dict
        client.policies.begin_create_or_update.return_value.result.return_value = policy_data
        provider = AzureWafProvider(
            subscription_id="sub-123",
            resource_group="rg-test",
            waf_type="front_door",
            client=client,
        )
        scope = _scope()
        provider.update_policy_settings(scope, {"mode": "Prevention"})
        # Verify put_policy was called
        client.policies.begin_create_or_update.assert_called_once()
        call_args = client.policies.begin_create_or_update.call_args
        updated_policy = call_args[0][2]
        assert updated_policy["policy_settings"]["mode"] == "Prevention"

    def test_update_policy_settings_ag(self):
        from octorules_azure.provider import AzureWafProvider

        policy_data = {
            "name": "test-policy",
            "etag": '"etag-1"',
            "policy_settings": {
                "state": "Enabled",
                "mode": "Detection",
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
        scope = _scope()
        provider.update_policy_settings(scope, {"enabled_state": "Disabled"})
        client.web_application_firewall_policies.create_or_update.assert_called_once()
        call_args = client.web_application_firewall_policies.create_or_update.call_args
        updated_policy = call_args[0][2]
        assert updated_policy["policy_settings"]["state"] == "Disabled"
