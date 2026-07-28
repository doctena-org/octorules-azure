"""Policy settings management for Azure WAF policies.

These are non-phase YAML sections handled via extension hooks:
- ``azure_waf_policy_settings`` — policy mode, enabled state, body
  inspection, and other policy-level knobs

Uses plan_zone_hook (prefetch + finalize), apply_extension, format_extension,
validate_extension, and dump_extension — same pattern as Bunny's Shield
config in ``octorules_bunny/_shield_config.py``.
"""

import logging

from octorules.extensions import ProviderExtension, SettingsChange, SettingsPlan
from octorules.extensions import SettingsFormatter as CoreSettingsFormatter
from octorules.registration import idempotent_registration

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model for policy settings diffs
# ---------------------------------------------------------------------------
class PolicySettingsChange(SettingsChange):
    """A single field change in policy settings."""

    pass


class PolicySettingsPlan(SettingsPlan):
    """Plan for all policy settings changes in a zone."""

    pass


# ---------------------------------------------------------------------------
# Valid enum values
# ---------------------------------------------------------------------------
_VALID_MODES = frozenset({"Detection", "Prevention"})
_VALID_ENABLED_STATES = frozenset({"Enabled", "Disabled"})


# ---------------------------------------------------------------------------
# Normalization: SDK format -> YAML-friendly canonical form
# ---------------------------------------------------------------------------
def normalize_policy_settings(raw_settings: dict, waf_type: str) -> dict:
    """Convert SDK policy_settings to YAML-friendly canonical form.

    Front Door uses ``enabled_state`` and string ``request_body_check``
    ("Enabled"/"Disabled").  App Gateway uses ``state`` and boolean
    ``request_body_check``.  The canonical form uses ``enabled_state``
    (string) and ``request_body_check`` (bool).
    """
    if not raw_settings:
        return {}

    result: dict = {}

    # enabled_state: FD uses "enabled_state", AG uses "state"
    if waf_type == "app_gateway":
        state = raw_settings.get("state")
    else:
        state = raw_settings.get("enabled_state")
    if state is not None:
        result["enabled_state"] = state

    # mode: both use "mode" as-is
    mode = raw_settings.get("mode")
    if mode is not None:
        result["mode"] = mode

    # request_body_check: FD string "Enabled"/"Disabled" -> bool,
    # AG already bool
    rbc = raw_settings.get("request_body_check")
    if rbc is not None:
        if waf_type == "front_door" and isinstance(rbc, str):
            result["request_body_check"] = rbc == "Enabled"
        else:
            result["request_body_check"] = bool(rbc)

    # log_scrubbing: pass through as-is (both types)
    ls = raw_settings.get("log_scrubbing")
    if ls is not None:
        result["log_scrubbing"] = ls

    # FD-specific fields
    if waf_type == "front_door":
        for key in (
            "redirect_url",
            "custom_block_response_status_code",
            "custom_block_response_body",
            "javascript_challenge_expiration_in_minutes",
        ):
            val = raw_settings.get(key)
            if val is not None:
                result[key] = val

    # AG-specific fields
    if waf_type == "app_gateway":
        for key in (
            "max_request_body_size_in_kb",
            "file_upload_limit_in_mb",
            "request_body_inspect_limit_in_kb",
            "custom_block_response_status_code",
            "custom_block_response_body",
            "js_challenge_cookie_expiration_in_mins",
        ):
            val = raw_settings.get(key)
            if val is not None:
                result[key] = val
        # AG-only boolean fields
        for bool_key in ("request_body_enforcement", "file_upload_enforcement"):
            bval = raw_settings.get(bool_key)
            if bval is not None:
                result[bool_key] = bool(bval)

    return result


# ---------------------------------------------------------------------------
# Denormalization: YAML canonical form -> SDK format
# ---------------------------------------------------------------------------
def denormalize_policy_settings(settings: dict, waf_type: str) -> dict:
    """Convert YAML canonical form back to SDK format for API update.

    Only includes keys that are present in *settings* so that partial
    updates don't reset unspecified fields to defaults.
    """
    if not settings:
        return {}

    result: dict = {}

    # enabled_state -> FD "enabled_state", AG "state"
    if "enabled_state" in settings:
        if waf_type == "app_gateway":
            result["state"] = settings["enabled_state"]
        else:
            result["enabled_state"] = settings["enabled_state"]

    # mode: both use "mode"
    if "mode" in settings:
        result["mode"] = settings["mode"]

    # request_body_check: bool -> FD string, AG bool
    if "request_body_check" in settings:
        val = settings["request_body_check"]
        if waf_type == "front_door":
            result["request_body_check"] = "Enabled" if val else "Disabled"
        else:
            result["request_body_check"] = bool(val)

    # log_scrubbing: pass through
    if "log_scrubbing" in settings:
        result["log_scrubbing"] = settings["log_scrubbing"]

    # FD-specific fields: pass through
    if waf_type == "front_door":
        for key in (
            "redirect_url",
            "custom_block_response_status_code",
            "custom_block_response_body",
            "javascript_challenge_expiration_in_minutes",
        ):
            if key in settings:
                result[key] = settings[key]

    # AG-specific fields: pass through
    if waf_type == "app_gateway":
        for key in (
            "max_request_body_size_in_kb",
            "file_upload_limit_in_mb",
            "request_body_inspect_limit_in_kb",
            "custom_block_response_status_code",
            "custom_block_response_body",
            "request_body_enforcement",
            "file_upload_enforcement",
            "js_challenge_cookie_expiration_in_mins",
        ):
            if key in settings:
                result[key] = settings[key]

    return result


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------
def diff_policy_settings(current: dict, desired: dict) -> PolicySettingsPlan:
    """Diff current vs desired policy settings.

    Only diffs keys present in *desired* (partial update semantics).
    """
    changes: list[PolicySettingsChange] = []
    for key in sorted(desired.keys()):
        cur = current.get(key)
        des = desired.get(key)
        if cur != des:
            changes.append(PolicySettingsChange(field=key, current=cur, desired=des))
    return PolicySettingsPlan(changes=changes)


# ---------------------------------------------------------------------------
# Extension hooks
# ---------------------------------------------------------------------------
def _prefetch_policy_settings(all_desired, scope, provider):
    """Prefetch: fetch current policy settings."""
    desired = all_desired.get("azure.waf_policy_settings")
    if desired is None:
        return None

    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        current = provider.get_policy_settings(scope)
    except ProviderAuthError:
        raise
    except ProviderError:
        log.warning("Failed to fetch policy settings for %s", scope.label)
        current = {}

    return (current, desired)


def _finalize_policy_settings(zp, all_desired, scope, provider, ctx):
    """Finalize: compute diff and add to zone plan."""
    if ctx is None:
        return

    current, desired = ctx
    plan = diff_policy_settings(current, desired)
    if plan.has_changes:
        zp.extension_plans.setdefault("azure.waf_policy_settings", []).append(plan)


def _apply_policy_settings(zp, plans, scope, provider):
    """Apply policy settings changes."""
    synced: list[str] = []

    for plan in plans:
        if not isinstance(plan, PolicySettingsPlan) or not plan.has_changes:
            continue

        desired_values = {c.field: c.desired for c in plan.changes if c.has_changes}
        if desired_values:
            provider.update_policy_settings(scope, desired_values)
            synced.append("azure.waf_policy_settings")

    return synced, None


def _validate_policy_settings(desired, zone_name, errors, lines):
    """Validate azure_waf_policy_settings offline."""
    settings = desired.get("azure.waf_policy_settings")
    if not isinstance(settings, dict):
        return

    mode = settings.get("mode")
    if mode is not None and mode not in _VALID_MODES:
        errors.append(
            f"  {zone_name}/azure_waf_policy_settings: invalid"
            f" mode {mode!r} (must be one of {sorted(_VALID_MODES)})"
        )

    enabled_state = settings.get("enabled_state")
    if enabled_state is not None and enabled_state not in _VALID_ENABLED_STATES:
        errors.append(
            f"  {zone_name}/azure_waf_policy_settings: invalid"
            f" enabled_state {enabled_state!r} (must be one of {sorted(_VALID_ENABLED_STATES)})"
        )

    rbc = settings.get("request_body_check")
    if rbc is not None and not isinstance(rbc, bool):
        errors.append(
            f"  {zone_name}/azure_waf_policy_settings: invalid"
            f" request_body_check {rbc!r} (must be a boolean)"
        )


def _dump_policy_settings(scope, provider):
    """Export current policy settings to dump output."""
    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        settings = provider.get_policy_settings(scope)
    except ProviderAuthError:
        raise
    except ProviderError:
        return None

    if settings:
        return {"azure.waf_policy_settings": settings}
    return None


# ---------------------------------------------------------------------------
# Format extension
# ---------------------------------------------------------------------------


class PolicySettingsFormatter(CoreSettingsFormatter):
    """Formats policy settings diffs for plan output."""

    def __init__(self) -> None:
        super().__init__(
            plan_type=PolicySettingsPlan,
            prefix="policy_settings",
        )


# ---------------------------------------------------------------------------
# Extension
# ---------------------------------------------------------------------------
class PolicySettingsExtension(ProviderExtension):
    """WAF policy-level settings."""

    section = "azure.waf_policy_settings"
    formatter = PolicySettingsFormatter()

    def prefetch(self, desired, scope, provider):
        return _prefetch_policy_settings(desired, scope, provider)

    def finalize(self, zp, desired, scope, provider, ctx):
        return _finalize_policy_settings(zp, desired, scope, provider, ctx)

    def apply(self, zp, plans, scope, provider):
        return _apply_policy_settings(zp, plans, scope, provider)

    def dump(self, scope, provider):
        return _dump_policy_settings(scope, provider)

    def validate(self, desired, zone_name, errors, lines):
        return _validate_policy_settings(desired, zone_name, errors, lines)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
@idempotent_registration
def register_policy_settings() -> None:
    """Register all policy settings hooks with the core extension system."""
    from octorules.extensions import (
        register_format_extension,
        register_validate_extension,
    )

    register_format_extension("azure.waf_policy_settings", PolicySettingsFormatter())
    register_validate_extension(_validate_policy_settings)
