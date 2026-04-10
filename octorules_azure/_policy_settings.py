"""Policy settings management for Azure WAF policies.

These are non-phase YAML sections handled via extension hooks:
- ``azure_waf_policy_settings`` — policy mode, enabled state, body
  inspection, and other policy-level knobs

Uses plan_zone_hook (prefetch + finalize), apply_extension, format_extension,
validate_extension, and dump_extension — same pattern as Bunny's Shield
config in ``octorules_bunny/_shield_config.py``.
"""

import logging
import threading
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model for policy settings diffs
# ---------------------------------------------------------------------------
@dataclass
class PolicySettingsChange:
    """A single field change in policy settings."""

    field: str
    current: object
    desired: object

    @property
    def has_changes(self) -> bool:
        return self.current != self.desired


@dataclass
class PolicySettingsPlan:
    """Plan for all policy settings changes in a zone."""

    changes: list[PolicySettingsChange] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return any(c.has_changes for c in self.changes)

    @property
    def total_changes(self) -> int:
        return sum(1 for c in self.changes if c.has_changes)


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
    desired = all_desired.get("azure_waf_policy_settings")
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
        zp.extension_plans.setdefault("azure_waf_policy_settings", []).append(plan)


def _apply_policy_settings(zp, plans, scope, provider):
    """Apply policy settings changes."""
    synced: list[str] = []

    for plan in plans:
        if not isinstance(plan, PolicySettingsPlan) or not plan.has_changes:
            continue

        desired_values = {c.field: c.desired for c in plan.changes if c.has_changes}
        if desired_values:
            provider.update_policy_settings(scope, desired_values)
            synced.append("azure_waf_policy_settings")

    return synced, None


def _validate_policy_settings(desired, zone_name, errors, lines):
    """Validate azure_waf_policy_settings offline."""
    settings = desired.get("azure_waf_policy_settings")
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


def _dump_policy_settings(scope, provider, out_dir):
    """Export current policy settings to dump output."""
    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        settings = provider.get_policy_settings(scope)
    except ProviderAuthError:
        raise
    except ProviderError:
        return None

    if settings:
        return {"azure_waf_policy_settings": settings}
    return None


# ---------------------------------------------------------------------------
# Format extension
# ---------------------------------------------------------------------------
class PolicySettingsFormatter:
    """Formats policy settings diffs for plan output."""

    def format_text(self, plans: list, use_color: bool) -> list[str]:
        from octorules._color import Pen

        p = Pen(use_color)
        lines: list[str] = []
        for plan in plans:
            if not isinstance(plan, PolicySettingsPlan) or not plan.has_changes:
                continue
            for change in plan.changes:
                if not change.has_changes:
                    continue
                label = f"policy_settings.{change.field}"
                line = f"  ~ {label}: {change.current!r} -> {change.desired!r}"
                lines.append(p.warning(line))
        return lines

    def format_json(self, plans: list) -> list[dict]:
        result: list[dict] = []
        for plan in plans:
            if not isinstance(plan, PolicySettingsPlan) or not plan.has_changes:
                continue
            changes = []
            for change in plan.changes:
                if not change.has_changes:
                    continue
                changes.append(
                    {
                        "field": change.field,
                        "current": change.current,
                        "desired": change.desired,
                    }
                )
            if changes:
                result.append({"changes": changes})
        return result

    def format_markdown(
        self, plans: list, pending_diffs: list[list[tuple[str, object, object]]]
    ) -> list[str]:
        from octorules.formatter import _md_escape

        lines: list[str] = []
        for plan in plans:
            if not isinstance(plan, PolicySettingsPlan) or not plan.has_changes:
                continue
            for change in plan.changes:
                if not change.has_changes:
                    continue
                label = _md_escape(f"policy_settings.{change.field}")
                cur = _md_escape(repr(change.current))
                des = _md_escape(repr(change.desired))
                lines.append(f"| ~ | {label} | | {cur} -> {des} |")
        return lines

    def format_html(self, plans: list, lines: list[str]) -> tuple[int, int, int, int]:
        from html import escape as html_escape

        from octorules.formatter import _HTML_TABLE_HEADER, _html_summary_row

        total_modifies = 0
        for plan in plans:
            if not isinstance(plan, PolicySettingsPlan) or not plan.has_changes:
                continue
            lines.extend(_HTML_TABLE_HEADER)
            plan_modifies = 0
            for change in plan.changes:
                if not change.has_changes:
                    continue
                plan_modifies += 1
                label = html_escape(f"policy_settings.{change.field}")
                cur = html_escape(repr(change.current))
                des = html_escape(repr(change.desired))
                lines.append("  <tr>")
                lines.append("    <td>Modify</td>")
                lines.append(f"    <td>{label}</td>")
                lines.append(f"    <td>{cur} &rarr; {des}</td>")
                lines.append("  </tr>")
            lines.extend(_html_summary_row(0, 0, plan_modifies, 0))
            lines.append("</table>")
            total_modifies += plan_modifies
        return 0, 0, total_modifies, 0

    def format_report(self, plans: list, zone_has_drift: bool, phases_data: list[dict]) -> bool:
        total_modifies = 0
        for plan in plans:
            if not isinstance(plan, PolicySettingsPlan) or not plan.has_changes:
                continue
            total_modifies += sum(1 for c in plan.changes if c.has_changes)
        if total_modifies:
            zone_has_drift = True
            phases_data.append(
                {
                    "phase": "policy_settings",
                    "provider_id": "azure_waf_policy_settings",
                    "status": "drifted",
                    "yaml_rules": 0,
                    "live_rules": 0,
                    "adds": 0,
                    "removes": 0,
                    "modifies": total_modifies,
                }
            )
        return zone_has_drift


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
_registered = False
_register_lock = threading.Lock()


def register_policy_settings() -> None:
    """Register all policy settings hooks with the core extension system."""
    global _registered
    with _register_lock:
        if _registered:
            return

        from octorules.extensions import (
            register_apply_extension,
            register_dump_extension,
            register_format_extension,
            register_plan_zone_hook,
            register_validate_extension,
        )

        register_plan_zone_hook(_prefetch_policy_settings, _finalize_policy_settings)
        register_apply_extension("azure_waf_policy_settings", _apply_policy_settings)
        register_format_extension("azure_waf_policy_settings", PolicySettingsFormatter())
        register_validate_extension(_validate_policy_settings)
        register_dump_extension(_dump_policy_settings)
        _registered = True
