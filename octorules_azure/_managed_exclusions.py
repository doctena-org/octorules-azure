"""Global managed-rule exclusions for Azure WAF policies.

These are policy-level exclusions that apply across all managed rule sets,
stored at ``managed_rules.exclusions`` in the Azure SDK model.

Only applicable to Application Gateway WAF policies (Front Door does not
have a policy-wide ``managed_rules.exclusions`` array).

Uses the same extension hook pattern as ``_policy_settings.py``:
plan_zone_hook (prefetch + finalize), apply_extension, format_extension,
validate_extension, and dump_extension.
"""

import logging
import threading
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class ManagedExclusionsPlan:
    """Plan for global managed-rule exclusion changes in a zone."""

    current: list[dict] = field(default_factory=list)
    desired: list[dict] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return self.current != self.desired

    @property
    def total_changes(self) -> int:
        return 1 if self.has_changes else 0


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
def normalize_managed_exclusions(policy: dict) -> list[dict]:
    """Extract ``managed_rules.exclusions`` from a policy dict.

    Returns an empty list if the field is absent or empty.
    """
    managed = policy.get("managed_rules") or {}
    exclusions = managed.get("exclusions")
    if isinstance(exclusions, list):
        return list(exclusions)
    return []


def denormalize_managed_exclusions(policy: dict, exclusions: list[dict]) -> dict:
    """Write ``managed_rules.exclusions`` back into a policy dict.

    Mutates *policy* in-place and returns it.
    """
    if "managed_rules" not in policy:
        policy["managed_rules"] = {}
    policy["managed_rules"]["exclusions"] = exclusions
    return policy


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------
def diff_managed_exclusions(current: list[dict], desired: list[dict]) -> ManagedExclusionsPlan:
    """Diff current vs desired global managed exclusions."""
    return ManagedExclusionsPlan(current=current, desired=desired)


# ---------------------------------------------------------------------------
# Extension hooks
# ---------------------------------------------------------------------------
def _prefetch_managed_exclusions(all_desired, scope, provider):
    """Prefetch: fetch current global managed exclusions."""
    desired = all_desired.get("azure_waf_managed_exclusions")
    if desired is None:
        return None

    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        current = provider.get_managed_exclusions(scope)
    except ProviderAuthError:
        raise
    except ProviderError:
        log.warning("Failed to fetch managed exclusions for %s", scope.label)
        current = []

    return (current, desired)


def _finalize_managed_exclusions(zp, all_desired, scope, provider, ctx):
    """Finalize: compute diff and add to zone plan."""
    if ctx is None:
        return

    current, desired = ctx
    plan = diff_managed_exclusions(current, desired)
    if plan.has_changes:
        zp.extension_plans.setdefault("azure_waf_managed_exclusions", []).append(plan)


def _apply_managed_exclusions(zp, plans, scope, provider):
    """Apply global managed exclusion changes."""
    synced: list[str] = []

    for plan in plans:
        if not isinstance(plan, ManagedExclusionsPlan) or not plan.has_changes:
            continue

        provider.update_managed_exclusions(scope, plan.desired)
        synced.append("azure_waf_managed_exclusions")

    return synced, None


def _validate_managed_exclusions(desired, zone_name, errors, lines):
    """Validate azure_waf_managed_exclusions offline."""
    exclusions = desired.get("azure_waf_managed_exclusions")
    if exclusions is None:
        return

    from octorules_azure.validate import _WAF_TYPE

    if _WAF_TYPE.get() == "front_door":
        errors.append(
            f"  {zone_name}/azure_waf_managed_exclusions:"
            " not supported on Front Door WAF (only Application Gateway)"
        )
        return

    if not isinstance(exclusions, list):
        errors.append(
            f"  {zone_name}/azure_waf_managed_exclusions:"
            f" must be a list, got {type(exclusions).__name__}"
        )
        return

    for i, exc in enumerate(exclusions):
        if not isinstance(exc, dict):
            errors.append(
                f"  {zone_name}/azure_waf_managed_exclusions[{i}]:"
                f" must be a dict, got {type(exc).__name__}"
            )


def _dump_managed_exclusions(scope, provider, out_dir):
    """Export current global managed exclusions to dump output."""
    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        exclusions = provider.get_managed_exclusions(scope)
    except ProviderAuthError:
        raise
    except ProviderError:
        return None

    if exclusions:
        return {"azure_waf_managed_exclusions": exclusions}
    return None


# ---------------------------------------------------------------------------
# Format extension
# ---------------------------------------------------------------------------
class ManagedExclusionsFormatter:
    """Formats global managed exclusion diffs for plan output."""

    def format_text(self, plans: list, use_color: bool) -> list[str]:
        from octorules._color import Pen

        p = Pen(use_color)
        lines: list[str] = []
        for plan in plans:
            if not isinstance(plan, ManagedExclusionsPlan) or not plan.has_changes:
                continue
            line = f"  ~ managed_exclusions: {len(plan.current)} -> {len(plan.desired)} exclusions"
            lines.append(p.warning(line))
        return lines

    def format_json(self, plans: list) -> list[dict]:
        result: list[dict] = []
        for plan in plans:
            if not isinstance(plan, ManagedExclusionsPlan) or not plan.has_changes:
                continue
            result.append(
                {
                    "current": plan.current,
                    "desired": plan.desired,
                }
            )
        return result

    def format_markdown(
        self, plans: list, pending_diffs: list[list[tuple[str, object, object]]]
    ) -> list[str]:
        from octorules.formatter import _md_escape

        lines: list[str] = []
        for plan in plans:
            if not isinstance(plan, ManagedExclusionsPlan) or not plan.has_changes:
                continue
            label = _md_escape("managed_exclusions")
            detail = _md_escape(f"{len(plan.current)} -> {len(plan.desired)} exclusions")
            lines.append(f"| ~ | {label} | | {detail} |")
        return lines

    def format_html(self, plans: list, lines: list[str]) -> tuple[int, int, int, int]:
        from html import escape as html_escape

        from octorules.formatter import _HTML_TABLE_HEADER, _html_summary_row

        total_modifies = 0
        for plan in plans:
            if not isinstance(plan, ManagedExclusionsPlan) or not plan.has_changes:
                continue
            lines.extend(_HTML_TABLE_HEADER)
            total_modifies += 1
            label = html_escape("managed_exclusions")
            detail = html_escape(f"{len(plan.current)} -> {len(plan.desired)} exclusions")
            lines.append("  <tr>")
            lines.append("    <td>Modify</td>")
            lines.append(f"    <td>{label}</td>")
            lines.append(f"    <td>{detail}</td>")
            lines.append("  </tr>")
            lines.extend(_html_summary_row(0, 0, 1, 0))
            lines.append("</table>")
        return 0, 0, total_modifies, 0

    def format_report(self, plans: list, zone_has_drift: bool, phases_data: list[dict]) -> bool:
        total_modifies = 0
        for plan in plans:
            if isinstance(plan, ManagedExclusionsPlan) and plan.has_changes:
                total_modifies += 1
        if total_modifies:
            zone_has_drift = True
            phases_data.append(
                {
                    "phase": "managed_exclusions",
                    "provider_id": "azure_waf_managed_exclusions",
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


def register_managed_exclusions() -> None:
    """Register all managed exclusions hooks with the core extension system."""
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

        register_plan_zone_hook(_prefetch_managed_exclusions, _finalize_managed_exclusions)
        register_apply_extension("azure_waf_managed_exclusions", _apply_managed_exclusions)
        register_format_extension("azure_waf_managed_exclusions", ManagedExclusionsFormatter())
        register_validate_extension(_validate_managed_exclusions)
        register_dump_extension(_dump_managed_exclusions)
        _registered = True
