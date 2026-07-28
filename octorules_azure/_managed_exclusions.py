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
from dataclasses import dataclass, field

from octorules.extensions import ProviderExtension, SettingsChange, SettingsFormatter
from octorules.registration import idempotent_registration

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class ManagedExclusionsPlan:
    """Plan for global managed-rule exclusion changes in a zone.

    The exclusion lists are the source of truth — apply sends ``desired``
    wholesale — so ``changes`` is a view over them that lets core's
    :class:`SettingsFormatter` render this plan like any other settings
    section, instead of hand-rolling a formatter against private core names.
    """

    current: list[dict] = field(default_factory=list)
    desired: list[dict] = field(default_factory=list)
    # Nothing here is plan-gated; present so SettingsFormatter can read it.
    unsupported: list[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return self.current != self.desired

    @property
    def total_changes(self) -> int:
        return 1 if self.has_changes else 0

    @property
    def changes(self) -> list[SettingsChange]:
        if not self.has_changes:
            return []
        return [
            SettingsChange(
                field="exclusions",
                current=len(self.current),
                desired=len(self.desired),
            )
        ]


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
    desired = all_desired.get("azure.waf_managed_exclusions")
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
        zp.extension_plans.setdefault("azure.waf_managed_exclusions", []).append(plan)


def _apply_managed_exclusions(zp, plans, scope, provider):
    """Apply global managed exclusion changes."""
    synced: list[str] = []

    for plan in plans:
        if not isinstance(plan, ManagedExclusionsPlan) or not plan.has_changes:
            continue

        provider.update_managed_exclusions(scope, plan.desired)
        synced.append("azure.waf_managed_exclusions")

    return synced, None


def _validate_managed_exclusions(desired, zone_name, errors, lines):
    """Validate azure_waf_managed_exclusions offline."""
    exclusions = desired.get("azure.waf_managed_exclusions")
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


def _dump_managed_exclusions(scope, provider):
    """Export current global managed exclusions to dump output."""
    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        exclusions = provider.get_managed_exclusions(scope)
    except ProviderAuthError:
        raise
    except ProviderError:
        return None

    if exclusions:
        return {"azure.waf_managed_exclusions": exclusions}
    return None


# ---------------------------------------------------------------------------
# Format extension
# ---------------------------------------------------------------------------
class ManagedExclusionsFormatter(SettingsFormatter):
    """Formats global managed exclusion diffs for plan output.

    Text, markdown and HTML come from core.  Only JSON is overridden, to
    carry the full exclusion lists rather than the counts the shared
    formatter renders.
    """

    def __init__(self) -> None:
        super().__init__(plan_type=ManagedExclusionsPlan, prefix="managed_exclusions")

    def format_json(self, plans: list) -> list[dict]:
        result: list[dict] = []
        for plan in self._active_plans(plans):
            result.append({"current": plan.current, "desired": plan.desired})
        return result


# ---------------------------------------------------------------------------
# Extension
# ---------------------------------------------------------------------------
class ManagedExclusionsExtension(ProviderExtension):
    """Managed-rule exclusions."""

    section = "azure.waf_managed_exclusions"

    def prefetch(self, desired, scope, provider):
        return _prefetch_managed_exclusions(desired, scope, provider)

    def finalize(self, zp, desired, scope, provider, ctx):
        return _finalize_managed_exclusions(zp, desired, scope, provider, ctx)

    def apply(self, zp, plans, scope, provider):
        return _apply_managed_exclusions(zp, plans, scope, provider)

    def dump(self, scope, provider):
        return _dump_managed_exclusions(scope, provider)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
@idempotent_registration
def register_managed_exclusions() -> None:
    """Register all managed exclusions hooks with the core extension system."""
    from octorules.extensions import (
        register_format_extension,
        register_validate_extension,
    )

    register_format_extension("azure.waf_managed_exclusions", ManagedExclusionsFormatter())
    register_validate_extension(_validate_managed_exclusions)
