"""Tests that extension registration wires up correctly."""

from octorules.extensions import _format_extensions

import octorules_azure  # noqa: F401 — triggers __init__.py registration


def _plan_keys() -> set[str]:
    """Plan keys the provider exposes.

    Apply is reached through ``provider.extensions`` rather than a registry,
    so this asserts on what core actually walks.
    """
    from octorules_azure.provider import AzureWafProvider

    inst = object.__new__(AzureWafProvider)
    return {e.plan_key() for e in AzureWafProvider.extensions.fget(inst)}


# --- policy settings ---


def test_policy_settings_format_registered():
    assert "azure.waf_policy_settings" in _format_extensions


def test_policy_settings_apply_registered():
    assert "azure.waf_policy_settings" in _plan_keys()


# --- managed exclusions ---


def test_managed_exclusions_format_registered():
    assert "azure.waf_managed_exclusions" in _format_extensions


def test_managed_exclusions_apply_registered():
    assert "azure.waf_managed_exclusions" in _plan_keys()
