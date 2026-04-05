"""Tests that extension registration wires up correctly."""

from octorules.extensions import _apply_extensions, _format_extensions

import octorules_azure  # noqa: F401 — triggers __init__.py registration

# --- policy settings ---


def test_policy_settings_format_registered():
    assert "azure_waf_policy_settings" in _format_extensions


def test_policy_settings_apply_registered():
    assert "azure_waf_policy_settings" in _apply_extensions


# --- managed exclusions ---


def test_managed_exclusions_format_registered():
    assert "azure_waf_managed_exclusions" in _format_extensions


def test_managed_exclusions_apply_registered():
    assert "azure_waf_managed_exclusions" in _apply_extensions
