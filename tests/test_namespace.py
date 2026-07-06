"""Tests for Azure WAF namespace registration and nested zone format."""

import pytest
from octorules.config import normalize_zone_format
from octorules.phases import PROVIDER_NAMESPACES


class TestAzureNamespace:
    """Verify Azure namespace registration and nested format support."""

    def test_namespace_registered(self):
        """Verify 'azure' namespace is registered with correct mapping."""
        assert "azure" in PROVIDER_NAMESPACES
        namespace = PROVIDER_NAMESPACES["azure"]

        # Expected mapping: nested key -> canonical flat key
        expected = {
            "waf_custom_rules": "azure_waf_custom_rules",
            "waf_rate_rules": "azure_waf_rate_rules",
            "waf_managed_rules": "azure_waf_managed_rules",
            "waf_policy_settings": "azure_waf_policy_settings",
            "waf_managed_exclusions": "azure_waf_managed_exclusions",
        }
        assert namespace == expected

    def test_normalize_nested_to_flat(self):
        """Verify normalize_zone_format converts nested format to flat."""
        nested = {
            "azure": {
                "waf_custom_rules": [
                    {
                        "ref": "BlockBadIPs",
                        "priority": 1,
                        "action": "Block",
                    }
                ],
                "waf_rate_rules": [
                    {
                        "ref": "RateLimit",
                        "priority": 100,
                        "action": "Block",
                    }
                ],
                "waf_policy_settings": {
                    "mode": "Prevention",
                },
                "waf_managed_exclusions": [
                    {
                        "matchVariable": "RequestArgNames",
                        "selector": "q",
                    }
                ],
            }
        }

        # Normalize to flat format
        flat = normalize_zone_format(nested)

        # Verify flat keys are present
        assert "azure_waf_custom_rules" in flat
        assert "azure_waf_rate_rules" in flat
        assert "azure_waf_policy_settings" in flat
        assert "azure_waf_managed_exclusions" in flat

        # Verify nested key is removed
        assert "azure" not in flat

        # Verify content is unchanged
        assert flat["azure_waf_custom_rules"] == nested["azure"]["waf_custom_rules"]
        assert flat["azure_waf_rate_rules"] == nested["azure"]["waf_rate_rules"]
        assert flat["azure_waf_policy_settings"] == nested["azure"]["waf_policy_settings"]
        assert flat["azure_waf_managed_exclusions"] == nested["azure"]["waf_managed_exclusions"]

    def test_mixed_flat_and_nested_same_key_error(self):
        """Verify that mixing flat and nested spelling of same key raises ConfigError."""
        from octorules.config import ConfigError

        mixed = {
            "azure": {
                "waf_custom_rules": [
                    {
                        "ref": "Rule1",
                        "priority": 1,
                        "action": "Block",
                    }
                ]
            },
            # Flat spelling of the same waf_custom_rules key
            "azure_waf_custom_rules": [
                {
                    "ref": "Rule2",
                    "priority": 100,
                    "action": "Block",
                }
            ],
        }

        # Should raise ConfigError for duplicate key
        with pytest.raises(ConfigError, match="both flat and nested"):
            normalize_zone_format(mixed, source="test.yaml")

    def test_flat_format_still_works(self):
        """Verify that flat (legacy) format is still normalized correctly."""
        flat = {
            "azure_waf_custom_rules": [
                {
                    "ref": "BlockBadIPs",
                    "priority": 1,
                    "action": "Block",
                }
            ],
            "azure_waf_rate_rules": [
                {
                    "ref": "RateLimit",
                    "priority": 100,
                    "action": "Block",
                }
            ],
        }

        # Normalize (should be no-op for flat format)
        result = normalize_zone_format(flat)

        # Flat keys should remain
        assert "azure_waf_custom_rules" in result
        assert "azure_waf_rate_rules" in result
        assert result["azure_waf_custom_rules"] == flat["azure_waf_custom_rules"]
        assert result["azure_waf_rate_rules"] == flat["azure_waf_rate_rules"]
