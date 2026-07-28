"""Tests for Azure WAF namespace registration and nested zone format."""

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
            "waf_custom_rules": "azure.waf_custom_rules",
            "waf_rate_rules": "azure.waf_rate_rules",
            "waf_managed_rules": "azure.waf_managed_rules",
            "waf_policy_settings": "azure.waf_policy_settings",
            "waf_managed_exclusions": "azure.waf_managed_exclusions",
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
        assert "azure.waf_custom_rules" in flat
        assert "azure.waf_rate_rules" in flat
        assert "azure.waf_policy_settings" in flat
        assert "azure.waf_managed_exclusions" in flat

        # Verify nested key is removed
        assert "azure" not in flat

        # Verify content is unchanged
        assert flat["azure.waf_custom_rules"] == nested["azure"]["waf_custom_rules"]
        assert flat["azure.waf_rate_rules"] == nested["azure"]["waf_rate_rules"]
        assert flat["azure.waf_policy_settings"] == nested["azure"]["waf_policy_settings"]
        assert flat["azure.waf_managed_exclusions"] == nested["azure"]["waf_managed_exclusions"]
