"""Tests for Azure WAF audit extension (IP extraction)."""

from octorules_azure.audit import _extract_ips


class TestExtractIPs:
    def test_extracts_ip_match_ranges(self):
        rules_data = {
            "azure_waf_custom_rules": [
                {
                    "ref": "BlockIPs",
                    "action": "Block",
                    "matchConditions": [
                        {
                            "matchVariable": "RemoteAddr",
                            "operator": "IPMatch",
                            "matchValue": ["10.0.0.0/8", "192.168.1.0/24"],
                        }
                    ],
                }
            ]
        }
        results = _extract_ips(rules_data, "azure_waf_custom_rules")
        assert len(results) == 1
        assert results[0].ref == "BlockIPs"
        assert results[0].action == "Block"
        assert results[0].ip_ranges == ["10.0.0.0/8", "192.168.1.0/24"]

    def test_multiple_conditions(self):
        rules_data = {
            "azure_waf_custom_rules": [
                {
                    "ref": "Multi",
                    "action": "Block",
                    "matchConditions": [
                        {
                            "matchVariable": "RemoteAddr",
                            "operator": "IPMatch",
                            "matchValue": ["10.0.0.0/8"],
                        },
                        {
                            "matchVariable": "SocketAddr",
                            "operator": "IPMatch",
                            "matchValue": ["172.16.0.0/12"],
                        },
                    ],
                }
            ]
        }
        results = _extract_ips(rules_data, "azure_waf_custom_rules")
        assert len(results) == 1
        assert results[0].ip_ranges == ["10.0.0.0/8", "172.16.0.0/12"]

    def test_skips_non_ip_operators(self):
        rules_data = {
            "azure_waf_custom_rules": [
                {
                    "ref": "GeoBlock",
                    "action": "Block",
                    "matchConditions": [
                        {
                            "matchVariable": "RemoteAddr",
                            "operator": "GeoMatch",
                            "matchValue": ["CN", "RU"],
                        }
                    ],
                }
            ]
        }
        results = _extract_ips(rules_data, "azure_waf_custom_rules")
        assert results == []

    def test_empty_rules(self):
        results = _extract_ips({"azure_waf_custom_rules": []}, "azure_waf_custom_rules")
        assert results == []

    def test_non_azure_phase_ignored(self):
        rules_data = {
            "aws_waf_custom_rules": [
                {
                    "ref": "Test",
                    "action": "Block",
                    "matchConditions": [
                        {
                            "matchVariable": "RemoteAddr",
                            "operator": "IPMatch",
                            "matchValue": ["10.0.0.0/8"],
                        }
                    ],
                }
            ]
        }
        results = _extract_ips(rules_data, "aws_waf_custom_rules")
        assert results == []

    def test_rate_phase(self):
        rules_data = {
            "azure_waf_rate_rules": [
                {
                    "ref": "RateIP",
                    "action": "Block",
                    "matchConditions": [
                        {
                            "matchVariable": "RemoteAddr",
                            "operator": "IPMatch",
                            "matchValue": ["1.2.3.4"],
                        }
                    ],
                }
            ]
        }
        results = _extract_ips(rules_data, "azure_waf_rate_rules")
        assert len(results) == 1
        assert results[0].ip_ranges == ["1.2.3.4"]

    def test_missing_match_conditions(self):
        rules_data = {"azure_waf_custom_rules": [{"ref": "NoConditions", "action": "Block"}]}
        results = _extract_ips(rules_data, "azure_waf_custom_rules")
        assert results == []
