"""Shared fixtures for octorules-azure tests."""

from unittest.mock import MagicMock

import pytest


@pytest.fixture
def mock_fd_client():
    """Create a mock Front Door management client."""
    return MagicMock()


@pytest.fixture
def mock_ag_client():
    """Create a mock Application Gateway (Network) management client."""
    return MagicMock()


def _make_fd_policy(custom_rules=None, managed_rules=None, etag='"test-etag"'):
    """Build a Front Door WAF policy dict for testing."""
    return {
        "name": "test-policy",
        "etag": etag,
        "custom_rules": {
            "rules": custom_rules or [],
        },
        "managed_rules": managed_rules or {"managed_rule_sets": []},
        "policy_settings": {
            "enabled_state": "Enabled",
            "mode": "Prevention",
        },
    }


def _make_ag_policy(custom_rules=None, managed_rules=None, etag='"test-etag"'):
    """Build an App Gateway WAF policy dict for testing."""
    return {
        "name": "test-policy",
        "etag": etag,
        "custom_rules": custom_rules or [],
        "managed_rules": managed_rules or {"managed_rule_sets": []},
        "policy_settings": {
            "state": "Enabled",
            "mode": "Prevention",
        },
    }


@pytest.fixture
def fd_custom_rule():
    """A sample Front Door custom rule (SDK dict form)."""
    return {
        "name": "BlockBadIPs",
        "priority": 1,
        "enabled_state": "Enabled",
        "rule_type": "MatchRule",
        "match_conditions": [
            {
                "match_variable": "RemoteAddr",
                "selector": None,
                "operator": "IPMatch",
                "negate_condition": False,
                "match_value": ["192.168.1.0/24", "10.0.0.0/8"],
                "transforms": [],
            }
        ],
        "action": "Block",
    }


@pytest.fixture
def fd_rate_rule():
    """A sample Front Door rate-limit rule (SDK dict form)."""
    return {
        "name": "RateLimitAll",
        "priority": 10,
        "enabled_state": "Enabled",
        "rule_type": "RateLimitRule",
        "match_conditions": [
            {
                "match_variable": "RequestUri",
                "selector": None,
                "operator": "Any",
                "negate_condition": False,
                "match_value": [],
                "transforms": [],
            }
        ],
        "action": "Block",
        "rate_limit_duration_in_minutes": 1,
        "rate_limit_threshold": 100,
        "group_by": [{"variable_name": "SocketAddr"}],
    }


@pytest.fixture
def ag_custom_rule():
    """A sample App Gateway custom rule (SDK dict form)."""
    return {
        "name": "BlockBadIPs",
        "priority": 1,
        "state": "Enabled",
        "rule_type": "MatchRule",
        "match_conditions": [
            {
                "match_variables": [{"variable_name": "RemoteAddr", "selector": None}],
                "operator": "IPMatch",
                "negation_conditon": False,
                "match_values": ["192.168.1.0/24", "10.0.0.0/8"],
                "transforms": [],
            }
        ],
        "action": "Block",
    }


@pytest.fixture
def ag_rate_rule():
    """A sample App Gateway rate-limit rule (SDK dict form)."""
    return {
        "name": "RateLimitAll",
        "priority": 10,
        "state": "Enabled",
        "rule_type": "RateLimitRule",
        "match_conditions": [
            {
                "match_variables": [{"variable_name": "RequestUri", "selector": None}],
                "operator": "Any",
                "negation_conditon": False,
                "match_values": [],
                "transforms": [],
            }
        ],
        "action": "Block",
        "rate_limit_duration": "OneMin",
        "rate_limit_threshold": 100,
        "group_by_user_session": [{"group_by_variables": [{"variable_name": "ClientAddr"}]}],
    }


def make_normalised_rule(
    ref="TestRule",
    priority=1,
    action="Block",
    match_variable="RemoteAddr",
    operator="IPMatch",
    match_value=None,
    rule_type="MatchRule",
    enabled_state="Enabled",
    **extra,
):
    """Build a normalised (canonical) rule dict for validation tests."""
    rule = {
        "ref": ref,
        "priority": priority,
        "action": action,
        "enabledState": enabled_state,
        "ruleType": rule_type,
        "matchConditions": [
            {
                "matchVariable": match_variable,
                "selector": None,
                "operator": operator,
                "negateCondition": False,
                "matchValue": match_value if match_value is not None else ["203.0.113.0/24"],
                "transforms": [],
            }
        ],
        **extra,
    }
    return rule
