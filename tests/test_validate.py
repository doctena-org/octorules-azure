"""Tests for Azure WAF validation rules."""

import pytest
from octorules.testing.lint import assert_lint, assert_no_lint

from octorules_azure.validate import set_waf_type, validate_rules
from tests.conftest import make_normalised_rule


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------
class TestValidRules:
    def test_no_errors(self):
        rules = [make_normalised_rule()]
        assert validate_rules(rules) == []

    def test_multiple_valid_rules(self):
        # Distinct matchValues so AZ339 (cross-rule CIDR overlap) doesn't
        # fire — make_normalised_rule defaults to a single shared CIDR.
        rules = [
            make_normalised_rule(ref="R1", priority=1, match_value=["104.16.0.0/12"]),
            make_normalised_rule(ref="R2", priority=2, action="Allow", match_value=["8.8.8.8/32"]),
        ]
        assert validate_rules(rules) == []


# ---------------------------------------------------------------------------
# AZ001: Missing ref
# ---------------------------------------------------------------------------
class TestMissingRef:
    def test_missing_ref(self):
        rule = make_normalised_rule()
        del rule["ref"]
        results = validate_rules([rule])
        assert_lint(results, "AZ001")

    def test_empty_ref(self):
        rule = make_normalised_rule(ref="")
        results = validate_rules([rule])
        assert_lint(results, "AZ001")


# ---------------------------------------------------------------------------
# AZ010: Invalid ref format
# ---------------------------------------------------------------------------
class TestRefFormat:
    def test_starts_with_number(self):
        rule = make_normalised_rule(ref="1BadName")
        results = validate_rules([rule])
        assert_lint(results, "AZ010")

    def test_contains_hyphen(self):
        rule = make_normalised_rule(ref="Bad-Name")
        results = validate_rules([rule])
        assert_lint(results, "AZ010")

    def test_too_long(self):
        rule = make_normalised_rule(ref="A" * 129)
        results = validate_rules([rule])
        assert_lint(results, "AZ010")

    def test_valid_underscore(self):
        rule = make_normalised_rule(ref="Good_Name_123")
        assert validate_rules([rule]) == []


# ---------------------------------------------------------------------------
# AZ002/AZ100: Priority
# ---------------------------------------------------------------------------
class TestPriority:
    def test_missing_priority(self):
        rule = make_normalised_rule()
        del rule["priority"]
        results = validate_rules([rule])
        assert_lint(results, "AZ002")

    def test_negative_priority(self):
        rule = make_normalised_rule(priority=-1)
        results = validate_rules([rule])
        assert_lint(results, "AZ100")

    def test_zero_priority(self):
        rule = make_normalised_rule(priority=0)
        results = validate_rules([rule])
        assert_lint(results, "AZ100")

    def test_bool_priority(self):
        rule = make_normalised_rule(priority=True)
        results = validate_rules([rule])
        assert_lint(results, "AZ100")

    def test_string_priority(self):
        rule = make_normalised_rule()
        rule["priority"] = "five"
        results = validate_rules([rule])
        assert_lint(results, "AZ100")


# ---------------------------------------------------------------------------
# AZ101: Duplicate priority
# ---------------------------------------------------------------------------
class TestDuplicatePriority:
    def test_duplicate(self):
        rules = [
            make_normalised_rule(ref="R1", priority=1),
            make_normalised_rule(ref="R2", priority=1),
        ]
        results = validate_rules(rules)
        assert_lint(results, "AZ101")


# ---------------------------------------------------------------------------
# AZ102: Priority gaps
# ---------------------------------------------------------------------------
class TestPriorityGaps:
    def test_gap(self):
        rules = [
            make_normalised_rule(ref="R1", priority=1),
            make_normalised_rule(ref="R2", priority=5),
        ]
        results = validate_rules(rules)
        assert_lint(results, "AZ102")

    def test_contiguous(self):
        rules = [
            make_normalised_rule(ref="R1", priority=1),
            make_normalised_rule(ref="R2", priority=2),
        ]
        results = validate_rules(rules)
        assert_no_lint(results, "AZ102")


# ---------------------------------------------------------------------------
# AZ003/AZ200: Action
# ---------------------------------------------------------------------------
class TestAction:
    def test_missing_action(self):
        rule = make_normalised_rule()
        del rule["action"]
        results = validate_rules([rule])
        assert_lint(results, "AZ003")

    def test_invalid_action(self):
        rule = make_normalised_rule(action="Deny")
        results = validate_rules([rule])
        assert_lint(results, "AZ200")

    def test_valid_actions(self):
        for action in ("Allow", "Block", "Log", "Redirect", "AnomalyScoring", "JSChallenge"):
            rule = make_normalised_rule(action=action)
            errors = [r for r in validate_rules([rule]) if r.rule_id.startswith("AZ2")]
            assert errors == [], f"Unexpected error for action {action!r}: {errors}"


# ---------------------------------------------------------------------------
# AZ004/AZ300: matchConditions
# ---------------------------------------------------------------------------
class TestMatchConditions:
    def test_missing(self):
        rule = make_normalised_rule()
        del rule["matchConditions"]
        results = validate_rules([rule])
        assert_lint(results, "AZ004")

    def test_not_a_list(self):
        rule = make_normalised_rule()
        rule["matchConditions"] = "not-a-list"
        results = validate_rules([rule])
        assert_lint(results, "AZ300")

    def test_empty_list(self):
        rule = make_normalised_rule()
        rule["matchConditions"] = []
        results = validate_rules([rule])
        assert_lint(results, "AZ300")

    def test_exceeds_max(self):
        rule = make_normalised_rule()
        rule["matchConditions"] = [
            {
                "matchVariable": "RemoteAddr",
                "selector": None,
                "operator": "IPMatch",
                "negateCondition": False,
                "matchValue": ["10.0.0.0/8"],
                "transforms": [],
            }
        ] * 11
        results = validate_rules([rule])
        assert_lint(results, "AZ301")


# ---------------------------------------------------------------------------
# AZ310-AZ320: Individual condition checks
# ---------------------------------------------------------------------------
class TestConditionDetails:
    def test_invalid_match_variable(self):
        rule = make_normalised_rule(match_variable="BadVar")
        results = validate_rules([rule])
        assert_lint(results, "AZ310")

    def test_invalid_operator(self):
        rule = make_normalised_rule(operator="NotAnOp")
        results = validate_rules([rule])
        assert_lint(results, "AZ311")

    def test_missing_match_value_for_non_any(self):
        rule = make_normalised_rule(operator="Contains", match_value=[])
        results = validate_rules([rule])
        assert_lint(results, "AZ312")

    def test_ip_match_exceeds_limit(self):
        rule = make_normalised_rule(match_value=["10.0.0.1"] * 601)
        results = validate_rules([rule])
        assert_lint(results, "AZ313")

    def test_string_match_exceeds_limit(self):
        rule = make_normalised_rule(
            operator="Contains",
            match_variable="QueryString",
            match_value=["a"] * 11,
        )
        results = validate_rules([rule])
        assert_lint(results, "AZ313")

    def test_invalid_transform(self):
        rule = make_normalised_rule()
        rule["matchConditions"][0]["transforms"] = ["BadTransform"]
        results = validate_rules([rule])
        assert_lint(results, "AZ314")

    def test_selector_required_for_request_header(self):
        rule = make_normalised_rule(
            match_variable="RequestHeader",
            operator="Contains",
            match_value=["bot"],
        )
        rule["matchConditions"][0]["selector"] = None
        results = validate_rules([rule])
        assert_lint(results, "AZ315")

    def test_empty_selector_warning(self):
        rule = make_normalised_rule(
            match_variable="RequestHeader",
            operator="Contains",
            match_value=["bot"],
        )
        rule["matchConditions"][0]["selector"] = ""
        results = validate_rules([rule])
        assert_lint(results, "AZ316")

    def test_invalid_regex(self):
        rule = make_normalised_rule(operator="RegEx", match_value=["[invalid"])
        results = validate_rules([rule])
        assert_lint(results, "AZ317")

    def test_valid_regex(self):
        rule = make_normalised_rule(operator="RegEx", match_value=["^/admin.*"])
        results = validate_rules([rule])
        assert_no_lint(results, "AZ317")

    def test_invalid_cidr(self):
        rule = make_normalised_rule(match_value=["not-a-cidr"])
        results = validate_rules([rule])
        assert_lint(results, "AZ318")

    def test_valid_cidr(self):
        rule = make_normalised_rule(match_value=["104.16.0.0/12", "1.1.1.1"])
        assert validate_rules([rule]) == []

    def test_cidr_host_bits_set(self):
        rule = make_normalised_rule(match_value=["10.0.0.1/24"])
        results = validate_rules([rule])
        assert_lint(results, "AZ337")
        assert "10.0.0.0/24" in results[0].message

    def test_cidr_host_bits_clean(self):
        rule = make_normalised_rule(match_value=["10.0.0.0/24"])
        assert_no_lint(validate_rules([rule]), "AZ337")

    def test_cidr_host_bits_ipv6(self):
        rule = make_normalised_rule(match_value=["2001:db8::1/32"])
        results = validate_rules([rule])
        assert_lint(results, "AZ337")

    def test_unknown_country_code(self):
        rule = make_normalised_rule(
            operator="GeoMatch",
            match_variable="RemoteAddr",
            match_value=["us", "123"],  # lowercase and numeric are invalid format
        )
        results = validate_rules([rule])
        assert_lint(results, "AZ320")
        assert sum(1 for r in results if r.rule_id == "AZ320") == 2


# ---------------------------------------------------------------------------
# AZ400-AZ403: Rate limit
# ---------------------------------------------------------------------------
class TestRateLimit:
    def _rate_rule(self, **overrides):
        base = make_normalised_rule(
            ref="Rate1",
            rule_type="RateLimitRule",
            rateLimitDurationInMinutes=1,
            rateLimitThreshold=100,
            groupBy=[{"variableName": "SocketAddr"}],
        )
        base.update(overrides)
        return base

    def test_valid_rate_rule(self):
        assert validate_rules([self._rate_rule()]) == []

    def test_missing_duration(self):
        rule = self._rate_rule()
        del rule["rateLimitDurationInMinutes"]
        results = validate_rules([rule])
        assert_lint(results, "AZ400")

    def test_invalid_duration(self):
        rule = self._rate_rule(rateLimitDurationInMinutes=3)
        results = validate_rules([rule])
        assert_lint(results, "AZ400")

    def test_missing_threshold(self):
        rule = self._rate_rule()
        del rule["rateLimitThreshold"]
        results = validate_rules([rule])
        assert_lint(results, "AZ401")

    def test_threshold_too_low(self):
        rule = self._rate_rule(rateLimitThreshold=5)
        results = validate_rules([rule])
        assert_lint(results, "AZ403")

    def test_threshold_too_high(self):
        rule = self._rate_rule(rateLimitThreshold=2_000_000)
        results = validate_rules([rule])
        assert_lint(results, "AZ401")

    def test_invalid_group_by(self):
        rule = self._rate_rule(groupBy=[{"variableName": "BadVar"}])
        results = validate_rules([rule])
        assert_lint(results, "AZ402")


# ---------------------------------------------------------------------------
# AZ022: Duplicate ref
# ---------------------------------------------------------------------------
class TestDuplicateRef:
    def test_duplicate(self):
        rules = [
            make_normalised_rule(ref="Same", priority=1),
            make_normalised_rule(ref="Same", priority=2),
        ]
        results = validate_rules(rules)
        assert_lint(results, "AZ022")


# ---------------------------------------------------------------------------
# AZ020: Unknown fields
# ---------------------------------------------------------------------------
class TestUnknownFields:
    def test_unknown_field(self):
        rule = make_normalised_rule()
        rule["unknownField"] = "value"
        results = validate_rules([rule])
        assert_lint(results, "AZ020")


# ---------------------------------------------------------------------------
# AZ500: Regex rule limit
# Note: AZ500 (regex limit) and AZ501 (rule count limit) are tested in
# test_linter/test_plugin.py because they are cross-phase plugin checks.
# because it's a cross-phase check done by the plugin, not validate_rules.


# ---------------------------------------------------------------------------
# AZ600/AZ601: Best practice
# ---------------------------------------------------------------------------
class TestBestPractice:
    def test_disabled_rule(self):
        rule = make_normalised_rule(enabled_state="Disabled")
        results = validate_rules([rule])
        assert_lint(results, "AZ600")

    def test_log_action(self):
        rule = make_normalised_rule(action="Log")
        results = validate_rules([rule])
        assert_lint(results, "AZ601")

    def test_enabled_rule_no_info(self):
        rule = make_normalised_rule(enabled_state="Enabled")
        results = validate_rules([rule])
        assert_no_lint(results, "AZ600")


# ---------------------------------------------------------------------------
# AZ330: Redundant/conflicting transforms
# ---------------------------------------------------------------------------
class TestConflictingTransforms:
    def test_lowercase_uppercase_conflict(self):
        rule = make_normalised_rule(
            operator="Contains", match_variable="QueryString", match_value=["foo"]
        )
        rule["matchConditions"][0]["transforms"] = ["Lowercase", "Uppercase"]
        results = validate_rules([rule])
        assert_lint(results, "AZ330")

    def test_duplicate_transform(self):
        rule = make_normalised_rule(
            operator="Contains", match_variable="QueryString", match_value=["foo"]
        )
        rule["matchConditions"][0]["transforms"] = ["Lowercase", "Trim", "Lowercase"]
        results = validate_rules([rule])
        assert_lint(results, "AZ330")

    def test_no_conflict(self):
        rule = make_normalised_rule(
            operator="Contains", match_variable="QueryString", match_value=["foo"]
        )
        rule["matchConditions"][0]["transforms"] = ["Lowercase", "Trim"]
        results = validate_rules([rule])
        assert_no_lint(results, "AZ330")

    def test_single_transform_no_conflict(self):
        rule = make_normalised_rule(
            operator="Contains", match_variable="QueryString", match_value=["foo"]
        )
        rule["matchConditions"][0]["transforms"] = ["Lowercase"]
        results = validate_rules([rule])
        assert_no_lint(results, "AZ330")


# ---------------------------------------------------------------------------
# AZ331: matchValue type validation
# ---------------------------------------------------------------------------
class TestMatchValueTypes:
    def test_non_string_value(self):
        rule = make_normalised_rule(match_value=[123])
        results = validate_rules([rule])
        assert_lint(results, "AZ331")

    def test_bool_value(self):
        rule = make_normalised_rule(match_value=[True])
        results = validate_rules([rule])
        assert_lint(results, "AZ331")

    def test_all_strings_ok(self):
        rule = make_normalised_rule(match_value=["10.0.0.0/8", "192.168.1.0/24"])
        results = validate_rules([rule])
        assert_no_lint(results, "AZ331")

    def test_mixed_types(self):
        rule = make_normalised_rule(match_value=["valid", 42])
        results = validate_rules([rule])
        assert_lint(results, "AZ331")


# ---------------------------------------------------------------------------
# AZ332: Regex pattern length
# ---------------------------------------------------------------------------
class TestRegexLength:
    def test_long_pattern(self):
        rule = make_normalised_rule(operator="RegEx", match_value=["a" * 257])
        results = validate_rules([rule])
        assert_lint(results, "AZ332")

    def test_normal_pattern(self):
        rule = make_normalised_rule(operator="RegEx", match_value=["^/admin.*"])
        results = validate_rules([rule])
        assert_no_lint(results, "AZ332")

    def test_at_limit(self):
        rule = make_normalised_rule(operator="RegEx", match_value=["a" * 256])
        results = validate_rules([rule])
        assert_no_lint(results, "AZ332")


# ---------------------------------------------------------------------------
# AZ340/AZ341: Catch-all and dead rules
# ---------------------------------------------------------------------------
class TestCatchAllAndDeadRules:
    def _any_rule(self, ref, priority, action="Block"):
        return make_normalised_rule(
            ref=ref,
            priority=priority,
            action=action,
            match_variable="RequestUri",
            operator="Any",
            match_value=[],
        )

    def test_catch_all_detected(self):
        rules = [self._any_rule("CatchAll", 1)]
        results = validate_rules(rules)
        assert_lint(results, "AZ340")

    def test_catch_all_with_log_not_terminal(self):
        """Log action is not terminal -- should NOT trigger AZ340."""
        rules = [self._any_rule("LogAll", 1, action="Log")]
        results = validate_rules(rules)
        assert_no_lint(results, "AZ340")

    def test_dead_rule_after_catch_all(self):
        rules = [
            self._any_rule("CatchAll", 1, action="Block"),
            make_normalised_rule(ref="Unreachable", priority=2),
        ]
        results = validate_rules(rules)
        assert_lint(results, "AZ340")
        assert_lint(results, "AZ341")

    def test_no_dead_rules_when_no_catch_all(self):
        rules = [
            make_normalised_rule(ref="R1", priority=1),
            make_normalised_rule(ref="R2", priority=2),
        ]
        results = validate_rules(rules)
        assert_no_lint(results, "AZ340")
        assert_no_lint(results, "AZ341")

    def test_non_any_conditions_not_catch_all(self):
        """A rule with IPMatch is NOT a catch-all."""
        rules = [make_normalised_rule(ref="IPBlock", priority=1)]
        results = validate_rules(rules)
        assert_no_lint(results, "AZ340")

    def test_multiple_dead_rules(self):
        rules = [
            self._any_rule("CatchAll", 1),
            make_normalised_rule(ref="Dead1", priority=2),
            make_normalised_rule(ref="Dead2", priority=3),
        ]
        results = validate_rules(rules)
        dead = [r for r in results if r.rule_id == "AZ341"]
        assert len(dead) == 2

    def test_catch_all_at_end_no_dead_rules(self):
        rules = [
            make_normalised_rule(ref="First", priority=1),
            self._any_rule("CatchAll", 100),
        ]
        results = validate_rules(rules)
        assert_lint(results, "AZ340")
        assert_no_lint(results, "AZ341")


# ---------------------------------------------------------------------------
# AZ410: Rate rule without meaningful condition
# ---------------------------------------------------------------------------
class TestRateWithoutCondition:
    def test_rate_all_any(self):
        rule = make_normalised_rule(
            ref="RateAll",
            priority=1,
            action="Block",
            match_variable="RequestUri",
            operator="Any",
            match_value=[],
            rule_type="RateLimitRule",
            rateLimitDurationInMinutes=1,
            rateLimitThreshold=100,
            groupBy=[{"variableName": "SocketAddr"}],
        )
        results = validate_rules([rule])
        assert_lint(results, "AZ410")

    def test_rate_with_ip_match_no_warning(self):
        rule = make_normalised_rule(
            ref="RateIP",
            priority=1,
            action="Block",
            rule_type="RateLimitRule",
            rateLimitDurationInMinutes=1,
            rateLimitThreshold=100,
            groupBy=[{"variableName": "SocketAddr"}],
        )
        results = validate_rules([rule])
        assert_no_lint(results, "AZ410")

    def test_match_rule_with_any_no_warning(self):
        """AZ410 only applies to RateLimitRule, not MatchRule."""
        rule = make_normalised_rule(
            ref="AllowAll",
            priority=1,
            action="Allow",
            match_variable="RequestUri",
            operator="Any",
            match_value=[],
        )
        results = validate_rules([rule])
        assert_no_lint(results, "AZ410")


# ---------------------------------------------------------------------------
# Parametrized enum validation
# ---------------------------------------------------------------------------
class TestParametrizedEnums:
    @pytest.mark.parametrize(
        "variable",
        [
            "RemoteAddr",
            "RequestMethod",
            "QueryString",
            "PostArgs",
            "RequestUri",
            "RequestHeader",
            "RequestBody",
            "Cookies",
            "SocketAddr",
        ],
    )
    def test_all_valid_match_variables(self, variable):
        selector = "X-Test" if variable in ("RequestHeader", "Cookies", "PostArgs") else None
        rule = make_normalised_rule(match_variable=variable)
        rule["matchConditions"][0]["selector"] = selector
        errors = [r for r in validate_rules([rule]) if r.rule_id == "AZ310"]
        assert errors == [], f"Unexpected AZ310 for {variable}"

    @pytest.mark.parametrize(
        "operator",
        [
            "Any",
            "IPMatch",
            "GeoMatch",
            "Equal",
            "Contains",
            "LessThan",
            "GreaterThan",
            "LessThanOrEqual",
            "GreaterThanOrEqual",
            "BeginsWith",
            "EndsWith",
            "RegEx",
            "ServiceTagMatch",
        ],
    )
    def test_all_valid_operators(self, operator):
        if operator == "IPMatch":
            mv = ["10.0.0.0/8"]
        elif operator == "GeoMatch":
            mv = ["US"]
        else:
            mv = ["test"]
        if operator == "Any":
            mv = []
        rule = make_normalised_rule(operator=operator, match_value=mv)
        errors = [r for r in validate_rules([rule]) if r.rule_id == "AZ311"]
        assert errors == [], f"Unexpected AZ311 for {operator}"

    @pytest.mark.parametrize(
        "transform",
        [
            "Lowercase",
            "Uppercase",
            "Trim",
            "UrlDecode",
            "UrlEncode",
            "RemoveNulls",
            "HtmlEntityDecode",
        ],
    )
    def test_all_valid_transforms(self, transform):
        rule = make_normalised_rule(
            operator="Contains", match_variable="QueryString", match_value=["foo"]
        )
        rule["matchConditions"][0]["transforms"] = [transform]
        errors = [r for r in validate_rules([rule]) if r.rule_id == "AZ314"]
        assert errors == [], f"Unexpected AZ314 for {transform}"

    @pytest.mark.parametrize(
        "action",
        ["Allow", "Block", "Log", "Redirect", "AnomalyScoring", "JSChallenge"],
    )
    def test_all_valid_actions(self, action):
        rule = make_normalised_rule(action=action)
        errors = [r for r in validate_rules([rule]) if r.rule_id == "AZ200"]
        assert errors == [], f"Unexpected AZ200 for {action}"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------
class TestEdgeCases:
    def test_non_dict_in_rules_list(self):
        """Non-dict entries in rules list produce AZ023."""
        results = validate_rules(["not-a-dict", 42, None])
        az023 = [r for r in results if r.rule_id == "AZ023"]
        assert len(az023) == 3

    def test_non_dict_in_match_conditions(self):
        """Non-dict entries in matchConditions should produce AZ300."""
        rule = make_normalised_rule()
        rule["matchConditions"] = ["not-a-dict"]
        results = validate_rules([rule])
        assert_lint(results, "AZ300")

    def test_empty_rules_list(self):
        assert validate_rules([]) == []

    def test_rule_with_only_ref(self):
        """Minimal rule — should flag missing fields."""
        results = validate_rules([{"ref": "Bare"}])
        assert_lint(results, "AZ002")  # missing priority
        assert_lint(results, "AZ003")  # missing action
        assert_lint(results, "AZ004")  # missing matchConditions

    def test_matchvalue_none(self):
        """matchValue=None for non-Any operator should trigger AZ312."""
        rule = make_normalised_rule(operator="Contains", match_variable="QueryString")
        rule["matchConditions"][0]["matchValue"] = None
        results = validate_rules([rule])
        assert_lint(results, "AZ312")

    def test_priority_as_float(self):
        """Float priority should trigger AZ100."""
        rule = make_normalised_rule()
        rule["priority"] = 1.5
        results = validate_rules([rule])
        assert_lint(results, "AZ100")


# ---------------------------------------------------------------------------
# AZ005: Invalid enabledState
# ---------------------------------------------------------------------------
class TestEnabledState:
    def test_invalid_value(self):
        rule = make_normalised_rule(enabled_state="Active")
        results = validate_rules([rule])
        assert_lint(results, "AZ005")

    def test_valid_enabled(self):
        rule = make_normalised_rule(enabled_state="Enabled")
        results = validate_rules([rule])
        assert_no_lint(results, "AZ005")

    def test_valid_disabled(self):
        rule = make_normalised_rule(enabled_state="Disabled")
        results = validate_rules([rule])
        assert_no_lint(results, "AZ005")
        assert_lint(results, "AZ600")  # info

    def test_missing_enabled_state_ok(self):
        rule = make_normalised_rule()
        del rule["enabledState"]
        results = validate_rules([rule])
        assert_no_lint(results, "AZ005")


# ---------------------------------------------------------------------------
# AZ006: Invalid ruleType
# ---------------------------------------------------------------------------
class TestRuleType:
    def test_invalid_value(self):
        rule = make_normalised_rule(rule_type="CustomRule")
        results = validate_rules([rule])
        assert_lint(results, "AZ006")

    def test_valid_match_rule(self):
        rule = make_normalised_rule(rule_type="MatchRule")
        results = validate_rules([rule])
        assert_no_lint(results, "AZ006")

    def test_valid_rate_limit_rule(self):
        rule = make_normalised_rule(
            rule_type="RateLimitRule",
            rateLimitDurationInMinutes=1,
            rateLimitThreshold=100,
            groupBy=[],
        )
        results = validate_rules([rule])
        assert_no_lint(results, "AZ006")


# ---------------------------------------------------------------------------
# AZ021: negateCondition must be bool
# ---------------------------------------------------------------------------
class TestNegateCondition:
    def test_string_negate(self):
        rule = make_normalised_rule()
        rule["matchConditions"][0]["negateCondition"] = "true"
        results = validate_rules([rule])
        assert_lint(results, "AZ021")

    def test_int_negate(self):
        rule = make_normalised_rule()
        rule["matchConditions"][0]["negateCondition"] = 1
        results = validate_rules([rule])
        assert_lint(results, "AZ021")

    def test_bool_negate_ok(self):
        rule = make_normalised_rule()
        rule["matchConditions"][0]["negateCondition"] = True
        results = validate_rules([rule])
        assert_no_lint(results, "AZ021")


# ---------------------------------------------------------------------------
# AZ319: Private IP ranges
# ---------------------------------------------------------------------------
class TestPrivateIPRanges:
    @pytest.mark.parametrize(
        "cidr",
        [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.1.0/24",
            "127.0.0.1",
            "169.254.0.0/16",
            "100.64.0.0/10",
            "::1",
            "fc00::1",
            "fe80::1",
        ],
    )
    def test_private_ranges_flagged(self, cidr):
        rule = make_normalised_rule(match_value=[cidr])
        results = validate_rules([rule])
        assert_lint(results, "AZ319")

    @pytest.mark.parametrize("cidr", ["8.8.8.8", "1.1.1.0/24", "104.16.0.0/12"])
    def test_public_ranges_not_flagged(self, cidr):
        rule = make_normalised_rule(match_value=[cidr])
        results = validate_rules([rule])
        assert_no_lint(results, "AZ319")

    def test_documentation_rfc5737_flagged(self):
        """RFC 5737 documentation address (192.0.2.1) should now be flagged."""
        rule = make_normalised_rule(match_value=["192.0.2.1"])
        results = validate_rules([rule])
        assert_lint(results, "AZ319")
        az319 = [r for r in results if r.rule_id == "AZ319"]
        assert "documentation" in az319[0].message

    def test_documentation_rfc3849_ipv6_flagged(self):
        """IPv6 documentation prefix (2001:db8::1) should now be flagged."""
        rule = make_normalised_rule(match_value=["2001:db8::1"])
        results = validate_rules([rule])
        assert_lint(results, "AZ319")
        az319 = [r for r in results if r.rule_id == "AZ319"]
        assert "documentation" in az319[0].message

    def test_benchmark_testing_flagged(self):
        """RFC 2544 benchmark testing range should be flagged."""
        rule = make_normalised_rule(match_value=["198.18.0.1"])
        results = validate_rules([rule])
        assert_lint(results, "AZ319")

    def test_multicast_flagged(self):
        """Multicast range (224.0.0.0/4) should be flagged."""
        rule = make_normalised_rule(match_value=["224.0.0.1"])
        results = validate_rules([rule])
        assert_lint(results, "AZ319")

    # --- Regression for v0.1.8: strict containment narrowing. -------------
    # Prior to v0.1.8, AZ319 used a bidirectional overlap check, which
    # double-fired on catch-all (0.0.0.0/0) alongside AZ322 and produced
    # false positives for public supernets that happened to engulf a
    # reserved range.  Narrowed to strict containment to match the other
    # four providers (CF/AWS/Google/Bunny).
    def test_catch_all_does_not_double_flag_az319(self):
        """0.0.0.0/0 is AZ322's job — AZ319 must not also fire."""
        rule = make_normalised_rule(match_value=["0.0.0.0/0"])
        results = validate_rules([rule])
        az319_hits = [r for r in results if r.rule_id == "AZ319"]
        assert az319_hits == []

    def test_ipv6_catch_all_does_not_double_flag_az319(self):
        rule = make_normalised_rule(match_value=["::/0"])
        results = validate_rules([rule])
        az319_hits = [r for r in results if r.rule_id == "AZ319"]
        assert az319_hits == []

    def test_public_supernet_engulfing_reserved_not_flagged(self):
        # 8.0.0.0/4 contains 10.0.0.0/8 but is overwhelmingly public space.
        # Strict containment: not a subset of any reserved range → no AZ319.
        rule = make_normalised_rule(match_value=["8.0.0.0/4"])
        results = validate_rules([rule])
        assert_no_lint(results, "AZ319")


# ---------------------------------------------------------------------------
# AZ321: Selector on non-selector variable
# ---------------------------------------------------------------------------
class TestSelectorOnNonSelectorVar:
    def test_selector_on_remote_addr(self):
        rule = make_normalised_rule(match_variable="RemoteAddr")
        rule["matchConditions"][0]["selector"] = "something"
        results = validate_rules([rule])
        assert_lint(results, "AZ321")

    def test_selector_on_request_header_ok(self):
        rule = make_normalised_rule(
            match_variable="RequestHeader",
            operator="Contains",
            match_value=["bot"],
        )
        rule["matchConditions"][0]["selector"] = "User-Agent"
        results = validate_rules([rule])
        assert_no_lint(results, "AZ321")

    def test_no_selector_on_remote_addr_ok(self):
        rule = make_normalised_rule()
        rule["matchConditions"][0]["selector"] = None
        results = validate_rules([rule])
        assert_no_lint(results, "AZ321")


# ---------------------------------------------------------------------------
# AZ322: Catch-all CIDR
# ---------------------------------------------------------------------------
class TestCatchAllCIDR:
    def test_ipv4_catch_all(self):
        rule = make_normalised_rule(match_value=["0.0.0.0/0"])
        results = validate_rules([rule])
        assert_lint(results, "AZ322")

    def test_ipv6_catch_all(self):
        rule = make_normalised_rule(match_value=["::/0"])
        results = validate_rules([rule])
        assert_lint(results, "AZ322")

    def test_normal_cidr_ok(self):
        rule = make_normalised_rule(match_value=["104.16.0.0/12"])
        results = validate_rules([rule])
        assert_no_lint(results, "AZ322")


# ---------------------------------------------------------------------------
# AZ323: GeoMatch with very many countries
# ---------------------------------------------------------------------------
class TestGeoMatchManyCountries:
    def test_200_countries(self):
        codes = [f"{chr(65 + i // 26)}{chr(65 + i % 26)}" for i in range(200)]
        rule = make_normalised_rule(
            operator="GeoMatch", match_variable="RemoteAddr", match_value=codes
        )
        results = validate_rules([rule])
        assert_lint(results, "AZ323")

    def test_10_countries_ok(self):
        rule = make_normalised_rule(
            operator="GeoMatch",
            match_variable="RemoteAddr",
            match_value=["US", "CA", "GB", "DE", "FR", "JP", "AU", "NZ", "IE", "NL"],
        )
        results = validate_rules([rule])
        assert_no_lint(results, "AZ323")


# ---------------------------------------------------------------------------
# AZ324: Negated Any always false
# ---------------------------------------------------------------------------
class TestNegatedAny:
    def test_negated_any_always_false(self):
        rule = make_normalised_rule(match_variable="RequestUri", operator="Any", match_value=[])
        rule["matchConditions"][0]["negateCondition"] = True
        results = validate_rules([rule])
        assert_lint(results, "AZ324")

    def test_non_negated_any_ok(self):
        rule = make_normalised_rule(match_variable="RequestUri", operator="Any", match_value=[])
        rule["matchConditions"][0]["negateCondition"] = False
        results = validate_rules([rule])
        assert_no_lint(results, "AZ324")


# ---------------------------------------------------------------------------
# AZ333: Transforms on non-string operators
# ---------------------------------------------------------------------------
class TestTransformsOnNonStringOps:
    @pytest.mark.parametrize("op", ["IPMatch", "GeoMatch", "Any", "ServiceTagMatch"])
    def test_transforms_no_effect(self, op):
        mv = (
            ["10.0.0.0/8"]
            if op == "IPMatch"
            else ["US"]
            if op == "GeoMatch"
            else ["AzureFrontDoor.Backend"]
            if op == "ServiceTagMatch"
            else []
        )
        rule = make_normalised_rule(operator=op, match_variable="RemoteAddr", match_value=mv)
        rule["matchConditions"][0]["transforms"] = ["Lowercase"]
        results = validate_rules([rule])
        assert_lint(results, "AZ333")

    @pytest.mark.parametrize("op", ["Contains", "Equal", "BeginsWith", "RegEx"])
    def test_transforms_ok_on_string_ops(self, op):
        rule = make_normalised_rule(operator=op, match_variable="QueryString", match_value=["test"])
        rule["matchConditions"][0]["transforms"] = ["Lowercase"]
        results = validate_rules([rule])
        assert_no_lint(results, "AZ333")


# ---------------------------------------------------------------------------
# AZ334: Duplicate matchValue entries
# ---------------------------------------------------------------------------
class TestDuplicateMatchValue:
    def test_duplicate_ip(self):
        rule = make_normalised_rule(match_value=["10.0.0.1", "10.0.0.1"])
        results = validate_rules([rule])
        assert_lint(results, "AZ334")

    def test_duplicate_string_case_insensitive(self):
        rule = make_normalised_rule(
            operator="Contains", match_variable="QueryString", match_value=["Test", "test"]
        )
        results = validate_rules([rule])
        assert_lint(results, "AZ334")

    def test_unique_values_ok(self):
        rule = make_normalised_rule(match_value=["10.0.0.1", "10.0.0.2"])
        results = validate_rules([rule])
        assert_no_lint(results, "AZ334")


# ---------------------------------------------------------------------------
# AZ602: All rules disabled
# ---------------------------------------------------------------------------
class TestAllDisabled:
    def test_all_disabled(self):
        rules = [
            make_normalised_rule(ref="R1", priority=1, enabled_state="Disabled"),
            make_normalised_rule(ref="R2", priority=2, enabled_state="Disabled"),
        ]
        results = validate_rules(rules)
        assert_lint(results, "AZ602")

    def test_mixed_states_ok(self):
        rules = [
            make_normalised_rule(ref="R1", priority=1, enabled_state="Disabled"),
            make_normalised_rule(ref="R2", priority=2, enabled_state="Enabled"),
        ]
        results = validate_rules(rules)
        assert_no_lint(results, "AZ602")

    def test_all_enabled_ok(self):
        rules = [make_normalised_rule(ref="R1", priority=1)]
        results = validate_rules(rules)
        assert_no_lint(results, "AZ602")


# ---------------------------------------------------------------------------
# AZ603: Allow catch-all bypasses managed rules
# ---------------------------------------------------------------------------
class TestAllowBypassesManaged:
    def test_allow_catch_all(self):
        rule = make_normalised_rule(
            ref="AllowAll",
            priority=1,
            action="Allow",
            match_variable="RequestUri",
            operator="Any",
            match_value=[],
        )
        results = validate_rules([rule])
        assert_lint(results, "AZ603")

    def test_block_catch_all_no_warning(self):
        rule = make_normalised_rule(
            ref="BlockAll",
            priority=1,
            action="Block",
            match_variable="RequestUri",
            operator="Any",
            match_value=[],
        )
        results = validate_rules([rule])
        assert_no_lint(results, "AZ603")

    def test_allow_with_condition_ok(self):
        rule = make_normalised_rule(ref="AllowIP", priority=1, action="Allow")
        results = validate_rules([rule])
        assert_no_lint(results, "AZ603")

    @pytest.mark.parametrize("action", ["Redirect", "JSChallenge", "Log"])
    def test_non_allow_catch_all_no_warning(self, action):
        rule = make_normalised_rule(
            ref="CatchAll",
            priority=1,
            action=action,
            match_variable="RequestUri",
            operator="Any",
            match_value=[],
        )
        results = validate_rules([rule])
        assert_no_lint(results, "AZ603")


# ---------------------------------------------------------------------------
# AZ325: Any operator with non-empty matchValue
# ---------------------------------------------------------------------------
class TestAnyWithMatchValue:
    def test_any_with_values_warns(self):
        rule = make_normalised_rule(
            match_variable="RequestUri", operator="Any", match_value=["test"]
        )
        results = validate_rules([rule])
        assert_lint(results, "AZ325")

    def test_any_with_empty_list_ok(self):
        rule = make_normalised_rule(match_variable="RequestUri", operator="Any", match_value=[])
        results = validate_rules([rule])
        assert_no_lint(results, "AZ325")

    def test_non_any_with_values_ok(self):
        rule = make_normalised_rule(operator="IPMatch", match_value=["104.16.0.0/12"])
        results = validate_rules([rule])
        assert_no_lint(results, "AZ325")


# ---------------------------------------------------------------------------
# AZ335: Empty string in matchValue
# ---------------------------------------------------------------------------
class TestEmptyStringMatchValue:
    def test_empty_string_in_contains(self):
        rule = make_normalised_rule(
            operator="Contains", match_variable="QueryString", match_value=["", "test"]
        )
        results = validate_rules([rule])
        assert_lint(results, "AZ335")

    def test_empty_string_in_ip_match_not_flagged(self):
        """AZ335 only fires for string operators, not IPMatch."""
        rule = make_normalised_rule(operator="IPMatch", match_value=[""])
        results = validate_rules([rule])
        assert_no_lint(results, "AZ335")

    def test_non_empty_strings_ok(self):
        rule = make_normalised_rule(
            operator="Contains", match_variable="QueryString", match_value=["test"]
        )
        results = validate_rules([rule])
        assert_no_lint(results, "AZ335")


# ---------------------------------------------------------------------------
# AZ336: Duplicate matchVariable+operator in same rule
# ---------------------------------------------------------------------------
class TestDuplicateVariableOperator:
    def test_two_ip_match_on_remote_addr(self):
        rule = make_normalised_rule()
        rule["matchConditions"] = [
            {
                "matchVariable": "RemoteAddr",
                "selector": None,
                "operator": "IPMatch",
                "negateCondition": False,
                "matchValue": ["104.16.0.0/12"],
                "transforms": [],
            },
            {
                "matchVariable": "RemoteAddr",
                "selector": None,
                "operator": "IPMatch",
                "negateCondition": False,
                "matchValue": ["1.1.1.0/24"],
                "transforms": [],
            },
        ]
        results = validate_rules([rule])
        assert_lint(results, "AZ336")

    def test_same_variable_different_operators_ok(self):
        rule = make_normalised_rule()
        rule["matchConditions"] = [
            {
                "matchVariable": "RemoteAddr",
                "selector": None,
                "operator": "IPMatch",
                "negateCondition": False,
                "matchValue": ["104.16.0.0/12"],
                "transforms": [],
            },
            {
                "matchVariable": "RemoteAddr",
                "selector": None,
                "operator": "GeoMatch",
                "negateCondition": False,
                "matchValue": ["US"],
                "transforms": [],
            },
        ]
        results = validate_rules([rule])
        assert_no_lint(results, "AZ336")

    def test_different_variables_same_operator_ok(self):
        rule = make_normalised_rule()
        rule["matchConditions"] = [
            {
                "matchVariable": "QueryString",
                "selector": None,
                "operator": "Contains",
                "negateCondition": False,
                "matchValue": ["test"],
                "transforms": [],
            },
            {
                "matchVariable": "RequestUri",
                "selector": None,
                "operator": "Contains",
                "negateCondition": False,
                "matchValue": ["admin"],
                "transforms": [],
            },
        ]
        results = validate_rules([rule])
        assert_no_lint(results, "AZ336")


# ---------------------------------------------------------------------------
# AZ411: Rate limit fields on MatchRule
# ---------------------------------------------------------------------------
class TestRateFieldsOnMatchRule:
    def test_duration_on_match_rule(self):
        rule = make_normalised_rule(rateLimitDurationInMinutes=1)
        results = validate_rules([rule])
        assert_lint(results, "AZ411")

    def test_threshold_on_match_rule(self):
        rule = make_normalised_rule(rateLimitThreshold=100)
        results = validate_rules([rule])
        assert_lint(results, "AZ411")

    def test_group_by_on_match_rule(self):
        rule = make_normalised_rule(groupBy=[{"variableName": "SocketAddr"}])
        results = validate_rules([rule])
        assert_lint(results, "AZ411")

    def test_rate_fields_on_rate_rule_ok(self):
        rule = make_normalised_rule(
            rule_type="RateLimitRule",
            rateLimitDurationInMinutes=1,
            rateLimitThreshold=100,
            groupBy=[{"variableName": "SocketAddr"}],
        )
        results = validate_rules([rule])
        assert_no_lint(results, "AZ411")

    def test_empty_group_by_no_warning(self):
        """Empty groupBy list is not confusing."""
        rule = make_normalised_rule(groupBy=[])
        results = validate_rules([rule])
        assert_no_lint(results, "AZ411")


# ---------------------------------------------------------------------------
# Catch-all detection: IPMatch with 0.0.0.0/0 (enhanced _is_catch_all_rule)
# ---------------------------------------------------------------------------
class TestCatchAllIPMatch:
    def test_ip_catch_all_detected(self):
        rule = make_normalised_rule(
            ref="CatchAllIP", priority=1, action="Block", match_value=["0.0.0.0/0"]
        )
        results = validate_rules([rule])
        assert_lint(results, "AZ340")

    def test_ipv6_catch_all_detected(self):
        rule = make_normalised_rule(
            ref="CatchAllIPv6", priority=1, action="Block", match_value=["::/0"]
        )
        results = validate_rules([rule])
        assert_lint(results, "AZ340")

    def test_ip_catch_all_makes_next_rule_dead(self):
        rules = [
            make_normalised_rule(
                ref="CatchAll", priority=1, action="Block", match_value=["0.0.0.0/0"]
            ),
            make_normalised_rule(ref="Dead", priority=2),
        ]
        results = validate_rules(rules)
        assert_lint(results, "AZ341")

    def test_normal_ip_range_not_catch_all(self):
        rule = make_normalised_rule(
            ref="NormalIP", priority=1, action="Block", match_value=["104.16.0.0/12"]
        )
        results = validate_rules([rule])
        assert_no_lint(results, "AZ340")


# ---------------------------------------------------------------------------
# Parametrized negative tests (invalid values)
# ---------------------------------------------------------------------------
class TestParametrizedInvalid:
    @pytest.mark.parametrize(
        "variable",
        ["remoteaddr", "REMOTEADDR", "RemoteAddress", "IP", "Header", "Body", ""],
    )
    def test_invalid_match_variables(self, variable):
        rule = make_normalised_rule(match_variable=variable)
        results = validate_rules([rule])
        assert_lint(results, "AZ310")

    @pytest.mark.parametrize(
        "operator",
        ["ipmatch", "IPMATCH", "Matches", "Regex", "In", "NotEqual", "Like", ""],
    )
    def test_invalid_operators(self, operator):
        rule = make_normalised_rule(operator=operator, match_value=["test"])
        results = validate_rules([rule])
        assert_lint(results, "AZ311")

    @pytest.mark.parametrize(
        "transform",
        ["lowercase", "LOWERCASE", "Base64Decode", "HexEncode", "Normalize", ""],
    )
    def test_invalid_transforms(self, transform):
        rule = make_normalised_rule(
            operator="Contains", match_variable="QueryString", match_value=["test"]
        )
        rule["matchConditions"][0]["transforms"] = [transform]
        results = validate_rules([rule])
        assert_lint(results, "AZ314")

    @pytest.mark.parametrize(
        "action",
        ["block", "BLOCK", "Deny", "Count", "Challenge", "Captcha", "Drop"],
    )
    def test_invalid_actions(self, action):
        rule = make_normalised_rule(action=action)
        results = validate_rules([rule])
        assert_lint(results, "AZ200")


# ---------------------------------------------------------------------------
# WAF-type-aware validation (AZ201, AZ326, AZ327, AZ328)
# ---------------------------------------------------------------------------
class TestWafTypeAware:
    """Tests for rules that depend on waf_type (set via set_waf_type())."""

    def teardown_method(self):
        set_waf_type("")  # Reset after each test

    # AZ201: FD-only actions on App Gateway
    @pytest.mark.parametrize("action", ["Redirect", "AnomalyScoring"])
    def test_fd_only_action_on_app_gateway(self, action):
        set_waf_type("app_gateway")
        rule = make_normalised_rule(action=action)
        results = validate_rules([rule])
        assert_lint(results, "AZ201")

    @pytest.mark.parametrize("action", ["Redirect", "AnomalyScoring"])
    def test_fd_only_action_on_front_door_ok(self, action):
        set_waf_type("front_door")
        rule = make_normalised_rule(action=action)
        results = validate_rules([rule])
        assert_no_lint(results, "AZ201")

    def test_jschallenge_ok_on_both(self):
        """JSChallenge is valid on both Front Door and App Gateway."""
        for wt in ("front_door", "app_gateway"):
            set_waf_type(wt)
            rule = make_normalised_rule(action="JSChallenge")
            errors = [r for r in validate_rules([rule]) if r.rule_id == "AZ201"]
            assert errors == [], f"JSChallenge on {wt} should not trigger AZ201"

    @pytest.mark.parametrize("action", ["Allow", "Block", "Log"])
    def test_common_actions_ok_on_both(self, action):
        for wt in ("front_door", "app_gateway"):
            set_waf_type(wt)
            rule = make_normalised_rule(action=action)
            errors = [r for r in validate_rules([rule]) if r.rule_id == "AZ201"]
            assert errors == [], f"{action} on {wt} should not trigger AZ201"

    def test_no_waf_type_no_warning(self):
        """When waf_type is not set, no AZ201/326/327/328 should fire."""
        set_waf_type("")
        rule = make_normalised_rule(action="Redirect")
        results = validate_rules([rule])
        assert_no_lint(results, "AZ201")

    # AZ326: FD-only operator on App Gateway
    def test_service_tag_match_on_app_gateway(self):
        set_waf_type("app_gateway")
        rule = make_normalised_rule(operator="ServiceTagMatch", match_value=["AzureFrontDoor"])
        results = validate_rules([rule])
        assert_lint(results, "AZ326")

    def test_service_tag_match_on_front_door_ok(self):
        set_waf_type("front_door")
        rule = make_normalised_rule(operator="ServiceTagMatch", match_value=["AzureFrontDoor"])
        results = validate_rules([rule])
        assert_no_lint(results, "AZ326")

    # AZ327: FD-only variable on App Gateway
    def test_socket_addr_on_app_gateway(self):
        set_waf_type("app_gateway")
        rule = make_normalised_rule(match_variable="SocketAddr")
        results = validate_rules([rule])
        assert_lint(results, "AZ327")

    def test_socket_addr_on_front_door_ok(self):
        set_waf_type("front_door")
        rule = make_normalised_rule(match_variable="SocketAddr")
        results = validate_rules([rule])
        assert_no_lint(results, "AZ327")

    # AZ328: AG-only transform on Front Door
    def test_html_entity_decode_on_front_door(self):
        set_waf_type("front_door")
        rule = make_normalised_rule(
            operator="Contains", match_variable="QueryString", match_value=["test"]
        )
        rule["matchConditions"][0]["transforms"] = ["HtmlEntityDecode"]
        results = validate_rules([rule])
        assert_lint(results, "AZ328")

    def test_html_entity_decode_on_app_gateway_ok(self):
        set_waf_type("app_gateway")
        rule = make_normalised_rule(
            operator="Contains", match_variable="QueryString", match_value=["test"]
        )
        rule["matchConditions"][0]["transforms"] = ["HtmlEntityDecode"]
        results = validate_rules([rule])
        assert_no_lint(results, "AZ328")

    # AZ103: Front Door priority range
    def test_priority_exceeds_fd_max(self):
        set_waf_type("front_door")
        rule = make_normalised_rule(priority=101)
        results = validate_rules([rule])
        assert_lint(results, "AZ103")
        assert "101" in next(r for r in results if r.rule_id == "AZ103").message

    def test_priority_at_fd_max(self):
        set_waf_type("front_door")
        rule = make_normalised_rule(priority=100)
        results = validate_rules([rule])
        assert_no_lint(results, "AZ103")

    def test_priority_1_fd_ok(self):
        set_waf_type("front_door")
        rule = make_normalised_rule(priority=1)
        results = validate_rules([rule])
        assert_no_lint(results, "AZ103")

    def test_priority_high_on_app_gateway_ok(self):
        """App Gateway allows priorities well above 100."""
        set_waf_type("app_gateway")
        rule = make_normalised_rule(priority=500)
        results = validate_rules([rule])
        assert_no_lint(results, "AZ103")

    def test_priority_high_no_waf_type_ok(self):
        """When waf_type is not set, no AZ103 should fire."""
        set_waf_type("")
        rule = make_normalised_rule(priority=200)
        results = validate_rules([rule])
        assert_no_lint(results, "AZ103")


# ---------------------------------------------------------------------------
# AZ338: Redundant CIDRs in matchValue
# ---------------------------------------------------------------------------
class TestRedundantCIDRs:
    def test_ipv4_subnet_of(self):
        """10.1.0.0/16 is a subnet of 10.0.0.0/8 -- redundant."""
        rule = make_normalised_rule(match_value=["10.0.0.0/8", "10.1.0.0/16"])
        results = validate_rules([rule])
        assert_lint(results, "AZ338")
        msg = next(r for r in results if r.rule_id == "AZ338").message
        assert "10.1.0.0/16" in msg
        assert "10.0.0.0/8" in msg

    def test_ipv4_supernet_first(self):
        """Order doesn't matter -- smaller listed first, larger second."""
        rule = make_normalised_rule(match_value=["10.1.0.0/16", "10.0.0.0/8"])
        results = validate_rules([rule])
        assert_lint(results, "AZ338")

    def test_ipv4_no_overlap(self):
        """Disjoint CIDRs should not trigger."""
        rule = make_normalised_rule(match_value=["10.0.0.0/8", "192.168.0.0/16"])
        results = validate_rules([rule])
        assert_no_lint(results, "AZ338")

    def test_ipv6_subnet_of(self):
        """2001:db8:1::/48 is a subnet of 2001:db8::/32."""
        rule = make_normalised_rule(match_value=["2001:db8::/32", "2001:db8:1::/48"])
        results = validate_rules([rule])
        assert_lint(results, "AZ338")

    def test_ipv6_no_overlap(self):
        rule = make_normalised_rule(match_value=["2001:db8::/32", "2001:db9::/32"])
        results = validate_rules([rule])
        assert_no_lint(results, "AZ338")

    def test_no_cross_version_comparison(self):
        """IPv4 and IPv6 should not be compared to each other."""
        rule = make_normalised_rule(match_value=["10.0.0.0/8", "2001:db8::/32"])
        results = validate_rules([rule])
        assert_no_lint(results, "AZ338")

    def test_single_cidr_ok(self):
        """Single entry cannot be redundant."""
        rule = make_normalised_rule(match_value=["10.0.0.0/8"])
        results = validate_rules([rule])
        assert_no_lint(results, "AZ338")

    def test_invalid_cidr_skipped(self):
        """Invalid CIDRs should not crash the check."""
        rule = make_normalised_rule(match_value=["10.0.0.0/8", "not-a-cidr", "10.1.0.0/16"])
        results = validate_rules([rule])
        # AZ338 still fires for the valid pair
        assert_lint(results, "AZ338")
        # AZ318 fires for the invalid one
        assert_lint(results, "AZ318")

    def test_host_ip_subnet_of_cidr(self):
        """A bare IP (treated as /32) inside a CIDR is redundant."""
        rule = make_normalised_rule(match_value=["10.0.0.0/8", "10.1.2.3"])
        results = validate_rules([rule])
        assert_lint(results, "AZ338")

    def test_identical_cidrs_not_flagged(self):
        """Exact duplicates are handled by AZ334, not AZ338."""
        rule = make_normalised_rule(match_value=["10.0.0.0/8", "10.0.0.0/8"])
        results = validate_rules([rule])
        assert_no_lint(results, "AZ338")
        assert_lint(results, "AZ334")

    def test_one_warning_per_condition(self):
        """Even with multiple overlaps, only one AZ338 per condition."""
        rule = make_normalised_rule(match_value=["10.0.0.0/8", "10.1.0.0/16", "10.2.0.0/16"])
        results = validate_rules([rule])
        az338 = [r for r in results if r.rule_id == "AZ338"]
        assert len(az338) == 1

    def test_host_bits_set_still_detects_overlap(self):
        """CIDRs with host bits set are normalised (strict=False) before comparison."""
        rule = make_normalised_rule(match_value=["10.0.0.0/8", "10.1.0.1/16"])
        results = validate_rules([rule])
        assert_lint(results, "AZ338")
        # AZ337 also fires for the host-bits issue
        assert_lint(results, "AZ337")


# ---------------------------------------------------------------------------
# AZ339: Cross-rule CIDR overlap (sweep-line O(n log n))
# ---------------------------------------------------------------------------
class TestAZ339CrossRuleOverlap:
    """Detect overlapping CIDRs across rules in the same phase.

    Mirrors CF478, WA164, GA305, BN307. Azure-specific because the data
    model is inline IP arrays per rule (no shared list/IPSet concept).
    """

    @staticmethod
    def _ip_match_rule(ref: str, priority: int, cidrs: list[str], action: str = "Block") -> dict:
        """Build a normalised rule with one IPMatch condition on RemoteAddr."""
        return make_normalised_rule(
            ref=ref,
            priority=priority,
            action=action,
            operator="IPMatch",
            match_value=cidrs,
            match_variable="RemoteAddr",
        )

    def test_ipv4_containment_across_rules(self):
        """Narrow CIDR contained in broader CIDR from another rule fires AZ339."""
        rules = [
            self._ip_match_rule("BlockAll10", 10, ["10.0.0.0/8"]),
            self._ip_match_rule("BlockBranch", 20, ["10.1.0.0/16"]),
        ]
        assert_lint(validate_rules(rules), "AZ339")

    def test_ipv4_disjoint_no_az339(self):
        """Disjoint CIDRs across rules don't fire."""
        rules = [
            self._ip_match_rule("R1", 10, ["10.0.0.0/8"]),
            self._ip_match_rule("R2", 20, ["192.168.0.0/16"]),
        ]
        assert_no_lint(validate_rules(rules), "AZ339")

    def test_ipv4_adjacent_no_az339(self):
        """Adjacent /9s (10.0.0.0/9 + 10.128.0.0/9) are not overlapping."""
        rules = [
            self._ip_match_rule("R1", 10, ["10.0.0.0/9"]),
            self._ip_match_rule("R2", 20, ["10.128.0.0/9"]),
        ]
        assert_no_lint(validate_rules(rules), "AZ339")

    def test_ipv6_containment_across_rules(self):
        """IPv6 containment is detected the same as IPv4."""
        rules = [
            self._ip_match_rule("R1", 10, ["2001:db8::/32"]),
            self._ip_match_rule("R2", 20, ["2001:db8:1234::/48"]),
        ]
        assert_lint(validate_rules(rules), "AZ339")

    def test_mixed_family_no_cross_overlap(self):
        """IPv4 from one rule and IPv6 from another don't cross-overlap."""
        rules = [
            self._ip_match_rule("R1", 10, ["10.0.0.0/8"]),
            self._ip_match_rule("R2", 20, ["2001:db8::/32"]),
        ]
        assert_no_lint(validate_rules(rules), "AZ339")

    def test_different_match_variables_no_overlap(self):
        """Same CIDR on different matchVariables (RemoteAddr vs SocketAddr)
        is not a cross-rule overlap — they're distinct enforcement points."""
        rules = [
            self._ip_match_rule("R1", 10, ["10.0.0.0/8"]),
            make_normalised_rule(
                ref="R2",
                priority=20,
                operator="IPMatch",
                match_value=["10.1.0.0/16"],
                match_variable="SocketAddr",
            ),
        ]
        assert_no_lint(validate_rules(rules), "AZ339")

    def test_catch_all_skipped_in_az339(self):
        """0.0.0.0/0 in one rule + narrow CIDR in another doesn't fire AZ339.
        AZ322 already flags the catch-all separately."""
        rules = [
            self._ip_match_rule("R1", 10, ["0.0.0.0/0"]),
            self._ip_match_rule("R2", 20, ["10.0.0.0/8"]),
        ]
        results = validate_rules(rules)
        assert_no_lint(results, "AZ339")
        # AZ322 still surfaces the catch-all.
        assert_lint(results, "AZ322")

    def test_ipv6_catch_all_skipped(self):
        """Same skip applies to ::/0 vs narrower IPv6."""
        rules = [
            self._ip_match_rule("R1", 10, ["::/0"]),
            self._ip_match_rule("R2", 20, ["2001:db8::/32"]),
        ]
        results = validate_rules(rules)
        assert_no_lint(results, "AZ339")

    def test_within_rule_overlap_uses_az338_not_az339(self):
        """Overlap inside a single rule's matchValue is AZ338's domain;
        AZ339 only flags cross-rule overlaps to avoid double-reporting."""
        rules = [
            self._ip_match_rule("R1", 10, ["10.0.0.0/8", "10.1.0.0/16"]),
        ]
        results = validate_rules(rules)
        assert_lint(results, "AZ338")
        assert_no_lint(results, "AZ339")

    def test_message_names_both_rules(self):
        """The finding identifies both contributing rules so users can act."""
        rules = [
            self._ip_match_rule("BroadBlock", 10, ["10.0.0.0/8"]),
            self._ip_match_rule("NarrowBlock", 20, ["10.5.0.0/16"]),
        ]
        results = validate_rules(rules)
        az339 = [r for r in results if r.rule_id == "AZ339"]
        assert len(az339) == 1
        assert "BroadBlock" in az339[0].message
        assert "NarrowBlock" in az339[0].message
        assert az339[0].ref == "NarrowBlock"  # narrower rule owns the finding

    def test_three_nested_rules(self):
        """A chain of three rules with progressively narrower CIDRs produces
        N-1 findings (each contained CIDR reported against its immediate parent)."""
        rules = [
            self._ip_match_rule("R8", 10, ["10.0.0.0/8"]),
            self._ip_match_rule("R16", 20, ["10.1.0.0/16"]),
            self._ip_match_rule("R24", 30, ["10.1.0.0/24"]),
        ]
        results = validate_rules(rules)
        az339 = [r for r in results if r.rule_id == "AZ339"]
        # Two findings: /16 contained in /8, /24 contained in /16.
        assert len(az339) == 2

    def test_duplicate_cidr_across_rules_is_flagged(self):
        """Two rules with the exact same CIDR — flagged as duplicate cross-rule."""
        rules = [
            self._ip_match_rule("R1", 10, ["10.0.0.0/8"]),
            self._ip_match_rule("R2", 20, ["10.0.0.0/8"]),
        ]
        results = validate_rules(rules)
        az339 = [r for r in results if r.rule_id == "AZ339"]
        assert len(az339) == 1
        assert "Duplicate CIDR" in az339[0].message

    def test_single_rule_no_az339(self):
        """One rule alone can't produce a cross-rule overlap."""
        rules = [self._ip_match_rule("R1", 10, ["10.0.0.0/8", "10.1.0.0/16"])]
        assert_no_lint(validate_rules(rules), "AZ339")

    def test_non_ipmatch_operators_skipped(self):
        """Equal/Contains/RegEx etc. don't carry CIDRs — AZ339 ignores them."""
        rule_a = self._ip_match_rule("R1", 10, ["10.0.0.0/8"])
        rule_b = make_normalised_rule(
            ref="R2",
            priority=20,
            operator="Equal",
            match_value=["10.1.0.0/16"],  # not a CIDR for Equal, but harmless
            match_variable="RequestUri",
        )
        rules = [rule_a, rule_b]
        assert_no_lint(validate_rules(rules), "AZ339")

    def test_sweep_line_fast_on_large_input(self):
        """Lock in O(n log n): 500 disjoint /32s across 500 rules lints quickly."""
        import time

        rules = [
            self._ip_match_rule(f"R{i}", i + 1, [f"203.0.{i // 256}.{i % 256}/32"])
            for i in range(500)
        ]
        start = time.monotonic()
        results = validate_rules(rules)
        elapsed = time.monotonic() - start
        assert elapsed < 1.0, f"AZ339 sweep-line too slow: {elapsed:.2f}s for 500 rules"
        assert [r for r in results if r.rule_id == "AZ339"] == []


# ---------------------------------------------------------------------------
# AZ023: Rule entry is not a dict
# ---------------------------------------------------------------------------
class TestRuleEntryNotDict:
    def test_string_entry(self):
        """Non-dict rule entry produces AZ023 error."""
        results = validate_rules(["not a dict"])
        assert_lint(results, "AZ023")

    def test_int_entry(self):
        results = validate_rules([42])
        assert_lint(results, "AZ023")

    def test_list_entry(self):
        results = validate_rules([[1, 2, 3]])
        assert_lint(results, "AZ023")

    def test_mixed_valid_and_invalid(self):
        """Valid dict rules still validated alongside non-dict entries."""
        rule = make_normalised_rule()
        results = validate_rules(["bad", rule])
        assert_lint(results, "AZ023")
        # The valid rule should not produce AZ023
        az023_count = sum(1 for r in results if r.rule_id == "AZ023")
        assert az023_count == 1
