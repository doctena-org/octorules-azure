"""Tests for Azure WAF linter plugin."""

from octorules.linter.engine import LintContext

from octorules_azure.linter._plugin import azure_lint


def _ids(ctx):
    """Extract rule IDs from a LintContext."""
    return [r.rule_id for r in ctx.results]


class TestAzureLint:
    def test_runs_validation(self):
        rules_data = {
            "azure_waf_custom_rules": [
                {
                    "priority": 1,
                    "action": "Block",
                    "matchConditions": [
                        {
                            "matchVariable": "RemoteAddr",
                            "selector": None,
                            "operator": "IPMatch",
                            "negateCondition": False,
                            "matchValue": ["203.0.113.0/24"],
                            "transforms": [],
                        }
                    ],
                    "ruleType": "MatchRule",
                    "enabledState": "Enabled",
                    # Missing ref -> should produce AZ001
                }
            ]
        }
        ctx = LintContext()
        azure_lint(rules_data, ctx)
        assert "AZ001" in _ids(ctx)

    def test_non_azure_phases_ignored(self):
        rules_data = {
            "aws_waf_custom_rules": [
                {"priority": 1}  # Invalid rule but not our phase
            ]
        }
        ctx = LintContext()
        azure_lint(rules_data, ctx)
        assert ctx.results == []

    def test_phase_filter_respected(self):
        rules_data = {
            "azure_waf_custom_rules": [
                {
                    "priority": 1,
                    "action": "Block",
                    "matchConditions": [
                        {
                            "matchVariable": "RemoteAddr",
                            "selector": None,
                            "operator": "IPMatch",
                            "negateCondition": False,
                            "matchValue": ["203.0.113.0/24"],
                            "transforms": [],
                        }
                    ],
                    "ruleType": "MatchRule",
                    "enabledState": "Enabled",
                    # Missing ref -> AZ001
                }
            ]
        }
        ctx = LintContext(phase_filter=["azure_waf_rate_rules"])
        azure_lint(rules_data, ctx)
        # Custom rules phase should be skipped
        assert ctx.results == []

    def test_valid_rules_produce_no_errors(self):
        rules_data = {
            "azure_waf_custom_rules": [
                {
                    "ref": "TestRule",
                    "priority": 1,
                    "action": "Block",
                    "enabledState": "Enabled",
                    "ruleType": "MatchRule",
                    "matchConditions": [
                        {
                            "matchVariable": "RemoteAddr",
                            "selector": None,
                            "operator": "IPMatch",
                            "negateCondition": False,
                            "matchValue": ["203.0.113.0/24"],
                            "transforms": [],
                        }
                    ],
                }
            ]
        }
        ctx = LintContext()
        azure_lint(rules_data, ctx)
        assert ctx.results == []

    def test_non_list_phase_produces_az024(self):
        rules_data = {"azure_waf_custom_rules": "not a list"}
        ctx = LintContext()
        azure_lint(rules_data, ctx)
        rule_ids = _ids(ctx)
        assert "AZ024" in rule_ids
        result = next(r for r in ctx.results if r.rule_id == "AZ024")
        assert result.phase == "azure_waf_custom_rules"
        assert "not a list" in result.message

    def test_non_list_phase_dict_produces_az024(self):
        rules_data = {"azure_waf_custom_rules": {"key": "value"}}
        ctx = LintContext()
        azure_lint(rules_data, ctx)
        rule_ids = _ids(ctx)
        assert "AZ024" in rule_ids

    def test_non_list_phase_skipped_by_filter(self):
        rules_data = {"azure_waf_custom_rules": "not a list"}
        ctx = LintContext(phase_filter=["azure_waf_rate_rules"])
        azure_lint(rules_data, ctx)
        assert ctx.results == []


class TestCrossPhaseChecks:
    def test_duplicate_match_conditions(self):
        conditions = [
            {
                "matchVariable": "RemoteAddr",
                "selector": None,
                "operator": "IPMatch",
                "negateCondition": False,
                "matchValue": ["203.0.113.0/24"],
                "transforms": [],
            }
        ]
        rules_data = {
            "azure_waf_custom_rules": [
                {
                    "ref": "R1",
                    "priority": 1,
                    "action": "Block",
                    "enabledState": "Enabled",
                    "ruleType": "MatchRule",
                    "matchConditions": conditions,
                },
                {
                    "ref": "R2",
                    "priority": 2,
                    "action": "Allow",
                    "enabledState": "Enabled",
                    "ruleType": "MatchRule",
                    "matchConditions": conditions,
                },
            ]
        }
        ctx = LintContext()
        azure_lint(rules_data, ctx)
        assert "AZ520" in _ids(ctx)

    def test_duplicate_match_conditions_reordered(self):
        """AZ520 detects duplicates even when conditions are in different order."""
        cond_ip = {
            "matchVariable": "RemoteAddr",
            "selector": None,
            "operator": "IPMatch",
            "negateCondition": False,
            "matchValue": ["203.0.113.0/24"],
            "transforms": [],
        }
        cond_qs = {
            "matchVariable": "QueryString",
            "selector": None,
            "operator": "Contains",
            "negateCondition": False,
            "matchValue": ["/admin"],
            "transforms": [],
        }
        rules_data = {
            "azure_waf_custom_rules": [
                {
                    "ref": "R1",
                    "priority": 1,
                    "action": "Block",
                    "enabledState": "Enabled",
                    "ruleType": "MatchRule",
                    "matchConditions": [cond_ip, cond_qs],
                },
                {
                    "ref": "R2",
                    "priority": 2,
                    "action": "Allow",
                    "enabledState": "Enabled",
                    "ruleType": "MatchRule",
                    "matchConditions": [cond_qs, cond_ip],
                },
            ]
        }
        ctx = LintContext()
        azure_lint(rules_data, ctx)
        az520 = [r for r in ctx.results if r.rule_id == "AZ520"]
        assert len(az520) == 1
        assert "R1" in az520[0].message
        assert "R2" in az520[0].message

    def test_no_duplicate_when_genuinely_different_multi_conditions(self):
        """Two rules with different multi-condition sets should NOT trigger AZ520."""
        cond_ip = {
            "matchVariable": "RemoteAddr",
            "selector": None,
            "operator": "IPMatch",
            "negateCondition": False,
            "matchValue": ["203.0.113.0/24"],
            "transforms": [],
        }
        cond_qs = {
            "matchVariable": "QueryString",
            "selector": None,
            "operator": "Contains",
            "negateCondition": False,
            "matchValue": ["/admin"],
            "transforms": [],
        }
        cond_uri = {
            "matchVariable": "RequestUri",
            "selector": None,
            "operator": "Contains",
            "negateCondition": False,
            "matchValue": ["/login"],
            "transforms": [],
        }
        rules_data = {
            "azure_waf_custom_rules": [
                {
                    "ref": "R1",
                    "priority": 1,
                    "action": "Block",
                    "enabledState": "Enabled",
                    "ruleType": "MatchRule",
                    "matchConditions": [cond_ip, cond_qs],
                },
                {
                    "ref": "R2",
                    "priority": 2,
                    "action": "Block",
                    "enabledState": "Enabled",
                    "ruleType": "MatchRule",
                    "matchConditions": [cond_ip, cond_uri],
                },
            ]
        }
        ctx = LintContext()
        azure_lint(rules_data, ctx)
        assert "AZ520" not in _ids(ctx)

    def test_no_duplicate_when_different_conditions(self):
        rules_data = {
            "azure_waf_custom_rules": [
                {
                    "ref": "R1",
                    "priority": 1,
                    "action": "Block",
                    "enabledState": "Enabled",
                    "ruleType": "MatchRule",
                    "matchConditions": [
                        {
                            "matchVariable": "RemoteAddr",
                            "selector": None,
                            "operator": "IPMatch",
                            "negateCondition": False,
                            "matchValue": ["203.0.113.0/24"],
                            "transforms": [],
                        }
                    ],
                },
                {
                    "ref": "R2",
                    "priority": 2,
                    "action": "Block",
                    "enabledState": "Enabled",
                    "ruleType": "MatchRule",
                    "matchConditions": [
                        {
                            "matchVariable": "RequestUri",
                            "selector": None,
                            "operator": "Contains",
                            "negateCondition": False,
                            "matchValue": ["/admin"],
                            "transforms": [],
                        }
                    ],
                },
            ]
        }
        ctx = LintContext()
        azure_lint(rules_data, ctx)
        assert "AZ520" not in _ids(ctx)


class TestTotalRuleCount:
    def _make_rule(self, ref, priority):
        return {
            "ref": ref,
            "priority": priority,
            "action": "Block",
            "enabledState": "Enabled",
            "ruleType": "MatchRule",
            "matchConditions": [
                {
                    "matchVariable": "RemoteAddr",
                    "selector": None,
                    "operator": "IPMatch",
                    "negateCondition": False,
                    "matchValue": ["203.0.113.0/24"],
                    "transforms": [],
                }
            ],
        }

    def test_exceeds_limit_across_phases(self):
        """AZ501 counts across all phases, not per-phase."""
        rules_data = {
            "azure_waf_custom_rules": [self._make_rule(f"C{i}", i) for i in range(1, 61)],
            "azure_waf_rate_rules": [
                {
                    **self._make_rule(f"R{i}", 100 + i),
                    "ruleType": "RateLimitRule",
                    "rateLimitDurationInMinutes": 1,
                    "rateLimitThreshold": 100,
                    "groupBy": [],
                }
                for i in range(1, 51)
            ],
        }
        # 60 + 50 = 110 > 100
        ctx = LintContext()
        azure_lint(rules_data, ctx)
        assert "AZ501" in _ids(ctx)

    def test_under_limit(self):
        rules_data = {
            "azure_waf_custom_rules": [self._make_rule(f"C{i}", i) for i in range(1, 51)],
        }
        ctx = LintContext()
        azure_lint(rules_data, ctx)
        assert "AZ501" not in _ids(ctx)

    def test_managed_rules_excluded_from_count(self):
        """AZ501 must not count managed rule sets toward the 100-custom-rule limit."""
        rules_data = {
            "azure_waf_custom_rules": [self._make_rule(f"C{i}", i) for i in range(1, 100)],
            "azure_waf_managed_rules": [
                {
                    "ref": "Microsoft_DefaultRuleSet",
                    "ruleSetType": "Microsoft_DefaultRuleSet",
                    "ruleSetVersion": "2.1",
                    "ruleSetAction": "Block",
                },
                {
                    "ref": "Microsoft_BotManagerRuleSet",
                    "ruleSetType": "Microsoft_BotManagerRuleSet",
                    "ruleSetVersion": "1.0",
                },
            ],
        }
        # 99 custom + 2 managed = 101 entries total, but only 99 custom count
        ctx = LintContext()
        azure_lint(rules_data, ctx)
        assert "AZ501" not in _ids(ctx)


class TestCrossPhasePriorities:
    def _make_rule(self, ref, priority, rule_type="MatchRule", **extra):
        return {
            "ref": ref,
            "priority": priority,
            "action": "Block",
            "enabledState": "Enabled",
            "ruleType": rule_type,
            "matchConditions": [
                {
                    "matchVariable": "RemoteAddr",
                    "selector": None,
                    "operator": "IPMatch",
                    "negateCondition": False,
                    "matchValue": ["203.0.113.0/24"],
                    "transforms": [],
                }
            ],
            **extra,
        }

    def test_duplicate_priority_across_phases(self):
        """AZ521: Same priority in custom and rate phases."""
        rules_data = {
            "azure_waf_custom_rules": [self._make_rule("C1", 5)],
            "azure_waf_rate_rules": [
                {
                    **self._make_rule("R1", 5, rule_type="RateLimitRule"),
                    "rateLimitDurationInMinutes": 1,
                    "rateLimitThreshold": 100,
                    "groupBy": [],
                }
            ],
        }
        ctx = LintContext()
        azure_lint(rules_data, ctx)
        assert "AZ521" in _ids(ctx)

    def test_no_duplicate_different_priorities(self):
        rules_data = {
            "azure_waf_custom_rules": [self._make_rule("C1", 1)],
            "azure_waf_rate_rules": [
                {
                    **self._make_rule("R1", 2, rule_type="RateLimitRule"),
                    "rateLimitDurationInMinutes": 1,
                    "rateLimitThreshold": 100,
                    "groupBy": [],
                }
            ],
        }
        ctx = LintContext()
        azure_lint(rules_data, ctx)
        assert "AZ521" not in _ids(ctx)


class TestCrossPhaseRegexCount:
    def _make_regex_rule(self, ref, priority, rule_type="MatchRule", **extra):
        return {
            "ref": ref,
            "priority": priority,
            "action": "Block",
            "enabledState": "Enabled",
            "ruleType": rule_type,
            "matchConditions": [
                {
                    "matchVariable": "RequestUri",
                    "selector": None,
                    "operator": "RegEx",
                    "negateCondition": False,
                    "matchValue": ["^/test"],
                    "transforms": [],
                }
            ],
            **extra,
        }

    def test_regex_count_across_phases(self):
        """AZ500: 3 regex in custom + 3 regex in rate = 6 > 5 limit."""
        rules_data = {
            "azure_waf_custom_rules": [self._make_regex_rule(f"C{i}", i) for i in range(1, 4)],
            "azure_waf_rate_rules": [
                {
                    **self._make_regex_rule(f"R{i}", 10 + i, rule_type="RateLimitRule"),
                    "rateLimitDurationInMinutes": 1,
                    "rateLimitThreshold": 100,
                    "groupBy": [],
                }
                for i in range(1, 4)
            ],
        }
        ctx = LintContext()
        azure_lint(rules_data, ctx)
        az500 = [r for r in ctx.results if r.rule_id == "AZ500"]
        # Should have at least one cross-phase AZ500 from the plugin
        assert len(az500) >= 1

    def test_single_phase_exceeds_limit(self):
        """AZ500: 6 regex rules in one phase exceeds the 5-rule limit."""
        rules_data = {
            "azure_waf_custom_rules": [self._make_regex_rule(f"R{i}", i) for i in range(1, 7)],
        }
        ctx = LintContext()
        azure_lint(rules_data, ctx)
        az500 = [r for r in ctx.results if r.rule_id == "AZ500"]
        assert len(az500) == 1

    def test_at_limit_no_error(self):
        """5 regex rules is exactly at the limit — no AZ500."""
        rules_data = {
            "azure_waf_custom_rules": [self._make_regex_rule(f"R{i}", i) for i in range(1, 6)],
        }
        ctx = LintContext()
        azure_lint(rules_data, ctx)
        az500 = [r for r in ctx.results if r.rule_id == "AZ500"]
        assert len(az500) == 0


class TestRuleMetadataIntegrity:
    def test_unique_rule_ids(self):
        from octorules_azure.linter._rules import AZ_RULE_METAS

        ids = [r.rule_id for r in AZ_RULE_METAS]
        dupes = [x for x in ids if ids.count(x) > 1]
        assert len(ids) == len(set(ids)), f"Duplicate rule IDs: {dupes}"

    def test_rule_count_matches_docs(self):
        from octorules_azure.linter._rules import AZ_RULE_METAS

        assert len(AZ_RULE_METAS) == 73

    def test_all_rule_ids_start_with_az(self):
        from octorules_azure.linter._rules import AZ_RULE_METAS

        for meta in AZ_RULE_METAS:
            assert meta.rule_id.startswith("AZ"), f"{meta.rule_id} doesn't start with AZ"

    def test_plugin_rule_ids_match_meta(self):
        from octorules_azure.linter._plugin import AZ_RULE_IDS
        from octorules_azure.linter._rules import AZ_RULE_METAS

        meta_ids = frozenset(r.rule_id for r in AZ_RULE_METAS)
        assert AZ_RULE_IDS == meta_ids
