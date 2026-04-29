"""End-to-end tests for the 'octorules lint' CLI command with the Azure provider."""

from pathlib import Path

import pytest
from octorules.cli import build_parser, cmd_lint, main
from octorules.config import Config

# Importing the provider module triggers register_azure_linter() at
# module load time, which is what cmd_lint depends on.  cmd_lint itself
# does NOT call _discover_provider_modules(), so the plugin must be
# registered before the first test runs.
import octorules_azure  # noqa: F401


@pytest.fixture
def lint_config(tmp_path):
    """Minimal config + rules files exercising Azure-specific lint paths.

    The Azure linter operates on the *canonical* (camelCase) form — the
    snake_case fields shown in the README are normalised by the
    plan/sync pipeline before reaching the linter.  Tests feed canonical
    YAML directly.
    """
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    # Clean rules — public IPs only, no AZ319/AZ322 hits expected.
    (rules_dir / "clean-policy.yaml").write_text(
        "azure_waf_custom_rules:\n"
        "  - ref: BlockPublicIPs\n"
        "    priority: 1\n"
        "    action: Block\n"
        "    enabledState: Enabled\n"
        "    ruleType: MatchRule\n"
        "    matchConditions:\n"
        "      - matchVariable: RemoteAddr\n"
        "        operator: IPMatch\n"
        "        matchValue:\n"
        "          - 1.2.3.0/24\n"
        "          - 8.8.8.0/24\n"
    )

    # Rules that trigger multiple AZ violations.
    (rules_dir / "bad-policy.yaml").write_text(
        "azure_waf_custom_rules:\n"
        # AZ319: reserved IP.
        "  - ref: BlockPrivate\n"
        "    priority: 1\n"
        "    action: Block\n"
        "    enabledState: Enabled\n"
        "    ruleType: MatchRule\n"
        "    matchConditions:\n"
        "      - matchVariable: RemoteAddr\n"
        "        operator: IPMatch\n"
        "        matchValue:\n"
        "          - 10.0.0.0/8\n"
        # AZ322: catch-all (must not also fire AZ319 after v0.1.8).
        "  - ref: CatchAll\n"
        "    priority: 2\n"
        "    action: Block\n"
        "    enabledState: Enabled\n"
        "    ruleType: MatchRule\n"
        "    matchConditions:\n"
        "      - matchVariable: RemoteAddr\n"
        "        operator: IPMatch\n"
        "        matchValue:\n"
        "          - 0.0.0.0/0\n"
    )

    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "providers:\n"
        "  azure:\n"
        "    subscription_id: test-sub-id\n"
        "    resource_group: rg-test\n"
        "    waf_type: front_door\n"
        "  rules:\n"
        "    directory: ./rules\n"
        "zones:\n"
        "  clean-policy:\n"
        "    sources:\n"
        "      - rules\n"
        "  bad-policy:\n"
        "    sources:\n"
        "      - rules\n"
    )
    return Config.from_file(config_file)


class TestBuildParser:
    def test_lint_subcommand_exists(self):
        parser = build_parser()
        args = parser.parse_args(["lint"])
        assert args.command == "lint"

    def test_lint_rule_filter_accepts_az_codes(self):
        parser = build_parser()
        args = parser.parse_args(["lint", "--rule", "AZ319", "--rule", "AZ322"])
        assert args.lint_rules == ["AZ319", "AZ322"]


class TestCmdLint:
    def test_clean_rules_exit_0(self, lint_config):
        # Documentation ranges in clean-policy.yaml trigger AZ319 (WARNING),
        # but without --exit-code, warnings don't fail the exit code.
        rc = cmd_lint(lint_config, ["clean-policy"])
        assert rc == 0

    def test_bad_rules_surface_findings(self, lint_config, capsys):
        cmd_lint(lint_config, ["bad-policy"])
        captured = capsys.readouterr()
        assert "AZ319" in captured.out
        assert "AZ322" in captured.out

    def test_az319_narrowing_catch_all_no_double_flag(self, lint_config, capsys):
        # Regression for v0.1.8: 0.0.0.0/0 must surface AZ322 but NOT AZ319.
        cmd_lint(lint_config, ["bad-policy"], lint_rules=["AZ319"])
        captured = capsys.readouterr()
        # When filtering to AZ319 alone, the only hit should be the 10.0.0.0/8
        # from the BlockPrivate rule, not the 0.0.0.0/0 from CatchAll.
        lines = [ln for ln in captured.out.splitlines() if "AZ319" in ln]
        assert all("0.0.0.0/0" not in ln for ln in lines), lines

    def test_json_format(self, lint_config, capsys):
        cmd_lint(lint_config, ["bad-policy"], lint_format="json")
        captured = capsys.readouterr()
        assert '"rule_id"' in captured.out
        assert "AZ319" in captured.out

    def test_sarif_format(self, lint_config, capsys):
        cmd_lint(lint_config, ["bad-policy"], lint_format="sarif")
        captured = capsys.readouterr()
        assert '"version": "2.1.0"' in captured.out

    def test_rule_filter_scopes_output(self, lint_config, capsys):
        cmd_lint(lint_config, ["bad-policy"], lint_rules=["AZ322"])
        captured = capsys.readouterr()
        assert "AZ322" in captured.out
        assert "AZ319" not in captured.out

    def test_output_file(self, lint_config, tmp_path):
        out_file = str(tmp_path / "lint-report.txt")
        cmd_lint(lint_config, ["bad-policy"], output_file=out_file)
        assert Path(out_file).exists()
        assert "AZ" in Path(out_file).read_text()


class TestMainLintCommand:
    def test_main_lint_exits_zero_on_info_findings(self, lint_config, tmp_path):
        config_file = tmp_path / "config.yaml"
        with pytest.raises(SystemExit) as exc_info:
            main(["--config", str(config_file), "lint", "--zone", "clean-policy"])
        assert exc_info.value.code == 0
