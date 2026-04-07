"""Azure WAF linter -- registers all Azure-specific lint rules and plugins."""

_registered = False


def register_azure_linter() -> None:
    """Register the Azure WAF lint plugin, rule definitions, and non-phase keys.

    Safe to call multiple times -- subsequent calls are no-ops.
    """
    global _registered
    if _registered:
        return

    from octorules.linter.plugin import LintPlugin, register_linter
    from octorules.linter.rules.registry import register_rules

    from octorules_azure.linter._plugin import AZ_RULE_IDS, azure_lint
    from octorules_azure.linter._rules import AZ_RULE_METAS

    register_linter(LintPlugin(name="azure", lint_fn=azure_lint, rule_ids=AZ_RULE_IDS))
    register_rules(AZ_RULE_METAS)

    _registered = True
