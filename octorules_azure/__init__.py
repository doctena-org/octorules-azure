"""Azure WAF provider for octorules."""

from octorules.phases import register_api_fields, register_non_phase_key, register_phases

from octorules_azure._phases import AZURE_PHASE_IDS, AZURE_PHASE_NAMES, AZURE_PHASES
from octorules_azure.provider import AzureWafProvider
from octorules_azure.validate import validate_managed_rules, validate_rules

register_phases(AZURE_PHASES)
register_api_fields("rule", {"ruleType", "ruleSetType"})

from octorules_azure.linter import register_azure_linter  # noqa: E402

register_azure_linter()

# Register audit IP extractor.
from octorules_azure.audit import register_azure_audit  # noqa: E402

register_azure_audit()

# Register policy settings extension.
register_non_phase_key("azure_waf_policy_settings")

from octorules_azure._policy_settings import register_policy_settings  # noqa: E402

register_policy_settings()

# Register managed exclusions extension.
register_non_phase_key("azure_waf_managed_exclusions")

from octorules_azure._managed_exclusions import register_managed_exclusions  # noqa: E402

register_managed_exclusions()

__all__ = [
    "AZURE_PHASE_IDS",
    "AZURE_PHASE_NAMES",
    "AzureWafProvider",
    "validate_managed_rules",
    "validate_rules",
]
