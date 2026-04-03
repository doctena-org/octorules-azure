"""Azure WAF provider for octorules."""

from octorules.phases import register_api_fields, register_phases

from octorules_azure._phases import AZURE_PHASE_IDS, AZURE_PHASE_NAMES, AZURE_PHASES
from octorules_azure.provider import AzureWafProvider
from octorules_azure.validate import validate_rules

register_phases(AZURE_PHASES)
register_api_fields("rule", {"ruleType"})

from octorules_azure.linter import register_azure_linter  # noqa: E402

register_azure_linter()

# Register audit IP extractor.
from octorules_azure.audit import register_azure_audit  # noqa: E402

register_azure_audit()

__all__ = ["AZURE_PHASE_IDS", "AZURE_PHASE_NAMES", "AzureWafProvider", "validate_rules"]
