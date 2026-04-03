"""Azure WAF phase definitions (shared between __init__ and provider)."""

from octorules.phases import Phase

AZURE_PHASES = [
    Phase(
        "azure_waf_custom_rules",
        "azure_waf_custom",
        None,
        zone_level=True,
        account_level=False,
    ),
    Phase(
        "azure_waf_rate_rules",
        "azure_waf_rate",
        None,
        zone_level=True,
        account_level=False,
    ),
]

AZURE_PHASE_NAMES: frozenset[str] = frozenset(p.friendly_name for p in AZURE_PHASES)
AZURE_PHASE_IDS: frozenset[str] = frozenset(p.provider_id for p in AZURE_PHASES)
