"""Azure WAF audit extension -- extracts IP ranges from IPMatch conditions."""

from octorules.audit import RuleIPInfo, iter_audit_rules
from octorules.extensions import register_audit_extension

from octorules_azure import AZURE_PHASE_NAMES


def _extract_ips(rules_data: dict, phase_name: str) -> list[RuleIPInfo]:
    """Extract IP ranges from Azure WAF rules in *phase_name*.

    Finds matchConditions with ``operator=IPMatch`` and collects their
    ``matchValue`` entries as IP ranges.
    """

    results: list[RuleIPInfo] = []
    for rule in iter_audit_rules(rules_data, phase_name, AZURE_PHASE_NAMES):
        # Core's audit filters disabled rules on the universal `enabled` key,
        # but Azure's canonical spelling is enabledState: "Disabled" — filter
        # it here, per the convention that a provider whose rules carry their
        # own disabled marker handles it in its extractor.
        if str(rule.get("enabledState", "Enabled")) == "Disabled":
            continue
        ref = str(rule.get("ref", ""))
        action = str(rule.get("action", ""))

        conditions = rule.get("matchConditions")
        if not isinstance(conditions, list):
            continue

        ip_ranges: list[str] = []
        for cond in conditions:
            if not isinstance(cond, dict):
                continue
            if cond.get("operator") != "IPMatch":
                continue
            values = cond.get("matchValue", [])
            if isinstance(values, list):
                ip_ranges.extend(v for v in values if isinstance(v, str))

        if ip_ranges:
            results.append(
                RuleIPInfo(
                    zone_name="",  # Stamped by caller
                    phase_name=phase_name,
                    ref=ref,
                    action=action,
                    ip_ranges=ip_ranges,
                )
            )

    return results


def register_azure_audit() -> None:
    """Register the Azure WAF audit IP extractor."""
    register_audit_extension("azure_waf", _extract_ips)
