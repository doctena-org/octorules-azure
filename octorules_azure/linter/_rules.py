"""Azure WAF lint rule definitions -- all Azure-specific RuleMeta instances."""

from octorules.linter.engine import Severity
from octorules.linter.rules.registry import RuleMeta

# --- AZ0xx: Structure checks ---
AZ001 = RuleMeta("AZ001", "structure", "Rule missing 'ref'", Severity.ERROR)
AZ002 = RuleMeta("AZ002", "structure", "Rule missing 'priority'", Severity.ERROR)
AZ003 = RuleMeta("AZ003", "structure", "Rule missing 'action'", Severity.ERROR)
AZ004 = RuleMeta("AZ004", "structure", "Rule missing 'matchConditions'", Severity.ERROR)
AZ005 = RuleMeta("AZ005", "structure", "Invalid enabledState value", Severity.ERROR)
AZ006 = RuleMeta("AZ006", "structure", "Invalid ruleType value", Severity.ERROR)
AZ010 = RuleMeta("AZ010", "structure", "Invalid ref format", Severity.ERROR)
AZ020 = RuleMeta("AZ020", "structure", "Unknown top-level rule field", Severity.WARNING)
AZ021 = RuleMeta("AZ021", "structure", "negateCondition must be a boolean", Severity.ERROR)
AZ022 = RuleMeta("AZ022", "structure", "Duplicate ref within phase", Severity.ERROR)
AZ023 = RuleMeta("AZ023", "structure", "Rule entry is not a dict", Severity.ERROR)
AZ024 = RuleMeta("AZ024", "structure", "Phase value is not a list", Severity.ERROR)

# --- AZ1xx: Priority checks ---
AZ100 = RuleMeta("AZ100", "priority", "Priority must be a positive integer", Severity.ERROR)
AZ101 = RuleMeta("AZ101", "priority", "Duplicate priority across rules", Severity.ERROR)
AZ102 = RuleMeta("AZ102", "priority", "Non-contiguous rule priorities", Severity.INFO)
AZ103 = RuleMeta(
    "AZ103", "priority", "Priority exceeds Front Door maximum of 100", Severity.WARNING
)

# --- AZ2xx: Action checks ---
AZ200 = RuleMeta("AZ200", "action", "Invalid action type", Severity.ERROR)
AZ201 = RuleMeta("AZ201", "action", "Action not supported on this WAF type", Severity.ERROR)

# --- AZ3xx: Match condition checks ---
AZ300 = RuleMeta("AZ300", "match", "matchConditions must be a non-empty list", Severity.ERROR)
AZ301 = RuleMeta("AZ301", "match", "matchConditions exceeds 10 per rule", Severity.ERROR)
AZ310 = RuleMeta("AZ310", "match", "Invalid matchVariable", Severity.ERROR)
AZ311 = RuleMeta("AZ311", "match", "Invalid operator", Severity.ERROR)
AZ312 = RuleMeta("AZ312", "match", "Missing matchValue for non-Any operator", Severity.ERROR)
AZ313 = RuleMeta("AZ313", "match", "matchValue exceeds limit", Severity.ERROR)
AZ314 = RuleMeta("AZ314", "match", "Invalid transform type", Severity.ERROR)
AZ315 = RuleMeta("AZ315", "match", "Selector required for variable", Severity.ERROR)
AZ316 = RuleMeta("AZ316", "match", "Empty selector", Severity.WARNING)
AZ317 = RuleMeta("AZ317", "match", "Invalid regex pattern", Severity.ERROR)
AZ318 = RuleMeta("AZ318", "match", "Invalid CIDR in IPMatch", Severity.WARNING)
AZ319 = RuleMeta("AZ319", "match", "Private/reserved IP range in IPMatch", Severity.INFO)
AZ320 = RuleMeta("AZ320", "match", "GeoMatch with unknown country code", Severity.WARNING)
AZ321 = RuleMeta("AZ321", "match", "Selector on non-selector variable", Severity.WARNING)
AZ322 = RuleMeta("AZ322", "match", "Catch-all CIDR matches all traffic", Severity.WARNING)
AZ323 = RuleMeta("AZ323", "match", "GeoMatch with very many countries", Severity.WARNING)
AZ324 = RuleMeta("AZ324", "match", "Negated Any operator always false", Severity.WARNING)
AZ325 = RuleMeta("AZ325", "match", "matchValue ignored with Any operator", Severity.WARNING)
AZ326 = RuleMeta("AZ326", "match", "Operator not supported on this WAF type", Severity.ERROR)
AZ327 = RuleMeta("AZ327", "match", "Variable not supported on this WAF type", Severity.ERROR)
AZ328 = RuleMeta("AZ328", "match", "Transform not supported on this WAF type", Severity.ERROR)
AZ330 = RuleMeta("AZ330", "match", "Redundant or conflicting transforms", Severity.WARNING)
AZ331 = RuleMeta("AZ331", "match", "matchValue entry must be a string", Severity.ERROR)
AZ332 = RuleMeta("AZ332", "match", "Regex pattern exceeds recommended length", Severity.WARNING)
AZ333 = RuleMeta("AZ333", "match", "Transforms have no effect with this operator", Severity.WARNING)
AZ334 = RuleMeta("AZ334", "match", "Duplicate matchValue entry", Severity.WARNING)
AZ335 = RuleMeta("AZ335", "match", "matchValue contains an empty string", Severity.WARNING)
AZ336 = RuleMeta(
    "AZ336",
    "match",
    "Multiple conditions on same variable+operator (AND = intersection)",
    Severity.WARNING,
)
AZ337 = RuleMeta("AZ337", "match", "CIDR has host bits set", Severity.WARNING)
AZ338 = RuleMeta("AZ338", "match", "Redundant CIDR in matchValue", Severity.WARNING)
AZ340 = RuleMeta("AZ340", "match", "Catch-all rule matches all traffic", Severity.WARNING)
AZ341 = RuleMeta("AZ341", "match", "Rule is unreachable after catch-all", Severity.WARNING)

# --- AZ4xx: Rate-limit checks ---
AZ400 = RuleMeta("AZ400", "rate_limit", "rateLimitDurationInMinutes invalid", Severity.ERROR)
AZ401 = RuleMeta("AZ401", "rate_limit", "rateLimitThreshold invalid", Severity.ERROR)
AZ402 = RuleMeta("AZ402", "rate_limit", "Invalid groupBy variable", Severity.ERROR)
AZ403 = RuleMeta("AZ403", "rate_limit", "rateLimitThreshold below minimum", Severity.ERROR)
AZ410 = RuleMeta(
    "AZ410",
    "rate_limit",
    "RateLimitRule matches all traffic without meaningful condition",
    Severity.WARNING,
)
AZ411 = RuleMeta(
    "AZ411",
    "rate_limit",
    "Rate-limit fields on a MatchRule are ignored",
    Severity.WARNING,
)

# --- AZ5xx: Cross-rule / policy-level checks ---
AZ500 = RuleMeta("AZ500", "cross_rule", "Regex rules exceed 5 per policy", Severity.ERROR)
AZ501 = RuleMeta("AZ501", "cross_rule", "Custom rules exceed 100 per policy", Severity.WARNING)
AZ520 = RuleMeta(
    "AZ520",
    "cross_rule",
    "Duplicate match conditions across rules in phase",
    Severity.WARNING,
)
AZ521 = RuleMeta("AZ521", "cross_rule", "Duplicate priority across phases", Severity.ERROR)

# --- AZ6xx: Best-practice / operational checks ---
AZ600 = RuleMeta("AZ600", "best_practice", "Rule is disabled", Severity.INFO)
AZ601 = RuleMeta(
    "AZ601",
    "best_practice",
    "Log action does not block or allow -- traffic continues to next rule",
    Severity.INFO,
)
AZ602 = RuleMeta("AZ602", "best_practice", "All rules in phase are disabled", Severity.WARNING)
AZ603 = RuleMeta(
    "AZ603",
    "best_practice",
    "Allow catch-all rule bypasses all managed rules",
    Severity.INFO,
)

# --- AZ7xx: Managed rule set checks ---
AZ700 = RuleMeta("AZ700", "managed", "Managed rule set missing or duplicate ref", Severity.ERROR)
AZ701 = RuleMeta("AZ701", "managed", "Invalid or unknown ruleSetType", Severity.WARNING)
AZ702 = RuleMeta("AZ702", "managed", "Invalid ruleSetAction", Severity.ERROR)
AZ703 = RuleMeta("AZ703", "managed", "Invalid enabledState in rule override", Severity.ERROR)
AZ704 = RuleMeta("AZ704", "managed", "Invalid ruleGroupOverrides structure", Severity.ERROR)
AZ705 = RuleMeta(
    "AZ705", "managed", "ruleSetAction not supported on this WAF type", Severity.WARNING
)
AZ706 = RuleMeta("AZ706", "managed", "Missing or invalid ruleId in rule override", Severity.ERROR)
AZ707 = RuleMeta("AZ707", "managed", "Invalid action in rule override", Severity.ERROR)
AZ708 = RuleMeta(
    "AZ708", "managed", "FD-only override action used with Application Gateway", Severity.WARNING
)

AZ_RULE_METAS: list[RuleMeta] = [obj for obj in globals().values() if isinstance(obj, RuleMeta)]
