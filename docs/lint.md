# Azure WAF Lint Rules

59 rules with the `AZ` prefix. Suppress individual rules per-zone with
`# octorules:suppress AZ001` comments in your YAML files.

## Quick Reference

| Rule | Severity | Category | Description |
|------|----------|----------|-------------|
| AZ001 | ERROR | structure | Rule missing `ref` |
| AZ002 | ERROR | structure | Rule missing `priority` |
| AZ003 | ERROR | structure | Rule missing `action` |
| AZ004 | ERROR | structure | Rule missing `matchConditions` |
| AZ005 | ERROR | structure | Invalid `enabledState` value |
| AZ006 | ERROR | structure | Invalid `ruleType` value |
| AZ010 | ERROR | structure | Invalid `ref` format |
| AZ020 | WARNING | structure | Unknown top-level rule field |
| AZ021 | ERROR | structure | `negateCondition` must be boolean |
| AZ022 | ERROR | structure | Duplicate `ref` within phase |
| AZ100 | ERROR | priority | Priority must be a positive integer |
| AZ101 | ERROR | priority | Duplicate priority across rules |
| AZ102 | INFO | priority | Non-contiguous rule priorities |
| AZ200 | ERROR | action | Invalid action type |
| AZ201 | ERROR | action | Action not supported on this WAF type |
| AZ300 | ERROR | match | `matchConditions` must be non-empty list of dicts |
| AZ301 | ERROR | match | `matchConditions` exceeds 10 per rule |
| AZ310 | ERROR | match | Invalid `matchVariable` |
| AZ311 | ERROR | match | Invalid `operator` |
| AZ312 | ERROR | match | Missing `matchValue` for non-Any operator |
| AZ313 | ERROR | match | `matchValue` exceeds limit |
| AZ314 | ERROR | match | Invalid transform type |
| AZ315 | ERROR | match | Selector required for variable |
| AZ316 | WARNING | match | Empty selector |
| AZ317 | ERROR | match | Invalid regex pattern |
| AZ318 | WARNING | match | Invalid CIDR in IPMatch |
| AZ319 | INFO | match | Private/reserved IP in IPMatch |
| AZ320 | WARNING | match | Unknown GeoMatch country code |
| AZ321 | WARNING | match | Selector on non-selector variable |
| AZ322 | WARNING | match | Catch-all CIDR |
| AZ323 | WARNING | match | GeoMatch with 200+ countries |
| AZ324 | WARNING | match | Negated Any always false |
| AZ325 | WARNING | match | matchValue ignored with Any |
| AZ326 | ERROR | match | Operator not supported on WAF type |
| AZ327 | ERROR | match | Variable not supported on WAF type |
| AZ328 | ERROR | match | Transform not supported on WAF type |
| AZ330 | WARNING | match | Redundant/conflicting transforms |
| AZ331 | ERROR | match | matchValue entry not a string |
| AZ332 | WARNING | match | Regex pattern too long |
| AZ333 | WARNING | match | Transforms have no effect |
| AZ334 | WARNING | match | Duplicate matchValue entry |
| AZ335 | WARNING | match | Empty string in matchValue |
| AZ336 | WARNING | match | Duplicate variable+operator in rule |
| AZ340 | WARNING | match | Catch-all rule |
| AZ341 | WARNING | match | Unreachable rule after catch-all |
| AZ400 | ERROR | rate_limit | Invalid rateLimitDurationInMinutes |
| AZ401 | ERROR | rate_limit | Invalid rateLimitThreshold |
| AZ402 | ERROR | rate_limit | Invalid groupBy variable |
| AZ403 | ERROR | rate_limit | Threshold below minimum |
| AZ410 | WARNING | rate_limit | Rate rule matches all traffic |
| AZ411 | WARNING | rate_limit | Rate-limit fields on MatchRule |
| AZ500 | ERROR | cross_rule | Regex rules exceed 5 per policy |
| AZ501 | WARNING | cross_rule | Custom rules exceed 100 per policy |
| AZ520 | WARNING | cross_rule | Duplicate match conditions |
| AZ521 | ERROR | cross_rule | Duplicate priority across phases |
| AZ600 | INFO | best_practice | Rule is disabled |
| AZ601 | INFO | best_practice | Log action continues to next rule |
| AZ602 | WARNING | best_practice | All rules in phase disabled |
| AZ603 | INFO | best_practice | Allow catch-all bypasses managed rules |

---

## Structure (AZ0xx)

### AZ001: Rule missing `ref`

Every rule must have a `ref` field (the rule name in Azure).

Triggers on:

```yaml
azure_waf_custom_rules:
  - priority: 1          # <-- no ref
    action: Block
    matchConditions: [...]
```

Fix: Add a `ref` field.

```yaml
azure_waf_custom_rules:
  - ref: BlockBadIPs
    priority: 1
    action: Block
    matchConditions: [...]
```

### AZ002: Rule missing `priority`

Every rule must have a numeric `priority` field.

Triggers on:

```yaml
  - ref: BlockBadIPs
    action: Block          # <-- no priority
    matchConditions: [...]
```

Fix: Add a unique positive integer `priority`.

### AZ003: Rule missing `action`

Every rule must have an `action` field specifying what to do when matched.

### AZ004: Rule missing `matchConditions`

Every rule must have at least one match condition.

### AZ005: Invalid `enabledState` value

`enabledState` must be exactly `"Enabled"` or `"Disabled"`.

Triggers on:

```yaml
  - ref: MyRule
    enabledState: Active    # <-- invalid
```

Fix: Use `Enabled` or `Disabled`.

### AZ006: Invalid `ruleType` value

`ruleType` must be exactly `"MatchRule"` or `"RateLimitRule"`.

Triggers on:

```yaml
  - ref: MyRule
    ruleType: CustomRule    # <-- invalid
```

### AZ010: Invalid `ref` format

Rule names must start with a letter and contain only letters, digits, and
underscores. Maximum 128 characters. Azure rejects rules that don't match
this pattern.

Triggers on:

```yaml
  - ref: 1BadName       # starts with digit
  - ref: my-rule        # contains hyphen
  - ref: AAAA...129+    # too long
```

Fix: Use `^[a-zA-Z][a-zA-Z0-9_]*$` pattern. Example: `Block_Bad_IPs`.

### AZ020: Unknown top-level rule field

Warns when a rule contains a field that isn't part of the Azure WAF schema.
This usually means a typo or a field from a different provider.

Triggers on:

```yaml
  - ref: MyRule
    Statement: {...}     # <-- AWS field, not Azure
```

### AZ021: negateCondition must be boolean

The `negateCondition` field must be `true` or `false`, not a string or integer.

Triggers on:

```yaml
    matchConditions:
      - matchVariable: RemoteAddr
        operator: IPMatch
        negateCondition: "true"    # <-- string, not bool
```

Fix: Use `negateCondition: true` (no quotes).

### AZ022: Duplicate `ref` within phase

Rule names must be unique within a phase. Duplicate refs cause unpredictable
behavior during sync.

---

## Priority (AZ1xx)

### AZ100: Priority must be a positive integer

The `priority` field must be a positive integer (1 or greater). Floats,
negative numbers, zero, and booleans are rejected.

### AZ101: Duplicate priority across rules

Azure WAF requires unique priorities within each phase. Two rules with the
same priority will cause a deployment error.

### AZ102: Non-contiguous rule priorities

Info-level notice when there are gaps in priority numbering (e.g., 1, 2, 5).
Not an error, but may indicate a deleted rule that should be cleaned up.

---

## Action (AZ2xx)

### AZ200: Invalid action type

The `action` field must be one of: `Allow`, `Block`, `Log`, `Redirect`,
`AnomalyScoring`, or `JSChallenge`.

Triggers on:

```yaml
  - ref: MyRule
    action: Deny           # <-- Azure uses "Block", not "Deny"
```

Fix: Use `Block` instead of `Deny`.

Note: `Redirect` and `AnomalyScoring` are Front Door only. `JSChallenge`
requires Front Door Premium tier. See AZ201 for waf_type-aware validation.

### AZ201: Action not supported on this WAF type

Fires when a Front Door-only action (`Redirect`, `AnomalyScoring`) is used
with `waf_type: app_gateway`. These actions will be rejected by the App
Gateway API at deployment time.

Triggers on:

```yaml
# octorules.yaml: waf_type: app_gateway
  - ref: MyRule
    action: Redirect     # <-- FD only, not supported on App Gateway
```

---

## Match Conditions (AZ3xx)

### AZ300: matchConditions must be a non-empty list of dicts

The `matchConditions` field must be a list containing at least one dict.

Triggers on:

```yaml
    matchConditions: []              # empty
    matchConditions: "RemoteAddr"    # not a list
    matchConditions: ["bad"]         # entries must be dicts
```

### AZ301: matchConditions exceeds 10 per rule

Azure WAF supports a maximum of 10 match conditions per rule. All conditions
within a rule are ANDed together.

### AZ310: Invalid matchVariable

The `matchVariable` must be one of: `RemoteAddr`, `SocketAddr`,
`RequestMethod`, `QueryString`, `PostArgs`, `RequestUri`, `RequestHeader`,
`RequestBody`, `Cookies`.

### AZ311: Invalid operator

The `operator` must be one of: `Any`, `IPMatch`, `GeoMatch`, `Equal`,
`Contains`, `BeginsWith`, `EndsWith`, `RegEx`, `LessThan`, `GreaterThan`,
`LessThanOrEqual`, `GreaterThanOrEqual`, `ServiceTagMatch`.

### AZ312: Missing matchValue for non-Any operator

All operators except `Any` require at least one entry in `matchValue`.

Triggers on:

```yaml
    matchConditions:
      - matchVariable: RemoteAddr
        operator: IPMatch
        matchValue: []               # <-- empty for non-Any
```

### AZ313: matchValue exceeds limit

IPMatch supports up to 600 values per condition. String operators (Contains,
Equal, etc.) support up to 10 values per condition.

### AZ314: Invalid transform type

Valid transforms: `Lowercase`, `Uppercase`, `Trim`, `UrlDecode`, `UrlEncode`,
`RemoveNulls`, `HtmlEntityDecode` (App Gateway only).

### AZ315: Selector required for variable

`RequestHeader`, `Cookies`, and `PostArgs` require a `selector` specifying
which header, cookie, or post parameter to match.

Triggers on:

```yaml
    matchConditions:
      - matchVariable: RequestHeader
        operator: Contains           # <-- no selector: which header?
        matchValue: ["bot"]
```

Fix: Add `selector: User-Agent` (or the relevant header name).

### AZ316: Empty selector

Warning when `selector` is set to an empty string for a variable that requires
one. The rule will match against an empty header/cookie name.

### AZ317: Invalid regex pattern

The `matchValue` entries for `RegEx` operator must be valid regular
expressions. Syntax errors are caught at lint time instead of deployment.

Triggers on:

```yaml
    matchConditions:
      - matchVariable: RequestUri
        operator: RegEx
        matchValue:
          - "[invalid"               # <-- unclosed bracket
```

### AZ318: Invalid CIDR in IPMatch

Warns when an `IPMatch` value is not a valid IPv4/IPv6 address or CIDR.

Triggers on:

```yaml
        matchValue:
          - "not-an-ip"
          - "999.999.999.999"
```

### AZ319: Private/reserved IP range in IPMatch

Info-level notice when a private or reserved IP range (RFC 1918, loopback,
link-local, RFC 6598) appears in an IPMatch condition. These addresses are
typically not seen in public WAF traffic and may indicate a configuration
meant for a different environment.

Triggers on:

```yaml
        matchValue:
          - 10.0.0.0/8
          - 192.168.1.0/24
          - 127.0.0.1
```

### AZ320: Unknown GeoMatch country code

GeoMatch values must be ISO 3166-1 alpha-2 country codes (exactly 2
uppercase letters). Lowercase or numeric values are rejected by Azure.

Triggers on:

```yaml
        matchValue:
          - "us"           # <-- must be "US"
          - "123"          # <-- not a country code
```

### AZ321: Selector on non-selector variable

Warning when `selector` is set on a variable that doesn't use selectors
(e.g., `RemoteAddr`, `RequestUri`). The selector is ignored by Azure but
may indicate the wrong variable was chosen.

Triggers on:

```yaml
    matchConditions:
      - matchVariable: RemoteAddr
        selector: X-Forwarded-For    # <-- ignored; did you mean RequestHeader?
        operator: IPMatch
```

### AZ322: Catch-all CIDR matches all traffic

Warns when `0.0.0.0/0` or `::/0` is used as an IPMatch value. These CIDRs
match all IPv4 or IPv6 traffic respectively, making the condition effectively
an `Any` match.

### AZ323: GeoMatch with very many countries

Warns when a GeoMatch condition has 200 or more country codes. With ~249
total ISO country codes, 200+ likely matches almost all traffic and may be
better expressed as a negated condition with the few countries to exclude.

### AZ324: Negated Any operator always false

A condition with `operator: Any` and `negateCondition: true` never matches.
Since `Any` matches everything, negating it matches nothing. The rule
containing this condition will never trigger.

Triggers on:

```yaml
    matchConditions:
      - matchVariable: RequestUri
        operator: Any
        negateCondition: true        # <-- always false
```

Fix: Remove `negateCondition` or use a different operator.

### AZ325: matchValue ignored with Any operator

The `Any` operator matches all traffic regardless of `matchValue`. If
`matchValue` is non-empty, the values are silently ignored — likely a
mistake where a different operator was intended.

Triggers on:

```yaml
    matchConditions:
      - matchVariable: RequestUri
        operator: Any
        matchValue: ["/api/"]        # <-- ignored by Any
```

Fix: Use `operator: BeginsWith` if you want to match the path, or use
`matchValue: []` if `Any` is intentional.

### AZ326: Operator not supported on this WAF type

Fires when `ServiceTagMatch` (Front Door only) is used with
`waf_type: app_gateway`.

### AZ327: Variable not supported on this WAF type

Fires when `SocketAddr` (Front Door only) is used with
`waf_type: app_gateway`. Application Gateway does not have a `SocketAddr`
variable — use `RemoteAddr` instead.

### AZ328: Transform not supported on this WAF type

Fires when `HtmlEntityDecode` (Application Gateway only) is used with
`waf_type: front_door`. Front Door does not support this transform.

### AZ330: Redundant or conflicting transforms

Warns when transforms cancel each other out or are duplicated.

Triggers on:

```yaml
        transforms:
          - Lowercase
          - Uppercase          # <-- cancels Lowercase
```

```yaml
        transforms:
          - Trim
          - Trim               # <-- duplicate
```

### AZ331: matchValue entry must be a string

All `matchValue` entries must be strings. Integers, booleans, and other types
are rejected.

Triggers on:

```yaml
        matchValue:
          - 12345              # <-- int, should be "12345"
          - true               # <-- bool, should be "true"
```

### AZ332: Regex pattern exceeds recommended length

Warns when a `RegEx` pattern exceeds 256 characters. Very long patterns may
indicate a configuration error or a pattern that should be split into
multiple rules.

### AZ333: Transforms have no effect with this operator

Warns when transforms are applied to `IPMatch`, `GeoMatch`, `Any`, or
`ServiceTagMatch` operators. These operators compare against structured
values where string transforms are meaningless.

Triggers on:

```yaml
    matchConditions:
      - matchVariable: RemoteAddr
        operator: IPMatch
        transforms:
          - Lowercase          # <-- no effect on IP comparison
        matchValue: ["10.0.0.1"]
```

Fix: Remove the `transforms` field.

### AZ334: Duplicate matchValue entry

Warns when the same value appears more than once in `matchValue`. For string
operators, comparison is case-insensitive (since transforms may normalize
case). Duplicates waste the 10-value limit without adding coverage.

### AZ335: matchValue contains an empty string

Warns when `matchValue` contains `""` for string operators (Contains, Equal,
BeginsWith, etc.). An empty string match is almost always unintentional and
can cause unexpected rule behavior.

Triggers on:

```yaml
    matchConditions:
      - matchVariable: QueryString
        operator: Contains
        matchValue: ["", "admin"]    # <-- empty string
```

### AZ336: Multiple conditions on same variable+operator

Warns when a rule has two or more conditions using the same `matchVariable`
and `operator`. Since conditions are ANDed, this creates an *intersection*
(IP must be in list A AND list B), not a union. Users almost always want OR
logic, which requires separate rules.

Triggers on:

```yaml
  - ref: ConfusingRule
    matchConditions:
      - matchVariable: RemoteAddr
        operator: IPMatch
        matchValue: ["10.0.0.0/8"]
      - matchVariable: RemoteAddr     # <-- same var + same op = AND
        operator: IPMatch
        matchValue: ["172.16.0.0/12"]
```

Fix: Merge values into one condition for AND, or split into separate rules
for OR.

### AZ340: Catch-all rule matches all traffic

Warns when all match conditions in a rule use the `Any` operator (or
`IPMatch` with `0.0.0.0/0` / `::/0`) with a terminal action (Allow, Block,
Redirect, JSChallenge). This rule matches
every request and makes all lower-priority rules unreachable.

### AZ341: Rule is unreachable after catch-all

Warns when a rule has a higher priority number (lower precedence) than a
catch-all rule with a terminal action. The catch-all processes every request
first, so this rule will never execute.

Triggers on:

```yaml
  - ref: CatchAll
    priority: 1
    action: Block
    matchConditions:
      - matchVariable: RequestUri
        operator: Any
  - ref: NeverReached         # <-- AZ341
    priority: 2
    action: Allow
    matchConditions: [...]
```

Fix: Remove the unreachable rule or adjust priorities.

---

## Rate Limiting (AZ4xx)

### AZ400: rateLimitDurationInMinutes invalid

For `RateLimitRule` rules, `rateLimitDurationInMinutes` must be `1` or `5`
(the only values Azure supports).

### AZ401: rateLimitThreshold invalid

The threshold must be an integer, must not exceed 1,000,000, and must not be
a non-integer type (string, float, bool). Values below 10 produce AZ403
instead.

### AZ402: Invalid groupBy variable

The `groupBy.variableName` must be `SocketAddr`, `GeoLocation`, or `None`.

### AZ403: rateLimitThreshold below minimum

Azure requires a minimum threshold of 10 requests per time window.

### AZ410: RateLimitRule matches all traffic

Warns when a rate-limit rule's conditions all use the `Any` operator. This
rate-limits every client regardless of what they request, which is usually
not the intended behavior.

Triggers on:

```yaml
azure_waf_rate_rules:
  - ref: RateLimitEverything
    ruleType: RateLimitRule
    rateLimitDurationInMinutes: 1
    rateLimitThreshold: 100
    matchConditions:
      - matchVariable: RequestUri
        operator: Any                # <-- matches everything
```

Fix: Add a meaningful condition (e.g., specific URI path, header).

### AZ411: Rate-limit fields on a MatchRule

Warns when rate-limit-specific fields (`rateLimitDurationInMinutes`,
`rateLimitThreshold`, `groupBy`) are present on a `MatchRule`. Azure
silently ignores these fields, but their presence signals confusion —
the user likely intended `ruleType: RateLimitRule`.

Triggers on:

```yaml
  - ref: ConfusedRule
    ruleType: MatchRule
    rateLimitThreshold: 100          # <-- ignored on MatchRule
    rateLimitDurationInMinutes: 1    # <-- ignored on MatchRule
```

Fix: Change `ruleType` to `RateLimitRule`, or remove the rate-limit fields.

---

## Cross-Rule / Policy-Level (AZ5xx)

### AZ500: Regex rules exceed 5 per policy

Azure limits the total number of custom rules using the `RegEx` operator to
5 per policy. This is enforced across all phases (custom + rate combined).

### AZ501: Custom rules exceed 100 per policy

Azure limits total custom rules to 100 per policy across all rule types.
This check counts rules in both `azure_waf_custom_rules` and
`azure_waf_rate_rules` phases.

### AZ520: Duplicate match conditions across rules

Warns when two rules in the same phase have identical `matchConditions`
(after JSON serialization). This usually indicates a copy-paste error.

### AZ521: Duplicate priority across phases

Azure requires priorities to be unique across ALL custom rules in a policy,
not just within a single phase. A priority used in `azure_waf_custom_rules`
cannot also be used in `azure_waf_rate_rules`.

Triggers on:

```yaml
azure_waf_custom_rules:
  - ref: CustomRule1
    priority: 5              # <-- conflict
    ...

azure_waf_rate_rules:
  - ref: RateRule1
    priority: 5              # <-- same priority, different phase
    ...
```

Fix: Use different priority values across phases.

---

## Best Practice (AZ6xx)

### AZ600: Rule is disabled

Info-level notice when `enabledState: Disabled`. Disabled rules consume
capacity but don't evaluate. Consider removing them if they're no longer
needed.

### AZ601: Log action continues to next rule

Info-level notice when `action: Log`. Unlike Allow/Block, the Log action
records the match but does NOT stop rule evaluation -- traffic continues to
the next rule and then to managed rules.

### AZ602: All rules in phase are disabled

Warns when every rule in a phase has `enabledState: Disabled`. This means
the entire phase is effectively inactive, which may not be intentional.

### AZ603: Allow catch-all bypasses managed rules

Info-level notice when an Allow rule with all-Any conditions exists. In
Azure WAF, an Allow action on a custom rule causes the request to skip all
managed rules (OWASP DRS, Bot Protection). This is by design but can be a
security concern if unintentional.
