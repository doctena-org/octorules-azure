# Lint Rule Reference

`octorules lint` performs offline static analysis of your Azure WAF rules files. **71 rules** with the `AZ` prefix cover structure, priorities, actions, match conditions, rate limits, cross-rule analysis, best practices, and managed rule sets.

These rules are registered automatically when `octorules-azure` is installed. They run alongside any core and other provider rules during `octorules lint`.

### Suppressing rules

Add a `# octorules:disable=RULE` comment immediately before a rule to suppress a specific finding. Multiple rule IDs can be comma-separated.

```yaml
azure_waf_custom_rules:
  # octorules:disable=AZ319
  - ref: AllowPrivate
    priority: 10
    action: Allow
    matchConditions:
      - matchVariable: RemoteAddr
        operator: IPMatch
        matchValue: ["10.0.0.0/8"]
```

**Multiple rules:**

```yaml
  # octorules:disable=AZ020,AZ600
  - ref: LegacyRule
    priority: 20
    action: Block
    enabledState: Disabled
    custom_field: something
    matchConditions:
      - matchVariable: RemoteAddr
        operator: IPMatch
        matchValue: ["203.0.113.0/24"]
```

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
| AZ103 | WARNING | priority | Priority out of valid range for this WAF type (Front Door) |
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
| AZ337 | WARNING | match | CIDR has host bits set |
| AZ338 | WARNING | match | Redundant CIDR in matchValue (already covered by a broader range) |
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
| AZ700 | ERROR | managed | Managed rule set missing or duplicate ref |
| AZ701 | WARNING | managed | Invalid or unknown ruleSetType |
| AZ702 | ERROR | managed | Invalid ruleSetAction |
| AZ703 | ERROR | managed | Invalid enabledState in rule override |
| AZ704 | ERROR | managed | Invalid ruleGroupOverrides structure |
| AZ705 | WARNING | managed | ruleSetAction not supported on this WAF type |
| AZ706 | ERROR | managed | Missing or invalid ruleId in rule override |
| AZ707 | ERROR | managed | Invalid action in rule override |
| AZ708 | WARNING | managed | FD-only managed rule override action used with App Gateway |

---

## Structure (AZ0xx)

### AZ001 -- Rule missing `ref`

**Severity:** ERROR

Every rule must have a `ref` field (the rule name in Azure).

**Triggers on:**

```yaml
azure_waf_custom_rules:
  - priority: 1
    action: Block
    matchConditions: [...]
```

**Fix:** Add a `ref` field:

```yaml
  - ref: BlockBadIPs
    priority: 1
    action: Block
    matchConditions: [...]
```

### AZ002 -- Rule missing `priority`

**Severity:** ERROR

Every rule must have a numeric `priority` field.

**Triggers on:**

```yaml
  - ref: BlockBadIPs
    action: Block
    matchConditions: [...]
```

**Fix:** Add a unique positive integer `priority`:

```yaml
  - ref: BlockBadIPs
    priority: 1
```

### AZ003 -- Rule missing `action`

**Severity:** ERROR

Every rule must have an `action` field specifying what to do when matched.

**Triggers on:**

```yaml
  - ref: MyRule
    priority: 1
    matchConditions: [...]
```

**Fix:** Add `action: Block` (or `Allow`, `Log`, `Redirect`, `JSChallenge`).

### AZ004 -- Rule missing `matchConditions`

**Severity:** ERROR

Every rule must have at least one match condition.

**Triggers on:**

```yaml
  - ref: MyRule
    priority: 1
    action: Block
```

**Fix:** Add a `matchConditions` list:

```yaml
    matchConditions:
      - matchVariable: RemoteAddr
        operator: IPMatch
        matchValue: ["203.0.113.0/24"]
```

### AZ005 -- Invalid `enabledState` value

**Severity:** ERROR

`enabledState` must be exactly `"Enabled"` or `"Disabled"`.

**Triggers on:**

```yaml
  - ref: MyRule
    enabledState: Active
```

**Fix:** Use `Enabled` or `Disabled`.

### AZ006 -- Invalid `ruleType` value

**Severity:** ERROR

`ruleType` must be exactly `"MatchRule"` or `"RateLimitRule"`.

**Triggers on:**

```yaml
  - ref: MyRule
    ruleType: CustomRule
```

**Fix:** Use `MatchRule` or `RateLimitRule`.

### AZ010 -- Invalid `ref` format

**Severity:** ERROR

Rule names must start with a letter and contain only letters, digits, and
underscores. Maximum 128 characters. Azure rejects rules that don't match
this pattern.

**Triggers on:**

```yaml
  - ref: 1BadName       # starts with digit
  - ref: my-rule        # contains hyphen
```

**Fix:** Use `^[a-zA-Z][a-zA-Z0-9_]*$` pattern. Example: `Block_Bad_IPs`.

### AZ020 -- Unknown top-level rule field

**Severity:** WARNING

Warns when a rule contains a field that isn't part of the Azure WAF schema.
This usually means a typo or a field from a different provider.

**Triggers on:**

```yaml
  - ref: MyRule
    Statement: {...}       # <-- AWS field, not Azure
```

### AZ021 -- negateCondition must be boolean

**Severity:** ERROR

The `negateCondition` field must be `true` or `false`, not a string or integer.

**Triggers on:**

```yaml
    matchConditions:
      - matchVariable: RemoteAddr
        operator: IPMatch
        negateCondition: "true"    # <-- string, not bool
```

**Fix:** Use `negateCondition: true` (no quotes).

### AZ022 -- Duplicate `ref` within phase

**Severity:** ERROR

Rule names must be unique within a phase. Duplicate refs cause unpredictable
behavior during sync.

**Triggers on:**

```yaml
azure_waf_custom_rules:
  - ref: BlockIPs
    priority: 1
    ...
  - ref: BlockIPs          # <-- duplicate
    priority: 2
    ...
```

---

## Priority (AZ1xx)

### AZ100 -- Priority must be a positive integer

**Severity:** ERROR

The `priority` field must be a positive integer (1 or greater). Floats,
negative numbers, zero, and booleans are rejected.

**Triggers on:**

```yaml
  - ref: MyRule
    priority: 0        # <-- must be >= 1
    priority: -1       # <-- negative
    priority: 1.5      # <-- float
    priority: true     # <-- bool
```

### AZ101 -- Duplicate priority across rules

**Severity:** ERROR

Azure WAF requires unique priorities within each phase. Two rules with the
same priority will cause a deployment error.

**Triggers on:**

```yaml
  - ref: RuleA
    priority: 1
  - ref: RuleB
    priority: 1        # <-- same as RuleA
```

### AZ102 -- Non-contiguous rule priorities

**Severity:** INFO

Info-level notice when there are gaps in priority numbering (e.g., 1, 2, 5).
Not an error, but may indicate a deleted rule that should be cleaned up.

### AZ103 -- Priority out of valid range for Front Door WAF

**Severity:** WARNING

Azure Front Door WAF requires custom rule priorities in the range 1–100. Priorities above 100 are accepted by the App Gateway API but rejected by Front Door at deployment time.

**Triggers on:**

```yaml
# config.yaml: waf_type: front_door
  - ref: LowPriorityRule
    priority: 150             # <-- exceeds Front Door maximum of 100
    action: Block
    matchConditions: [...]
```

**Fix:** Assign a priority between 1 and 100.

---

## Action (AZ2xx)

### AZ200 -- Invalid action type

**Severity:** ERROR

The `action` field must be one of: `Allow`, `Block`, `Log`, `Redirect`,
`AnomalyScoring`, or `JSChallenge`.

**Triggers on:**

```yaml
  - ref: MyRule
    action: Deny           # <-- Azure uses "Block", not "Deny"
```

**Fix:** Use `Block` instead of `Deny`.

Note: `Redirect` and `AnomalyScoring` are Front Door only.
See AZ201 for waf_type-aware validation.

### AZ201 -- Action not supported on this WAF type

**Severity:** ERROR

Fires when a Front Door-only action (`Redirect`, `AnomalyScoring`) is used
with `waf_type: app_gateway`. These actions will be rejected by the App
Gateway API at deployment time.

**Triggers on:**

```yaml
# config.yaml: waf_type: app_gateway
  - ref: MyRule
    action: Redirect       # <-- FD only
```

---

## Match Conditions (AZ3xx)

### AZ300 -- matchConditions must be a non-empty list of dicts

**Severity:** ERROR

The `matchConditions` field must be a list containing at least one dict.

**Triggers on:**

```yaml
    matchConditions: []              # <-- empty
    matchConditions: "RemoteAddr"    # <-- not a list
    matchConditions: ["bad"]         # <-- entries must be dicts
```

### AZ301 -- matchConditions exceeds 10 per rule

**Severity:** ERROR

Azure WAF supports a maximum of 10 match conditions per rule. All conditions
within a rule are ANDed together.

**Triggers on:** A rule with 11+ entries in `matchConditions`.

### AZ310 -- Invalid matchVariable

**Severity:** ERROR

The `matchVariable` must be one of: `RemoteAddr`, `SocketAddr`,
`RequestMethod`, `QueryString`, `PostArgs`, `RequestUri`, `RequestHeader`,
`RequestBody`, `Cookies`.

**Triggers on:**

```yaml
      - matchVariable: IP              # <-- not a valid variable
```

### AZ311 -- Invalid operator

**Severity:** ERROR

The `operator` must be one of: `Any`, `IPMatch`, `GeoMatch`, `Equal`,
`Contains`, `BeginsWith`, `EndsWith`, `RegEx`, `LessThan`, `GreaterThan`,
`LessThanOrEqual`, `GreaterThanOrEqual`, `ServiceTagMatch`.

**Triggers on:**

```yaml
      - operator: Matches             # <-- not a valid operator
```

### AZ312 -- Missing matchValue for non-Any operator

**Severity:** ERROR

All operators except `Any` require at least one entry in `matchValue`.

**Triggers on:**

```yaml
      - matchVariable: RemoteAddr
        operator: IPMatch
        matchValue: []               # <-- empty for non-Any
```

### AZ313 -- matchValue exceeds limit

**Severity:** ERROR

IPMatch supports up to 600 values per condition. String operators (Contains,
Equal, etc.) support up to 10 values per condition.

**Triggers on:** `matchValue` with 601+ entries for IPMatch, or 11+ for string operators.

### AZ314 -- Invalid transform type

**Severity:** ERROR

Valid transforms: `Lowercase`, `Uppercase`, `Trim`, `UrlDecode`, `UrlEncode`,
`RemoveNulls`, `HtmlEntityDecode` (App Gateway only).

**Triggers on:**

```yaml
        transforms:
          - Base64Decode             # <-- not a valid Azure transform
```

### AZ315 -- Selector required for variable

**Severity:** ERROR

`RequestHeader`, `Cookies`, and `PostArgs` require a `selector` specifying
which header, cookie, or post parameter to match.

**Triggers on:**

```yaml
      - matchVariable: RequestHeader
        operator: Contains           # <-- no selector: which header?
        matchValue: ["bot"]
```

**Fix:** Add `selector: User-Agent` (or the relevant header name).

### AZ316 -- Empty selector

**Severity:** WARNING

Warning when `selector` is set to an empty string for a variable that requires
one. The rule will match against an empty header/cookie name.

**Triggers on:**

```yaml
      - matchVariable: RequestHeader
        selector: ""                 # <-- empty
```

### AZ317 -- Invalid regex pattern

**Severity:** ERROR

The `matchValue` entries for `RegEx` operator must be valid regular
expressions. Syntax errors are caught at lint time instead of deployment.

**Triggers on:**

```yaml
      - operator: RegEx
        matchValue:
          - "[invalid"               # <-- unclosed bracket
```

### AZ318 -- Invalid CIDR in IPMatch

**Severity:** WARNING

Warns when an `IPMatch` value is not a valid IPv4/IPv6 address or CIDR.

**Triggers on:**

```yaml
        matchValue:
          - "not-an-ip"
          - "999.999.999.999"
```

### AZ319 -- Private/reserved IP range in IPMatch

**Severity:** INFO

Info-level notice when an IPMatch value overlaps with a private or reserved
IP range (RFC 1918, loopback, link-local, RFC 6598). This includes both
subnets of private ranges (e.g., `10.1.0.0/16`) and supernets that contain
private ranges (e.g., `0.0.0.0/4` which contains `10.0.0.0/8`). These
addresses are typically not seen in public WAF traffic and may indicate a
configuration meant for a different environment.

**Triggers on:**

```yaml
        matchValue:
          - 10.0.0.0/8               # <-- private range
          - 192.168.1.0/24           # <-- subnet of private range
          - 0.0.0.0/4                # <-- supernet containing 10.0.0.0/8
          - 127.0.0.1                # <-- loopback
```

### AZ320 -- Unknown GeoMatch country code

**Severity:** WARNING

GeoMatch values must be ISO 3166-1 alpha-2 country codes (exactly 2
uppercase letters). Lowercase or numeric values are rejected by Azure.

**Triggers on:**

```yaml
        matchValue:
          - "us"                     # <-- must be "US"
          - "123"                    # <-- not a country code
```

### AZ321 -- Selector on non-selector variable

**Severity:** WARNING

Warning when `selector` is set on a variable that doesn't use selectors
(e.g., `RemoteAddr`, `RequestUri`). The selector is ignored by Azure but
may indicate the wrong variable was chosen.

**Triggers on:**

```yaml
      - matchVariable: RemoteAddr
        selector: X-Forwarded-For    # <-- ignored; did you mean RequestHeader?
        operator: IPMatch
```

### AZ322 -- Catch-all CIDR matches all traffic

**Severity:** WARNING

Warns when `0.0.0.0/0` or `::/0` is used as an IPMatch value. These CIDRs
match all IPv4 or IPv6 traffic respectively, making the condition effectively
an `Any` match.

**Triggers on:**

```yaml
        matchValue:
          - "0.0.0.0/0"             # <-- matches everything
```

### AZ323 -- GeoMatch with very many countries

**Severity:** WARNING

Warns when a GeoMatch condition has 200 or more country codes. With ~249
total ISO country codes, 200+ likely matches almost all traffic and may be
better expressed as a negated condition with the few countries to exclude.

**Triggers on:** A GeoMatch condition with 200+ entries in `matchValue`.

### AZ324 -- Negated Any operator always false

**Severity:** WARNING

A condition with `operator: Any` and `negateCondition: true` never matches.
Since `Any` matches everything, negating it matches nothing. The rule
containing this condition will never trigger.

**Triggers on:**

```yaml
      - matchVariable: RequestUri
        operator: Any
        negateCondition: true        # <-- always false
```

**Fix:** Remove `negateCondition` or use a different operator.

### AZ325 -- matchValue ignored with Any operator

**Severity:** WARNING

The `Any` operator matches all traffic regardless of `matchValue`. If
`matchValue` is non-empty, the values are silently ignored -- likely a
mistake where a different operator was intended.

**Triggers on:**

```yaml
      - matchVariable: RequestUri
        operator: Any
        matchValue: ["/api/"]        # <-- ignored by Any
```

**Fix:** Use `operator: BeginsWith` if you want to match the path, or use
`matchValue: []` if `Any` is intentional.

### AZ326 -- Operator not supported on this WAF type

**Severity:** ERROR

Fires when `ServiceTagMatch` (Front Door only) is used with
`waf_type: app_gateway`.

**Triggers on:**

```yaml
# config.yaml: waf_type: app_gateway
      - operator: ServiceTagMatch    # <-- FD only
```

### AZ327 -- Variable not supported on this WAF type

**Severity:** ERROR

Fires when `SocketAddr` (Front Door only) is used with
`waf_type: app_gateway`. Application Gateway does not have a `SocketAddr`
variable -- use `RemoteAddr` instead.

**Triggers on:**

```yaml
# config.yaml: waf_type: app_gateway
      - matchVariable: SocketAddr    # <-- FD only
```

### AZ328 -- Transform not supported on this WAF type

**Severity:** ERROR

Fires when `HtmlEntityDecode` (Application Gateway only) is used with
`waf_type: front_door`. Front Door does not support this transform.

**Triggers on:**

```yaml
# config.yaml: waf_type: front_door
        transforms:
          - HtmlEntityDecode         # <-- AG only
```

### AZ330 -- Redundant or conflicting transforms

**Severity:** WARNING

Warns when transforms cancel each other out or are duplicated.

**Triggers on:**

```yaml
        transforms:
          - Lowercase
          - Uppercase                # <-- cancels Lowercase
```

```yaml
        transforms:
          - Trim
          - Trim                     # <-- duplicate
```

### AZ331 -- matchValue entry must be a string

**Severity:** ERROR

All `matchValue` entries must be strings. Integers, booleans, and other types
are rejected.

**Triggers on:**

```yaml
        matchValue:
          - 12345                    # <-- int, should be "12345"
          - true                     # <-- bool, should be "true"
```

### AZ332 -- Regex pattern exceeds recommended length

**Severity:** WARNING

Warns when a `RegEx` pattern exceeds 256 characters. Very long patterns may
indicate a configuration error or a pattern that should be split into
multiple rules.

**Triggers on:** A `matchValue` entry with 257+ characters when `operator: RegEx`.

### AZ333 -- Transforms have no effect with this operator

**Severity:** WARNING

Warns when transforms are applied to `IPMatch`, `GeoMatch`, `Any`, or
`ServiceTagMatch` operators. These operators compare against structured
values where string transforms are meaningless.

**Triggers on:**

```yaml
      - matchVariable: RemoteAddr
        operator: IPMatch
        transforms:
          - Lowercase                # <-- no effect on IP comparison
        matchValue: ["10.0.0.1"]
```

**Fix:** Remove the `transforms` field.

### AZ334 -- Duplicate matchValue entry

**Severity:** WARNING

Warns when the same value appears more than once in `matchValue`. For string
operators, comparison is case-insensitive (since transforms may normalize
case). For `IPMatch`, IPv6 addresses are lowercased before comparison so that
`2001:DB8::1` and `2001:db8::1` are detected as duplicates. Duplicates waste
the value limit without adding coverage.

**Triggers on:**

```yaml
        matchValue:
          - "test"
          - "Test"                   # <-- same after case normalization
```

```yaml
        operator: IPMatch
        matchValue:
          - "2001:DB8::1"
          - "2001:db8::1"            # <-- same after IPv6 normalization
```

### AZ335 -- matchValue contains an empty string

**Severity:** WARNING

Warns when `matchValue` contains `""` for string operators (Contains, Equal,
BeginsWith, etc.). An empty string match is almost always unintentional and
can cause unexpected rule behavior.

**Triggers on:**

```yaml
      - operator: Contains
        matchValue: ["", "admin"]    # <-- empty string
```

### AZ336 -- Multiple conditions on same variable+operator

**Severity:** WARNING

Warns when a rule has two or more conditions using the same `matchVariable`
and `operator`. Since conditions are ANDed, this creates an *intersection*
(IP must be in list A AND list B), not a union. Users almost always want OR
logic, which requires separate rules.

**Triggers on:**

```yaml
    matchConditions:
      - matchVariable: RemoteAddr
        operator: IPMatch
        matchValue: ["10.0.0.0/8"]
      - matchVariable: RemoteAddr     # <-- same var + same op = AND
        operator: IPMatch
        matchValue: ["172.16.0.0/12"]
```

**Fix:** Merge values into one condition for AND, or split into separate rules
for OR.

### AZ337 -- CIDR has host bits set

**Severity:** WARNING

The CIDR notation has host bits set (e.g. `10.0.0.1/24`). Azure accepts
this but silently normalises to the network address (`10.0.0.0/24`).
The rule warns so you can update the YAML to match what Azure actually
stores, preventing phantom diffs on subsequent plans.

```yaml
matchConditions:
  - matchVariable: RemoteAddr
    operator: IPMatch
    matchValue:
      - "10.0.0.1/24"   # <-- host bits set, did you mean 10.0.0.0/24?
```

**Fix:** Replace with the normalised network address shown in the warning.

### AZ338 -- Redundant CIDR in matchValue

**Severity:** WARNING

A CIDR in `matchValue` is already fully covered by a broader CIDR in the same
condition. The narrower range is redundant and can be removed without changing
the rule's behaviour.

**Triggers on:**

```yaml
matchConditions:
  - matchVariable: RemoteAddr
    operator: IPMatch
    matchValue:
      - "10.0.0.0/8"
      - "10.1.2.0/24"   # <-- redundant: already covered by 10.0.0.0/8
```

**Fix:** Remove the narrower CIDR:

```yaml
    matchValue:
      - "10.0.0.0/8"
```

### AZ340 -- Catch-all rule matches all traffic

**Severity:** WARNING

Warns when all match conditions in a rule use the `Any` operator (or
`IPMatch` with `0.0.0.0/0` / `::/0`) with a terminal action (Allow, Block,
Redirect, JSChallenge). This rule matches every request and makes all
lower-priority rules unreachable.

**Triggers on:**

```yaml
  - ref: BlockEverything
    priority: 1
    action: Block
    matchConditions:
      - matchVariable: RequestUri
        operator: Any
```

### AZ341 -- Rule is unreachable after catch-all

**Severity:** WARNING

Warns when a rule has a higher priority number (lower precedence) than a
catch-all rule with a terminal action. The catch-all processes every request
first, so this rule will never execute.

**Triggers on:**

```yaml
  - ref: CatchAll
    priority: 1
    action: Block
    matchConditions:
      - matchVariable: RequestUri
        operator: Any
  - ref: NeverReached              # <-- AZ341
    priority: 2
    action: Allow
    matchConditions: [...]
```

**Fix:** Remove the unreachable rule or adjust priorities.

---

## Rate Limiting (AZ4xx)

### AZ400 -- rateLimitDurationInMinutes invalid

**Severity:** ERROR

For `RateLimitRule` rules, `rateLimitDurationInMinutes` must be `1` or `5`
(the only values Azure supports).

**Triggers on:**

```yaml
    rateLimitDurationInMinutes: 10   # <-- must be 1 or 5
```

### AZ401 -- rateLimitThreshold invalid

**Severity:** ERROR

The threshold must be an integer and must not exceed 1,000,000. Must not be
a non-integer type (string, float, bool). Values below 10 produce AZ403
instead.

**Triggers on:**

```yaml
    rateLimitThreshold: "100"        # <-- string, must be int
    rateLimitThreshold: 2000000      # <-- exceeds 1,000,000
```

### AZ402 -- Invalid groupBy variable

**Severity:** ERROR

The `groupBy.variableName` must be `SocketAddr`, `GeoLocation`, or `None`.

**Triggers on:**

```yaml
    groupBy:
      - variableName: ClientIP       # <-- not a valid groupBy variable
```

### AZ403 -- rateLimitThreshold below minimum

**Severity:** ERROR

Azure requires a minimum threshold of 10 requests per time window.

**Triggers on:**

```yaml
    rateLimitThreshold: 5            # <-- below minimum of 10
```

### AZ410 -- RateLimitRule matches all traffic

**Severity:** WARNING

Warns when a rate-limit rule's conditions all use the `Any` operator. This
rate-limits every client regardless of what they request, which is usually
not the intended behavior.

**Triggers on:**

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

**Fix:** Add a meaningful condition (e.g., specific URI path, header).

### AZ411 -- Rate-limit fields on a MatchRule

**Severity:** WARNING

Warns when rate-limit-specific fields (`rateLimitDurationInMinutes`,
`rateLimitThreshold`, `groupBy`) are present on a `MatchRule`. Azure
silently ignores these fields, but their presence signals confusion --
the user likely intended `ruleType: RateLimitRule`.

**Triggers on:**

```yaml
  - ref: ConfusedRule
    ruleType: MatchRule
    rateLimitThreshold: 100          # <-- ignored on MatchRule
    rateLimitDurationInMinutes: 1    # <-- ignored on MatchRule
```

**Fix:** Change `ruleType` to `RateLimitRule`, or remove the rate-limit fields.

---

## Cross-Rule / Policy-Level (AZ5xx)

### AZ500 -- Regex rules exceed 5 per policy

**Severity:** ERROR

Azure limits the total number of custom rules using the `RegEx` operator to
5 per policy. This is enforced across all phases (custom + rate combined).

**Triggers on:** 6+ rules with `operator: RegEx` in any condition across both phases.

### AZ501 -- Custom rules exceed 100 per policy

**Severity:** WARNING

Azure limits total custom rules to 100 per policy across all rule types.
This check counts rules in both `azure_waf_custom_rules` and
`azure_waf_rate_rules` phases.

**Triggers on:** 101+ total rules across both phases.

### AZ520 -- Duplicate match conditions across rules

**Severity:** WARNING

Warns when two rules in the same phase have identical `matchConditions`
(after sorting and JSON serialization). Conditions are compared
order-insensitively, so `[A, B]` and `[B, A]` are detected as duplicates.
This usually indicates a copy-paste error.

**Triggers on:** Two rules with the same `matchConditions` (in any order) in the same phase.

### AZ521 -- Duplicate priority across phases

**Severity:** ERROR

Azure requires priorities to be unique across ALL custom rules in a policy,
not just within a single phase. A priority used in `azure_waf_custom_rules`
cannot also be used in `azure_waf_rate_rules`.

**Triggers on:**

```yaml
azure_waf_custom_rules:
  - ref: CustomRule1
    priority: 5                      # <-- conflict
    ...

azure_waf_rate_rules:
  - ref: RateRule1
    priority: 5                      # <-- same priority, different phase
    ...
```

**Fix:** Use different priority values across phases.

---

## Best Practice (AZ6xx)

### AZ600 -- Rule is disabled

**Severity:** INFO

Info-level notice when `enabledState: Disabled`. Disabled rules consume
capacity but don't evaluate. Consider removing them if they're no longer
needed.

**Triggers on:**

```yaml
  - ref: OldRule
    enabledState: Disabled
```

### AZ601 -- Log action continues to next rule

**Severity:** INFO

Info-level notice when `action: Log`. Unlike Allow/Block, the Log action
records the match but does NOT stop rule evaluation -- traffic continues to
the next rule and then to managed rules.

**Triggers on:**

```yaml
  - ref: LogSuspicious
    action: Log
```

### AZ602 -- All rules in phase are disabled

**Severity:** WARNING

Warns when every rule in a phase has `enabledState: Disabled`. This means
the entire phase is effectively inactive, which may not be intentional.

**Triggers on:** All rules in `azure_waf_custom_rules` (or `azure_waf_rate_rules`)
have `enabledState: Disabled`.

### AZ603 -- Allow catch-all bypasses managed rules

**Severity:** INFO

Info-level notice when an Allow rule with all-Any conditions exists. In
Azure WAF, an Allow action on a custom rule causes the request to skip all
managed rules (OWASP DRS, Bot Protection). This is by design but can be a
security concern if unintentional.

**Triggers on:**

```yaml
  - ref: AllowEverything
    action: Allow
    matchConditions:
      - matchVariable: RequestUri
        operator: Any
```

---

## Managed Rule Sets (AZ7xx)

### AZ700 -- Managed rule set missing or duplicate ref

**Severity:** ERROR

Every managed rule set entry must have a `ref` field identifying the rule set.
Refs must be unique within the `azure_waf_managed_rules` phase -- duplicate
refs indicate a copy-paste error.

**Triggers on:**

```yaml
azure_waf_managed_rules:
  - ruleSetType: Microsoft_DefaultRuleSet
    ruleSetVersion: "2.1"
    # missing ref
```

```yaml
azure_waf_managed_rules:
  - ref: Microsoft_DefaultRuleSet
    ruleSetType: Microsoft_DefaultRuleSet
    ruleSetVersion: "2.1"
  - ref: Microsoft_DefaultRuleSet     # <-- duplicate
    ruleSetType: Microsoft_DefaultRuleSet
    ruleSetVersion: "1.0"
```

**Fix:** Add a unique `ref` to each managed rule set entry.

### AZ701 -- Invalid or unknown ruleSetType

**Severity:** WARNING (unknown type), ERROR (missing or wrong type)

The `ruleSetType` field must be a non-empty string matching a known Azure
managed rule set. `ruleSetVersion` must also be a non-empty string.

Known rule set types:
- `Microsoft_DefaultRuleSet` -- Microsoft DRS (Front Door + App Gateway)
- `OWASP_CRS` -- OWASP Core Rule Set (App Gateway)
- `Microsoft_BotManagerRuleSet` -- Bot Manager (Front Door)
- `BotProtection` -- Bot Protection (App Gateway)

**Triggers on:**

```yaml
  - ref: MyRuleSet
    ruleSetType: UnknownSet          # <-- not a known type
    ruleSetVersion: "1.0"
```

```yaml
  - ref: MyRuleSet
    ruleSetType: Microsoft_DefaultRuleSet
    # missing ruleSetVersion
```

### AZ702 -- Invalid ruleSetAction

**Severity:** ERROR

The `ruleSetAction` field (Front Door only) must be one of: `Block`, `Log`,
or `Redirect`. This controls the default action for the entire managed rule
set.

**Triggers on:**

```yaml
  - ref: Microsoft_DefaultRuleSet
    ruleSetAction: Deny              # <-- must be Block, Log, or Redirect
```

**Fix:** Use `Block`, `Log`, or `Redirect`.

### AZ703 -- Invalid enabledState in rule override

**Severity:** ERROR

The `enabledState` field in a managed rule override must be exactly `"Enabled"`
or `"Disabled"`.

**Triggers on:**

```yaml
    ruleGroupOverrides:
      - ruleGroupName: SQLI
        rules:
          - ruleId: "942100"
            enabledState: Active     # <-- must be Enabled or Disabled
```

**Fix:** Use `Enabled` or `Disabled`.

### AZ704 -- Invalid ruleGroupOverrides structure

**Severity:** ERROR

The `ruleGroupOverrides` field must be a list of dicts. Each entry must have
a non-empty `ruleGroupName` string. The optional `rules` sub-field must be a
list of dicts.

**Triggers on:**

```yaml
    ruleGroupOverrides: "SQLI"       # <-- must be a list
```

```yaml
    ruleGroupOverrides:
      - rules:                       # <-- missing ruleGroupName
          - ruleId: "942100"
```

```yaml
    ruleGroupOverrides:
      - ruleGroupName: SQLI
        rules: "all"                 # <-- must be a list
```

**Fix:** Ensure `ruleGroupOverrides` is a list of dicts with valid
`ruleGroupName` and optional `rules` list.

### AZ705 -- ruleSetAction not supported on this WAF type

**Severity:** WARNING

Fires when `ruleSetAction` is used with `waf_type: app_gateway`. Application
Gateway does not support the `ruleSetAction` field -- it is Front Door only.

**Triggers on:**

```yaml
# config.yaml: waf_type: app_gateway
azure_waf_managed_rules:
  - ref: OWASP_CRS
    ruleSetType: OWASP_CRS
    ruleSetVersion: "3.2"
    ruleSetAction: Block             # <-- FD only
```

**Fix:** Remove `ruleSetAction` for App Gateway policies.

### AZ706 -- Missing or invalid ruleId in rule override

**Severity:** ERROR

Each rule override within `ruleGroupOverrides[].rules[]` must have a `ruleId`
field that is a non-empty string identifying the managed rule to override.

**Triggers on:**

```yaml
    ruleGroupOverrides:
      - ruleGroupName: SQLI
        rules:
          - enabledState: Disabled   # <-- missing ruleId
```

```yaml
        rules:
          - ruleId: 942100           # <-- must be a string, not int
            enabledState: Disabled
```

**Fix:** Add `ruleId: "942100"` (string, not integer) to each rule override.

### AZ707 -- Invalid action in rule override

**Severity:** ERROR

The `action` field in a managed rule override must be one of: `Allow`,
`Block`, `Log`, `Redirect`, or `AnomalyScoring`.

**Triggers on:**

```yaml
    ruleGroupOverrides:
      - ruleGroupName: SQLI
        rules:
          - ruleId: "942100"
            action: Deny             # <-- not a valid override action
```

**Fix:** Use `Allow`, `Block`, `Log`, `Redirect`, `AnomalyScoring`, `None`, or `JSChallenge`.

### AZ708 -- FD-only managed rule override action used with App Gateway

**Severity:** WARNING

Fires when a Front Door-only override action is used with `waf_type: app_gateway`. Currently, `Redirect` is the only override action restricted to Front Door.

**Triggers on:**

```yaml
azure_waf_managed_rules:
  - ref: DefaultRuleSet
    ruleSetType: Microsoft_DefaultRuleSet
    ruleSetVersion: "2.1"
    ruleGroupOverrides:
      - ruleGroupName: SQLI
        rules:
          - ruleId: "942100"
            action: Redirect            # <-- FD-only override action
```

**Fix:** Use `Allow`, `Block`, or `Log` for Application Gateway managed rule overrides.
