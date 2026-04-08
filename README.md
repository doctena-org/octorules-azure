# octorules-azure

Azure WAF provider for [octorules](https://github.com/doctena-org/octorules) — manages Azure Web Application Firewall custom rules as YAML.

Supports both **Azure Front Door WAF** (Premium/Standard) and **Application Gateway WAF** (WAF_v2) through a unified interface. Users write the same YAML regardless of which WAF type is deployed.

> **Alpha** — this provider has comprehensive offline test coverage (626 tests)
> but has not yet been tested against live Azure WAF APIs. Use with caution and
> report any issues.

## Installation

```bash
pip install octorules-azure
```

This installs octorules (core) and octorules-azure. The provider is auto-discovered — no `class:` needed in config.

## Configuration

```yaml
# config.yaml
providers:
  azure:
    subscription_id: env/AZURE_SUBSCRIPTION_ID
    resource_group: rg-waf-production
    waf_type: front_door       # or "app_gateway"
    timeout: 30                # API timeout in seconds
    max_workers: 1             # parallel workers for multi-zone ops
  rules:
    directory: ./rules

zones:
  api-gateway-waf-policy:
    sources:
      - rules
  corporate-site-waf-policy:
    sources:
      - rules
```

Each zone name maps to an Azure WAF policy name. The provider resolves policy names at runtime. The `env/` prefix resolves values from environment variables at runtime. All keys under the provider section are forwarded to the provider constructor as keyword arguments (octodns-style passthrough).

### Provider settings

All settings below go under the provider section (e.g. `providers.azure`).

| Key | Default | Description |
|---|---|---|
| `subscription_id` | `AZURE_SUBSCRIPTION_ID` env var | Azure subscription ID (required) |
| `resource_group` | `AZURE_RESOURCE_GROUP` env var | Resource group containing WAF policies (required) |
| `waf_type` | `front_door` / `AZURE_WAF_TYPE` env var | `"front_door"` or `"app_gateway"` |
| `timeout` | `30` | API timeout in seconds |
| `max_workers` | `1` | Parallel workers for multi-zone operations |

### Authentication

Uses [`DefaultAzureCredential`](https://learn.microsoft.com/en-us/python/api/azure-identity/azure.identity.defaultazurecredential) — no token is needed in the config file. Common options:

- **Service principal** (CI/CD): `AZURE_TENANT_ID` + `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET` env vars
- **Managed identity** (Azure VMs, ACI, App Service): assign identity to the resource, grant WAF Contributor role
- **Azure CLI** (local development): run `az login` before octorules commands
- **Certificate** (automated systems): `AZURE_TENANT_ID` + `AZURE_CLIENT_ID` + `AZURE_CLIENT_CERTIFICATE_PATH` env vars

The service principal or managed identity needs the **Contributor** or **Network Contributor** role on the resource group containing WAF policies.

Safety thresholds are configured under `safety:` (framework-owned, not forwarded to the provider):

| Key | Default | Description |
|---|---|---|
| `safety.delete_threshold` | `30.0` | Max % of rules that can be deleted |
| `safety.update_threshold` | `30.0` | Max % of rules that can be updated |
| `safety.min_existing` | `3` | Min rules before thresholds apply |

## Supported features

| Feature | Status | Azure concept |
|---|---|---|
| Phase rules (3 phases) | Supported | Custom rules, rate limit rules, managed rules |
| Policy settings | Supported | WAF mode, request body inspection, file upload limits |
| Custom rulesets | Not supported | Azure has no separate rule group concept |
| Lists (IP Sets) | Not supported | IPs are inline in `matchConditions` (up to 600 per condition) |
| Zone discovery (`list_zones`) | Supported | Lists WAF policies in resource group |
| ETag concurrency control | Supported | Retries on HTTP 412 (concurrent update conflict) |

## Phases

| Phase | Rule Type | Description |
|---|---|---|
| `azure_waf_custom_rules` | `MatchRule` | Standard WAF rules (IP blocks, geo-blocks, header checks, etc.) |
| `azure_waf_rate_rules` | `RateLimitRule` | Rate limiting rules with threshold, duration, and grouping |
| `azure_waf_managed_rules` | Managed | OWASP DRS, Bot Protection rule sets with overrides and exclusions |

## Rule format

The same YAML format works for both Front Door and Application Gateway. The adapter translates API-level differences (field naming, SDK models) transparently.

### Custom rules

```yaml
# rules/api-gateway-waf-policy.yaml
azure_waf_custom_rules:
  # Block specific IP ranges
  - ref: BlockBadIPs
    priority: 1
    action: Block
    matchConditions:
      - matchVariable: RemoteAddr
        operator: IPMatch
        matchValue:
          - 192.168.1.0/24
          - 10.0.0.0/8

  # Block requests with suspicious user-agent
  - ref: BlockBadUserAgents
    priority: 2
    action: Block
    matchConditions:
      - matchVariable: RequestHeader
        selector: User-Agent
        operator: Contains
        matchValue:
          - evilbot
          - scanner
        transforms:
          - Lowercase

  # Geo-block: allow only US and CA
  - ref: GeoBlock
    priority: 3
    action: Block
    matchConditions:
      - matchVariable: RemoteAddr
        operator: GeoMatch
        negateCondition: true
        matchValue:
          - US
          - CA

  # Block requests matching a regex pattern
  - ref: BlockAdminPaths
    priority: 4
    action: Block
    matchConditions:
      - matchVariable: RequestUri
        operator: RegEx
        matchValue:
          - "^/admin/.*\\.php$"
        transforms:
          - Lowercase
```

### Rate-limit rules

```yaml
azure_waf_rate_rules:
  # Rate limit API endpoints to 100 requests per minute per client IP
  - ref: RateLimitAPI
    priority: 100
    action: Block
    ruleType: RateLimitRule
    rateLimitDurationInMinutes: 1
    rateLimitThreshold: 100
    groupBy:
      - variableName: SocketAddr
    matchConditions:
      - matchVariable: RequestUri
        operator: BeginsWith
        matchValue:
          - /api/
```

### Rule fields reference

| Field | Type | Required | Description |
|---|---|---|---|
| `ref` | string | Yes | Rule name (letters, digits, underscores; max 128 chars) |
| `priority` | int | Yes | Evaluation order (positive int, lower = first; must be unique across all rules) |
| `action` | string | Yes | `Allow`, `Block`, `Log`, `Redirect`, `AnomalyScoring`, or `JSChallenge` |
| `enabledState` | string | No | `Enabled` (default) or `Disabled` |
| `ruleType` | string | No | `MatchRule` (default) or `RateLimitRule` |
| `matchConditions` | list | Yes | One or more conditions (ANDed); max 10 per rule |
| `rateLimitDurationInMinutes` | int | RateLimitRule | `1` or `5` (time window) |
| `rateLimitThreshold` | int | RateLimitRule | Requests per client in the window (10 — 1,000,000) |
| `groupBy` | list | No | Rate limit grouping: `SocketAddr`, `GeoLocation`, or `None` |

### Match condition fields

| Field | Type | Description |
|---|---|---|
| `matchVariable` | string | What to match: `RemoteAddr`, `SocketAddr`, `RequestMethod`, `QueryString`, `PostArgs`, `RequestUri`, `RequestHeader`, `RequestBody`, `Cookies` |
| `selector` | string | Header/cookie/post-arg name (required for `RequestHeader`, `Cookies`, `PostArgs`) |
| `operator` | string | `Any`, `IPMatch`, `GeoMatch`, `Equal`, `Contains`, `BeginsWith`, `EndsWith`, `RegEx`, `LessThan`, `GreaterThan`, `LessThanOrEqual`, `GreaterThanOrEqual`, `ServiceTagMatch` |
| `negateCondition` | bool | Invert the match (default: `false`) |
| `matchValue` | list | Values to match against (max 600 for IPMatch, 10 for string operators) |
| `transforms` | list | Pre-processing: `Lowercase`, `Uppercase`, `Trim`, `UrlDecode`, `UrlEncode`, `RemoveNulls`, `HtmlEntityDecode` |

## WAF Type Differences

The adapter pattern handles all API differences transparently. Users write identical YAML regardless of `waf_type`:

| Feature | Front Door | Application Gateway |
|---|---|---|
| **Scope** | Global (edge CDN) | Regional (reverse proxy) |
| **Propagation** | Up to 45 minutes | Seconds to minutes |
| **SDK** | `azure-mgmt-frontdoor` | `azure-mgmt-network` |
| **Update model** | Async LRO (`begin_create_or_update`) | Synchronous (`create_or_update`) |
| **Extra actions** | Redirect, AnomalyScoring | -- |
| **Extra transforms** | -- | HtmlEntityDecode |
| **Extra operators** | ServiceTagMatch | -- |
| **Match variable names** | `RequestHeader`, `Cookies` | `RequestHeaders`, `RequestCookies` (adapter maps) |
| **Negation field** | `negateCondition` | `negationConditon` (API typo; adapter maps) |

## Linting

73 lint rules with `AZ` prefix covering structure, priority, action, match conditions, rate limits, cross-rule analysis, best practices, and managed rule sets. See [`docs/lint.md`](docs/lint.md) for the full reference with examples.

```bash
octorules lint --config config.yaml
```

## Known limitations

- **Front Door propagation delay**: Configuration changes can take up to 45 minutes to propagate to all edge nodes globally. Plan accordingly for production deployments.
- **No PATCH API**: Azure WAF uses full-policy PUT. octorules always fetches the current policy first and merges changes, but concurrent external modifications during sync could conflict (mitigated by ETag retry).
- **No custom rulesets or lists**: Azure WAF has no equivalent of AWS Rule Groups or IP Sets. IP addresses are inline in `matchConditions` (max 600 per condition, 60,000 across all rules).
- **Regex limit**: Maximum 5 custom rules using the `RegEx` operator per policy.
- **Priority must be globally unique**: Rule priorities must be unique across ALL custom rules in a policy (both MatchRule and RateLimitRule combined), not just within a phase.

## Development

```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest tests/ -v
.venv/bin/ruff check octorules_azure/ tests/
.venv/bin/ruff format --check octorules_azure/ tests/
```

Pre-commit hook:

```bash
ln -sf ../../scripts/hooks/pre-commit .git/hooks/pre-commit
```

## License

Apache-2.0
