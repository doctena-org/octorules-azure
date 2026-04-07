# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.2] - 2026-04-07

### Added
- **AZ708** (WARNING): FD-only managed rule override action used with
  Application Gateway — fires when `Redirect` is used as an override action
  with `waf_type: app_gateway`.

### Fixed
- AZ501 no longer counts managed rule sets toward the 100-custom-rule limit
  (only `azure_waf_custom_rules` and `azure_waf_rate_rules` are counted).

## [0.1.1] - 2026-04-06

### Added
- `None` and `JSChallenge` added to valid managed rule override actions.
- `js_challenge_cookie_expiration_in_mins` policy setting support.
- `file_upload_enforcement` AG-only boolean policy setting support.

### Changed
- `Redirect` is now the only FD-only override action (previously all three
  of `Redirect`, `AnomalyScoring`, `JSChallenge` were blocked on AG for
  custom rule actions; override actions now have their own validation).
- `JSChallenge` is no longer FD-only for custom rule actions — removed from
  `_FD_ONLY_ACTIONS`.

## [0.1.0] - 2026-04-05

### Added
- Azure WAF provider supporting both Front Door and Application Gateway
- Adapter pattern isolating SDK differences between Front Door and App Gateway
- Unified YAML format — same rule syntax regardless of `waf_type`
- Phase support: `azure_waf_custom_rules` (MatchRule), `azure_waf_rate_rules`
  (RateLimitRule), and `azure_waf_managed_rules` (managed rule sets with
  per-rule overrides and set-level exclusions)
- `azure_waf_managed_exclusions` extension — manage policy-wide managed rule
  exclusions
- `azure_waf_policy_settings` extension — manage WAF policy settings (mode,
  enabled state, request body inspection, custom block responses, log
  scrubbing)
- 68 lint rules (AZ001–AZ707) covering structure, actions, match conditions,
  rate limits, managed rule sets, cross-rule analysis, and best practices
- Audit extension for IP range extraction from IPMatch conditions
- ETag-based concurrency control with automatic retry on HTTP 412
- Zone discovery via `list_zones()`
- `zone_plans` returns Azure SKU tier; `account_name` returns resource group
- Resilient `get_all_phase_rules` — transient errors populate `failed_phases`
  instead of crashing
