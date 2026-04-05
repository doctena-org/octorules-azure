# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
