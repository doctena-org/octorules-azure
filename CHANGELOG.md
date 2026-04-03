# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-04-03

### Added

- Azure WAF provider supporting both Front Door WAF and Application Gateway WAF
- Adapter pattern isolating SDK differences between Front Door and App Gateway
- Unified YAML format -- same rule syntax regardless of `waf_type`
- Phase support: `azure_waf_custom_rules` (MatchRule) and `azure_waf_rate_rules` (RateLimitRule)
- 59 lint rules (AZ001-AZ603) covering structure, priority, actions, match conditions, rate limits, cross-rule analysis, and best practices
- Catch-all and dead rule detection (including IPMatch with 0.0.0.0/0)
- Cross-phase validation (priority uniqueness, regex count, total rule count)
- Audit extension for IP range extraction from IPMatch conditions
- ETag-based concurrency control with automatic retry on HTTP 412
- Zone discovery via `list_zones()`
- 368 tests
