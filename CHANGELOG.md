# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.10] - 2026-04-29

### Added
- **AZ339** (cross_rule, WARNING): overlapping CIDR across rules in the
  same phase. Detects silent rule shadowing — when one rule's IPMatch
  contains another's, the broader rule wins by priority and the
  narrower one never fires. Uses an `O(n log n)` sweep-line over
  `IPMatch` conditions grouped by `(matchVariable, ip_version)`.
  Mirrors CF478 (Cloudflare), WA164 (AWS), GA305 (Google), BN307
  (Bunny). Covered by 15 dedicated tests.

### Changed
- **AZ319 severity bumped from INFO to WARNING** to align with peer
  reserved/bogon-IP rules (CF530, WA162, GA320, BN305 — all WARNING).
  No detection-logic change; only the severity.
- `FrontDoorAdapter.put_policy` caps the long-running-operation
  poller at 5 minutes. Previously the SDK default applied (infinite
  wait), so a network partition during async LRO polling could hang
  `octorules sync` indefinitely.

### Fixed
- `AzureWafProvider.zone_plans` now returns a snapshot copy of the
  internal mapping. Callers can no longer mutate the provider's
  cached SKU-tier state by accident (matches Cloudflare/Google/Bunny
  contracts).

## [0.1.8] - 2026-04-18

### Changed
- **AZ319 narrowed to strict containment** (aligned with
  CF/AWS/Google/Bunny). Previously used a bidirectional overlap check
  that double-flagged catch-all CIDRs (``0.0.0.0/0`` / ``::/0``,
  already covered by AZ322) and produced false positives for public
  supernets that happened to engulf reserved ranges (e.g.
  ``8.0.0.0/4``). Catch-alls are now exclusively handled by AZ322,
  and arbitrary public supernets are no longer flagged. Configs with
  unusual supernets will stop seeing AZ319 warnings on them.
- Minimum ``octorules`` dependency: ``>=0.26.0`` (was ``>=0.24.0``).

## [0.1.7] - 2026-04-13

### Changed
- AZ200, AZ005, AZ006, AZ400, AZ702, AZ703, AZ707: Valid options moved to
  `suggestion` field for better SARIF/IDE integration.
- Reserved IP list expanded from 9 to 28 networks (adds documentation,
  benchmark, multicast, IPv6 ranges).
- Explicit `RULE_IDS` per validator module for dead-rule detection.

## [0.1.6] - 2026-04-10

### Changed
- Policy settings and managed exclusions registration is now thread-safe
  (registration calls moved inside `threading.Lock`, `_registered` set last).
- Linter rule registration is now thread-safe (`threading.Lock`).

### Removed
- Unused `format_plan` and `count_changes` methods from
  `PolicySettingsFormatter` and `ManagedExclusionsFormatter`.

## [0.1.5] - 2026-04-09

### Fixed
- `azure_waf_managed_exclusions` now rejected during validation when
  WAF type is `front_door` (managed exclusions are only supported on
  Application Gateway).  Previously, the config was silently accepted
  during plan and failed at apply time.
- README test count updated (626 → 650).

### Changed
- Extension registration guards now use `threading.Lock` for correctness.
- Pre-commit hook now runs `yamllint` on workflow files.

## [0.1.4] - 2026-04-08

### Added
- AZ023 lint rule: "Rule entry is not a dict" (ERROR)
- AZ024 lint rule: "Phase value is not a list" (ERROR)

### Changed
- README heading capitalization normalized to sentence case
- README em dashes standardized

## [0.1.3] - 2026-04-07

### Added
- Debug logging across provider operations — resolve, get/put phase rules,
  extension hooks, and list/ruleset operations are now visible with `--debug`.

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
