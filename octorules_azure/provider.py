"""Azure WAF provider for octorules.

Maps octorules concepts to Azure WAF policies:
  - Zones -> WAF policies (resolve_zone_id looks up by name)
  - Phases -> Rule types within a policy (custom / rate-limit)
  - Custom rulesets, Lists -> Not supported

Supports both Azure Front Door WAF (``waf_type="front_door"``) and
Application Gateway WAF (``waf_type="app_gateway"``).  The ``waf_type``
parameter selects which internal adapter is used; the provider interface
is identical for both.

Authentication uses ``DefaultAzureCredential`` from ``azure-identity``
(env vars, managed identity, Azure CLI).
"""

import logging
import os
import threading

from azure.core.exceptions import (
    ClientAuthenticationError,
    HttpResponseError,
    ResourceNotFoundError,
    ServiceRequestError,
)
from octorules.config import ConfigError
from octorules.provider.base import PhaseRulesResult, Scope
from octorules.provider.exceptions import ProviderAuthError, ProviderError
from octorules.provider.utils import make_error_wrapper
from octorules.retry import retry_with_backoff

from octorules_azure._adapters import classify_phase, create_adapter
from octorules_azure._phases import AZURE_PHASE_IDS as _AZURE_PHASE_IDS

log = logging.getLogger(__name__)

# Azure error codes that indicate auth/permission problems.
_AUTH_ERROR_CODES = frozenset(
    {
        "AuthenticationFailed",
        "AuthorizationFailed",
        "InvalidAuthenticationTokenTenant",
        "LinkedAuthorizationFailed",
    }
)

# ETag retry config for concurrent PUT conflicts (HTTP 412).
_ETAG_RETRIES = 3
_ETAG_BACKOFF = (0.5, 1.0, 2.0)
_ETAG_JITTER = 0.5

# Transient error retry config for 5xx/429 (separate from ETag conflicts).
_TRANSIENT_BACKOFF = (1.0, 2.0, 4.0)

# HTTP status codes worth retrying — 429 (throttle) plus genuine server errors.
# Notably excludes 501 Not Implemented and 505 HTTP Version Not Supported.
_RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})


def _classify_azure_error(e: Exception) -> type[ProviderAuthError] | None:
    """Check HttpResponseError to determine if it's an auth error."""
    if isinstance(e, HttpResponseError):
        error_obj = getattr(e, "error", None)
        if error_obj is not None:
            code = getattr(error_obj, "code", "")
            if code in _AUTH_ERROR_CODES:
                return ProviderAuthError
    return None


class _NonRetryableError(Exception):
    """Internal: wraps a non-retryable error to escape retry_with_backoff."""


class _ETagMismatchError(ProviderError):
    """Internal: raised on HTTP 412 Precondition Failed (stale ETag).

    Extends ``ProviderError`` so that exhausted retries produce a proper
    provider exception.  Used so that :func:`retry_with_backoff` can catch
    a concrete type while non-ETag errors propagate immediately.
    """


# Azure SKU name -> simplified tier name.
_SKU_TIER_MAP = {
    "Premium_AzureFrontDoor": "premium",
    "Standard_AzureFrontDoor": "standard",
    "Classic_AzureFrontDoor": "classic",
    "WAF_v2": "waf_v2",
}


def _normalize_sku(policy: dict) -> str | None:
    """Extract and normalize the SKU tier from a policy dict.

    Returns ``None`` if no SKU information is present.
    """
    sku = policy.get("sku")
    if not isinstance(sku, dict):
        return None
    name = sku.get("name")
    if not name:
        return None
    return _SKU_TIER_MAP.get(name, name.lower())


_wrap_provider_errors = make_error_wrapper(
    auth_errors=(ClientAuthenticationError,),
    connection_errors=(ServiceRequestError, ConnectionError),
    generic_errors=(HttpResponseError,),
    classify=_classify_azure_error,
)


class AzureWafProvider:
    """Azure WAF provider for octorules.

    Maps octorules concepts to Azure WAF:
      - Zones -> WAF policies (resolve_zone_id looks up by name)
      - Phases -> Rule types (custom / rate-limit)
      - Custom rulesets, Lists -> Not supported

    Authentication uses ``DefaultAzureCredential`` (env vars, managed
    identity, Azure CLI, etc.).  The ``waf_type`` parameter selects
    between Front Door WAF and Application Gateway WAF.
    """

    SUPPORTS = frozenset({"zone_discovery"})

    def __init__(
        self,
        *,
        max_workers: int = 1,
        timeout: float | None = None,
        subscription_id: str | None = None,
        resource_group: str | None = None,
        waf_type: str | None = None,
        client: object = None,
        **_extra: object,
    ) -> None:
        self._subscription_id = subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID", "")
        if not self._subscription_id:
            raise ConfigError(
                "Azure subscription_id not specified"
                " (set 'subscription_id' in provider config or AZURE_SUBSCRIPTION_ID env var)"
            )

        self._resource_group = resource_group or os.environ.get("AZURE_RESOURCE_GROUP", "")
        if not self._resource_group:
            raise ConfigError(
                "Azure resource_group not specified"
                " (set 'resource_group' in provider config or AZURE_RESOURCE_GROUP env var)"
            )

        self._timeout = timeout if timeout is not None else 30

        waf_type_str = waf_type or os.environ.get("AZURE_WAF_TYPE", "front_door")
        self._waf_type = waf_type_str
        self._adapter = create_adapter(waf_type_str)

        from octorules_azure.validate import set_waf_type

        set_waf_type(waf_type_str)

        if client is not None:
            self._client = client
        else:
            from azure.identity import DefaultAzureCredential

            credential = DefaultAzureCredential()
            self._client = self._adapter.get_client(
                credential,
                self._subscription_id,
                connection_timeout=self._timeout,
                read_timeout=self._timeout,
            )

        self._max_workers = max_workers
        self._lock = threading.Lock()
        self._zone_plans: dict[str, str] = {}

    # -- Properties --

    @property
    def max_workers(self) -> int:
        """Maximum number of concurrent workers for parallel operations."""
        return self._max_workers

    @property
    def account_id(self) -> str | None:
        """Return the Azure subscription ID."""
        return self._subscription_id

    @property
    def account_name(self) -> str | None:
        """Return the Azure resource group name."""
        return self._resource_group

    @property
    def zone_plans(self) -> dict[str, str]:
        """Zone name -> normalized SKU tier, populated during resolve_zone_id."""
        return self._zone_plans

    # -- Internal helpers --

    def _with_etag_retry(self, operation: object, label: str) -> object:
        """Run *operation()* with ETag-mismatch retry on HTTP 412.

        Azure returns 412 Precondition Failed when the ETag in the
        ``If-Match`` header doesn't match the current resource.  This
        indicates a concurrent update; we retry by re-fetching and
        re-merging.
        """

        def _guarded_op():
            try:
                return operation()
            except HttpResponseError as e:
                if e.status_code == 412:
                    raise _ETagMismatchError(str(e)) from e
                raise

        return retry_with_backoff(
            _guarded_op,
            retryable=(_ETagMismatchError,),
            max_attempts=_ETAG_RETRIES,
            backoff=_ETAG_BACKOFF,
            jitter=_ETAG_JITTER,
            label=f"ETag retry for {label}",
        )

    def _retry_transient(self, fn, *, label: str):
        """Call *fn* with retry on transient Azure errors.

        Auth and not-found errors propagate immediately.  Only status
        codes in ``_RETRYABLE_STATUS_CODES`` (429, 500, 502, 503, 504)
        are retried; other errors (e.g. 501 Not Implemented) propagate.
        """
        # Non-retryable Azure errors (auth, not-found, 4xx client errors).
        # These are wrapped in _NonRetryable so they escape retry_with_backoff
        # even though they inherit from HttpResponseError.
        _NO_RETRY = (ClientAuthenticationError, ResourceNotFoundError)

        def _guarded():
            try:
                return fn()
            except _NO_RETRY as e:
                raise _NonRetryableError(e) from e
            except HttpResponseError as e:
                if e.status_code and e.status_code not in _RETRYABLE_STATUS_CODES:
                    raise _NonRetryableError(e) from e
                raise  # retryable status codes fall through to retry

        try:
            return retry_with_backoff(
                _guarded,
                retryable=(HttpResponseError, ServiceRequestError, ConnectionError),
                max_attempts=3,
                backoff=_TRANSIENT_BACKOFF,
                label=label,
            )
        except _NonRetryableError as wrapper:
            raise wrapper.__cause__ from None

    # -- Zone resolution --

    @_wrap_provider_errors
    def resolve_zone_id(self, zone_name: str) -> str:
        """Resolve a WAF policy name to its zone ID.

        In Azure, the policy name *is* the zone ID.  This method verifies
        the policy exists and extracts the SKU tier for ``zone_plans``.

        Raises ConfigError if the policy is not found.
        """
        try:
            policy = self._retry_transient(
                lambda: self._adapter.get_policy(self._client, self._resource_group, zone_name),
                label=f"resolve {zone_name}",
            )
        except ResourceNotFoundError:
            raise ConfigError(
                f"WAF policy {zone_name!r} not found in resource group {self._resource_group!r}"
            ) from None
        tier = _normalize_sku(policy)
        if tier is not None:
            with self._lock:
                self._zone_plans[zone_name] = tier
        log.debug("Resolved zone %s in resource group %s", zone_name, self._resource_group)
        return zone_name

    @_wrap_provider_errors
    def list_zones(self) -> list[str]:
        """List all WAF policy names in the resource group."""
        return self._retry_transient(
            lambda: self._adapter.list_policies(self._client, self._resource_group),
            label="list zones",
        )

    # -- Phase rules --

    @_wrap_provider_errors
    def get_phase_rules(self, scope: Scope, provider_id: str) -> list[dict]:
        """Get rules from a WAF policy filtered by phase type."""
        if provider_id not in _AZURE_PHASE_IDS:
            return []
        policy = self._retry_transient(
            lambda: self._adapter.get_policy(self._client, self._resource_group, scope.zone_id),
            label=f"get_phase_rules {scope.zone_id}",
        )
        if provider_id == "azure_waf_managed":
            raw = self._adapter.extract_managed_rules(policy)
            result = [self._adapter.normalize_managed_rule(rs) for rs in raw]
        else:
            raw_rules = self._adapter.extract_custom_rules(policy)
            result = []
            for r in raw_rules:
                normalised = self._adapter.normalize_rule(r)
                if classify_phase(normalised) == provider_id:
                    result.append(normalised)
        log.debug("get_phase_rules %s/%s: %d rules", scope.zone_id, provider_id, len(result))
        return result

    @_wrap_provider_errors
    def put_phase_rules(self, scope: Scope, provider_id: str, rules: list[dict]) -> int:
        """Replace rules of a specific phase type in a WAF policy.

        Azure WAF requires updating the entire policy atomically.  This
        method preserves rules belonging to other phases and managed rules,
        replacing only those matching ``provider_id``.

        Retries on HTTP 412 (ETag mismatch) by re-fetching and re-merging.
        """
        if provider_id == "azure_waf_managed":
            new_managed = [self._adapter.denormalize_managed_rule(r) for r in rules]

            def _op_managed() -> int:
                policy = self._adapter.get_policy(self._client, self._resource_group, scope.zone_id)
                updated_policy = self._adapter.replace_managed_rules(policy, new_managed)
                self._adapter.put_policy(
                    self._client, self._resource_group, scope.zone_id, updated_policy
                )
                return len(new_managed)

            count = self._with_etag_retry(_op_managed, f"policy {scope.zone_id}")
        else:
            new_rules = [self._adapter.denormalize_rule(r) for r in rules]

            def _op() -> int:
                policy = self._adapter.get_policy(self._client, self._resource_group, scope.zone_id)
                raw_rules = self._adapter.extract_custom_rules(policy)
                # Keep rules from other phases
                other_rules = [
                    r
                    for r in raw_rules
                    if classify_phase(self._adapter.normalize_rule(r)) != provider_id
                ]
                updated_policy = self._adapter.replace_custom_rules(policy, other_rules + new_rules)
                self._adapter.put_policy(
                    self._client, self._resource_group, scope.zone_id, updated_policy
                )
                return len(new_rules)

            count = self._with_etag_retry(_op, f"policy {scope.zone_id}")
        log.debug(
            "put_phase_rules %s/%s: wrote %d rules",
            scope.zone_id,
            provider_id,
            len(rules),
        )
        return count

    @_wrap_provider_errors
    def get_all_phase_rules(
        self, scope: Scope, *, provider_ids: list[str] | None = None
    ) -> PhaseRulesResult:
        """Fetch rules for all Azure phases from a WAF policy.

        Auth errors (``ClientAuthenticationError``, auth-classified
        ``HttpResponseError``) propagate immediately.  Transient errors
        (5xx, 429, connection) are caught and all requested phases are
        recorded as failed, matching how Cloudflare handles per-phase failures.
        """
        phases_to_fetch = provider_ids if provider_ids is not None else list(_AZURE_PHASE_IDS)
        phases_to_fetch = [p for p in phases_to_fetch if p in _AZURE_PHASE_IDS]

        if not phases_to_fetch:
            return PhaseRulesResult({}, failed_phases=[])

        try:
            policy = self._retry_transient(
                lambda: self._adapter.get_policy(self._client, self._resource_group, scope.zone_id),
                label=f"get_all_phase_rules {scope.zone_id}",
            )
        except ClientAuthenticationError:
            raise
        except (HttpResponseError, ServiceRequestError, ConnectionError) as exc:
            # Check if the HttpResponseError is actually an auth error
            if _classify_azure_error(exc) is ProviderAuthError:
                raise
            log.warning(
                "Failed to fetch policy for %s: %s",
                scope.zone_id,
                exc,
            )
            return PhaseRulesResult({}, failed_phases=list(phases_to_fetch))

        raw_rules = self._adapter.extract_custom_rules(policy)

        result: dict[str, list[dict]] = {}
        for r in raw_rules:
            normalised = self._adapter.normalize_rule(r)
            phase_id = classify_phase(normalised)
            if phase_id in phases_to_fetch:
                result.setdefault(phase_id, []).append(normalised)

        # Extract managed rules if requested
        if "azure_waf_managed" in phases_to_fetch:
            raw_managed = self._adapter.extract_managed_rules(policy)
            if raw_managed:
                result["azure_waf_managed"] = [
                    self._adapter.normalize_managed_rule(rs) for rs in raw_managed
                ]

        return PhaseRulesResult(result, failed_phases=[])

    # -- Unsupported: Custom Rulesets --

    @_wrap_provider_errors
    def list_custom_rulesets(self, scope: Scope) -> list[dict]:
        """Azure WAF has no custom rulesets concept."""
        return []

    @_wrap_provider_errors
    def get_custom_ruleset(self, scope: Scope, ruleset_id: str) -> list[dict]:
        """Azure WAF has no custom rulesets concept."""
        return []

    @_wrap_provider_errors
    def put_custom_ruleset(self, scope: Scope, ruleset_id: str, rules: list[dict]) -> int:
        """Azure WAF has no custom rulesets concept."""
        raise ConfigError("Custom rulesets are not supported by Azure WAF")

    @_wrap_provider_errors
    def create_custom_ruleset(
        self, scope: Scope, name: str, phase: str, capacity: int, description: str = ""
    ) -> dict:
        """Azure WAF has no custom rulesets concept."""
        raise ConfigError("Custom rulesets are not supported by Azure WAF")

    @_wrap_provider_errors
    def delete_custom_ruleset(self, scope: Scope, ruleset_id: str) -> None:
        """Azure WAF has no custom rulesets concept."""
        raise ConfigError("Custom rulesets are not supported by Azure WAF")

    @_wrap_provider_errors
    def get_all_custom_rulesets(
        self, scope: Scope, *, ruleset_ids: list[str] | None = None
    ) -> dict[str, dict]:
        """Azure WAF has no custom rulesets concept."""
        return {}

    # -- Unsupported: Lists --

    @_wrap_provider_errors
    def list_lists(self, scope: Scope) -> list[dict]:
        """Azure WAF has no separate lists API; IPs are inline in matchConditions."""
        return []

    @_wrap_provider_errors
    def create_list(self, scope: Scope, name: str, kind: str, description: str = "") -> dict:
        """Azure WAF has no separate lists API."""
        raise ConfigError("Lists are not supported by Azure WAF")

    @_wrap_provider_errors
    def delete_list(self, scope: Scope, list_id: str) -> None:
        """Azure WAF has no separate lists API."""
        raise ConfigError("Lists are not supported by Azure WAF")

    @_wrap_provider_errors
    def update_list_description(self, scope: Scope, list_id: str, description: str) -> None:
        """Azure WAF has no separate lists API."""
        raise ConfigError("Lists are not supported by Azure WAF")

    @_wrap_provider_errors
    def get_list_items(self, scope: Scope, list_id: str) -> list[dict]:
        """Azure WAF has no separate lists API."""
        return []

    @_wrap_provider_errors
    def put_list_items(self, scope: Scope, list_id: str, items: list[dict]) -> str:
        """Azure WAF has no separate lists API."""
        raise ConfigError("Lists are not supported by Azure WAF")

    @_wrap_provider_errors
    def poll_bulk_operation(
        self, scope: Scope, operation_id: str, *, timeout: float = 120.0
    ) -> str:
        """Azure WAF operations are synchronous -- always returns 'completed'."""
        return "completed"

    @_wrap_provider_errors
    def get_all_lists(
        self, scope: Scope, *, list_names: list[str] | None = None
    ) -> dict[str, dict]:
        """Azure WAF has no separate lists API."""
        return {}

    # -- Policy Settings --

    @_wrap_provider_errors
    def get_policy_settings(self, scope: Scope) -> dict:
        """Fetch and normalize policy settings for a WAF policy."""
        from octorules_azure._policy_settings import normalize_policy_settings

        policy = self._retry_transient(
            lambda: self._adapter.get_policy(self._client, self._resource_group, scope.zone_id),
            label=f"get_policy_settings {scope.zone_id}",
        )
        raw_settings = policy.get("policy_settings") or {}
        return normalize_policy_settings(raw_settings, self._waf_type)

    @_wrap_provider_errors
    def update_policy_settings(self, scope: Scope, settings: dict) -> None:
        """Update policy settings with ETag retry (read-modify-write)."""
        from octorules_azure._policy_settings import denormalize_policy_settings

        def _op():
            policy = self._adapter.get_policy(self._client, self._resource_group, scope.zone_id)
            current_settings = policy.get("policy_settings") or {}
            payload = denormalize_policy_settings(settings, self._waf_type)
            current_settings.update(payload)
            policy["policy_settings"] = current_settings
            self._adapter.put_policy(self._client, self._resource_group, scope.zone_id, policy)

        self._with_etag_retry(_op, f"policy_settings {scope.zone_id}")
        log.debug("Updated policy settings for %s", scope.zone_id)

    # -- Managed Exclusions --

    @_wrap_provider_errors
    def get_managed_exclusions(self, scope: Scope) -> list[dict]:
        """Fetch global managed-rule exclusions for a WAF policy."""
        from octorules_azure._managed_exclusions import normalize_managed_exclusions

        policy = self._retry_transient(
            lambda: self._adapter.get_policy(self._client, self._resource_group, scope.zone_id),
            label=f"get_managed_exclusions {scope.zone_id}",
        )
        return normalize_managed_exclusions(policy)

    @_wrap_provider_errors
    def update_managed_exclusions(self, scope: Scope, exclusions: list[dict]) -> None:
        """Update global managed-rule exclusions with ETag retry (read-modify-write)."""
        from octorules_azure._managed_exclusions import denormalize_managed_exclusions

        def _op():
            policy = self._adapter.get_policy(self._client, self._resource_group, scope.zone_id)
            denormalize_managed_exclusions(policy, exclusions)
            self._adapter.put_policy(self._client, self._resource_group, scope.zone_id, policy)

        self._with_etag_retry(_op, f"managed_exclusions {scope.zone_id}")
        log.debug("Updated managed exclusions for %s", scope.zone_id)
