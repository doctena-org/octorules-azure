"""Tests for ContextVar behaviour in Azure WAF validation.

Proves that ``_WAF_TYPE`` works correctly in single-threaded usage
(set in main, read in main) and documents the isolation semantics: a
child thread does NOT inherit the value set in the parent thread.
"""

import threading

from octorules_azure.validate import _WAF_TYPE, set_waf_type


class TestWafTypeSameThread:
    """ContextVar set+get in the same thread must round-trip."""

    def test_set_then_get(self):
        token = _WAF_TYPE.set("front_door")
        try:
            assert _WAF_TYPE.get() == "front_door"
        finally:
            _WAF_TYPE.reset(token)

    def test_set_via_helper(self):
        """set_waf_type() is the public API; verify it writes the var."""
        orig = _WAF_TYPE.get()
        set_waf_type("front_door")
        try:
            assert _WAF_TYPE.get() == "front_door"
        finally:
            _WAF_TYPE.set(orig)


class TestWafTypeDefault:
    """Without calling set_waf_type, the default must be empty string."""

    def test_default_value(self):
        # Use a fresh thread so there's definitely no prior .set() call
        result = []

        def reader():
            result.append(_WAF_TYPE.get())

        t = threading.Thread(target=reader)
        t.start()
        t.join()

        assert result == [""]


class TestWafTypeThreadIsolation:
    """ContextVar is per-context: child threads do NOT inherit the parent value.

    This is by design — ``contextvars.ContextVar`` copies are opt-in.
    Our usage pattern (set in provider __init__, validate in same thread) is safe.
    A worker thread spawned after `set_waf_type()` sees the *default*,
    not the parent's override.
    """

    def test_child_thread_sees_default_not_parent_value(self):
        token = _WAF_TYPE.set("app_gateway")
        try:
            child_value = []

            def reader():
                child_value.append(_WAF_TYPE.get())

            t = threading.Thread(target=reader)
            t.start()
            t.join()

            # Main thread still sees app_gateway
            assert _WAF_TYPE.get() == "app_gateway"
            # Child thread saw the default (""), NOT "app_gateway"
            assert child_value == [""]
        finally:
            _WAF_TYPE.reset(token)
