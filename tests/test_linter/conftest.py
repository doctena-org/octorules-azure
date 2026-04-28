"""Shared fixtures for the Azure linter test suite.

Assertion helpers (``assert_lint``, ``assert_no_lint``) live in
``octorules.testing.lint``; this conftest only ensures Azure rules are
registered before tests run.
"""

from octorules_azure.linter import register_azure_linter

# Ensure Azure linter rules are registered before any test in this directory runs.
register_azure_linter()
