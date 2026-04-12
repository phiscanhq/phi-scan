# phi-scan:ignore-file
"""Tests for the plugins command group — phi-scan plugins list.

Exercises the plugin listing command with synthetic entry-point stubs
injected via monkeypatch, covering empty registries, valid plugins,
skipped plugins, deterministic ordering, and JSON output.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner  # phi-scan:ignore

from phi_scan.cli import app
from phi_scan.constants import EXIT_CODE_CLEAN
from phi_scan.plugin_api import PLUGIN_API_VERSION, BaseRecognizer, ScanContext, ScanFinding
from phi_scan.plugin_loader import PLUGIN_ENTRY_POINT_GROUP

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ENTRY_POINTS_PATCH_TARGET: str = "phi_scan.plugin_loader.entry_points"

_ALPHA_DISTRIBUTION: str = "phi-scan-ext-alpha"
_BETA_DISTRIBUTION: str = "phi-scan-ext-beta"

_ALPHA_RECOGNIZER_NAME: str = "alpha_recognizer"
_BETA_RECOGNIZER_NAME: str = "beta_recognizer"
_ALPHA_ENTITY_TYPE: str = "ALPHA_IDENTIFIER"
_BETA_ENTITY_TYPE: str = "BETA_IDENTIFIER"

_ALPHA_ENTRY_POINT_NAME: str = "alpha_entry_point"
_BETA_ENTRY_POINT_NAME: str = "beta_entry_point"
_INVALID_ENTRY_POINT_NAME: str = "invalid_entry_point"

_MISMATCHED_API_VERSION: str = "2.0"
_INVALID_DISTRIBUTION: str = "phi-scan-ext-invalid"

_STATUS_LOADED_LABEL: str = "loaded"
_STATUS_SKIPPED_LABEL: str = "skipped-invalid"

_JSON_KEY_PLUGINS: str = "plugins"
_JSON_KEY_NAME: str = "name"
_JSON_KEY_VERSION: str = "version"
_JSON_KEY_API_VERSION: str = "api_version"
_JSON_KEY_ENTITY_TYPES: str = "entity_types"
_JSON_KEY_STATUS: str = "status"
_JSON_KEY_REASON: str = "reason"
_JSON_KEY_DISTRIBUTION: str = "distribution"
_JSON_KEY_ENTRY_POINT: str = "entry_point"

_EXPECTED_LOADED_JSON_KEYS: frozenset[str] = frozenset(
    {
        _JSON_KEY_NAME,
        _JSON_KEY_VERSION,
        _JSON_KEY_API_VERSION,
        _JSON_KEY_ENTITY_TYPES,
        _JSON_KEY_STATUS,
        _JSON_KEY_DISTRIBUTION,
        _JSON_KEY_ENTRY_POINT,
    }
)

_EXPECTED_SKIPPED_JSON_KEYS: frozenset[str] = frozenset(
    {
        _JSON_KEY_NAME,
        _JSON_KEY_STATUS,
        _JSON_KEY_REASON,
        _JSON_KEY_DISTRIBUTION,
        _JSON_KEY_ENTRY_POINT,
    }
)

_TWO_PLUGIN_COUNT: int = 2

_WIDE_TERMINAL_COLUMNS: str = "200"


# ---------------------------------------------------------------------------
# Stubs — same pattern as test_plugin_loader.py
# ---------------------------------------------------------------------------


class _DistributionStub:
    def __init__(self, distribution_name: str) -> None:
        self.name = distribution_name


class _EntryPointStub:
    def __init__(
        self,
        entry_point_name: str,
        loaded_class: object,
        distribution_name: str | None = None,
    ) -> None:
        self.name = entry_point_name
        self._loaded_class = loaded_class
        self._distribution_name = distribution_name

    def load(self) -> object:
        return self._loaded_class

    @property
    def dist(self) -> _DistributionStub | None:
        if self._distribution_name is None:
            return None
        return _DistributionStub(self._distribution_name)


# ---------------------------------------------------------------------------
# Recognizer stubs
# ---------------------------------------------------------------------------


class _AlphaRecognizer(BaseRecognizer):
    name = _ALPHA_RECOGNIZER_NAME
    entity_types = [_ALPHA_ENTITY_TYPE]

    def detect(self, line: str, context: ScanContext) -> list[ScanFinding]:
        del line, context
        return []


class _BetaRecognizer(BaseRecognizer):
    name = _BETA_RECOGNIZER_NAME
    entity_types = [_BETA_ENTITY_TYPE]

    def detect(self, line: str, context: ScanContext) -> list[ScanFinding]:
        del line, context
        return []


class _MismatchedVersionRecognizer(BaseRecognizer):
    name = "mismatched_version"
    entity_types = ["MISMATCHED_TYPE"]
    plugin_api_version = _MISMATCHED_API_VERSION

    def detect(self, line: str, context: ScanContext) -> list[ScanFinding]:
        del line, context
        return []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_cli_runner = CliRunner()


def _patch_entry_point_discovery(
    monkeypatch: pytest.MonkeyPatch,
    entry_point_stubs: list[_EntryPointStub],
) -> None:
    def _entry_points_replacement(*, group: str) -> list[_EntryPointStub]:
        if group != PLUGIN_ENTRY_POINT_GROUP:
            return []
        return list(entry_point_stubs)

    monkeypatch.setattr(_ENTRY_POINTS_PATCH_TARGET, _entry_points_replacement)


def _invoke_plugins_list(
    monkeypatch: pytest.MonkeyPatch,
    entry_point_stubs: list[_EntryPointStub],
    *,
    is_json: bool = False,
) -> str:
    _patch_entry_point_discovery(monkeypatch, entry_point_stubs)
    monkeypatch.setenv("COLUMNS", _WIDE_TERMINAL_COLUMNS)
    cli_arguments = ["plugins", "list"]
    if is_json:
        cli_arguments.append("--json")
    invocation_result = _cli_runner.invoke(app, cli_arguments)
    assert invocation_result.exit_code == EXIT_CODE_CLEAN
    return invocation_result.output


# ---------------------------------------------------------------------------
# Tests — empty state
# ---------------------------------------------------------------------------


class TestEmptyPluginRegistry:
    def test_no_plugins_shows_empty_message(self, monkeypatch: pytest.MonkeyPatch) -> None:
        output = _invoke_plugins_list(monkeypatch, [])
        assert "No recognizer plugins discovered" in output

    def test_no_plugins_json_returns_empty_list(self, monkeypatch: pytest.MonkeyPatch) -> None:
        output = _invoke_plugins_list(monkeypatch, [], is_json=True)
        parsed_output = json.loads(output)
        assert parsed_output[_JSON_KEY_PLUGINS] == []


# ---------------------------------------------------------------------------
# Tests — valid plugins
# ---------------------------------------------------------------------------


class TestValidPluginsListed:
    def test_single_valid_plugin_shows_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        stubs = [
            _EntryPointStub(_ALPHA_ENTRY_POINT_NAME, _AlphaRecognizer, _ALPHA_DISTRIBUTION),
        ]
        output = _invoke_plugins_list(monkeypatch, stubs)
        assert _ALPHA_RECOGNIZER_NAME in output

    def test_single_valid_plugin_shows_entity_type(self, monkeypatch: pytest.MonkeyPatch) -> None:
        stubs = [
            _EntryPointStub(_ALPHA_ENTRY_POINT_NAME, _AlphaRecognizer, _ALPHA_DISTRIBUTION),
        ]
        output = _invoke_plugins_list(monkeypatch, stubs)
        assert _ALPHA_ENTITY_TYPE in output

    def test_single_valid_plugin_shows_loaded_status(self, monkeypatch: pytest.MonkeyPatch) -> None:
        stubs = [
            _EntryPointStub(_ALPHA_ENTRY_POINT_NAME, _AlphaRecognizer, _ALPHA_DISTRIBUTION),
        ]
        output = _invoke_plugins_list(monkeypatch, stubs)
        assert _STATUS_LOADED_LABEL in output

    def test_multiple_valid_plugins_both_listed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        stubs = [
            _EntryPointStub(_ALPHA_ENTRY_POINT_NAME, _AlphaRecognizer, _ALPHA_DISTRIBUTION),
            _EntryPointStub(_BETA_ENTRY_POINT_NAME, _BetaRecognizer, _BETA_DISTRIBUTION),
        ]
        output = _invoke_plugins_list(monkeypatch, stubs)
        assert _ALPHA_RECOGNIZER_NAME in output
        assert _BETA_RECOGNIZER_NAME in output


# ---------------------------------------------------------------------------
# Tests — skipped / invalid plugins
# ---------------------------------------------------------------------------


class TestSkippedPluginsListed:
    def test_invalid_plugin_shows_skipped_status(self, monkeypatch: pytest.MonkeyPatch) -> None:
        stubs = [
            _EntryPointStub(
                _INVALID_ENTRY_POINT_NAME,
                _MismatchedVersionRecognizer,
                _INVALID_DISTRIBUTION,
            ),
        ]
        output = _invoke_plugins_list(monkeypatch, stubs)
        assert _STATUS_SKIPPED_LABEL in output

    def test_invalid_plugin_shows_reason(self, monkeypatch: pytest.MonkeyPatch) -> None:
        stubs = [
            _EntryPointStub(
                _INVALID_ENTRY_POINT_NAME,
                _MismatchedVersionRecognizer,
                _INVALID_DISTRIBUTION,
            ),
        ]
        output = _invoke_plugins_list(monkeypatch, stubs)
        assert "plugin_api_version" in output

    def test_mixed_valid_and_invalid_both_listed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        stubs = [
            _EntryPointStub(_ALPHA_ENTRY_POINT_NAME, _AlphaRecognizer, _ALPHA_DISTRIBUTION),
            _EntryPointStub(
                _INVALID_ENTRY_POINT_NAME,
                _MismatchedVersionRecognizer,
                _INVALID_DISTRIBUTION,
            ),
        ]
        output = _invoke_plugins_list(monkeypatch, stubs)
        assert _ALPHA_RECOGNIZER_NAME in output
        assert _STATUS_SKIPPED_LABEL in output


# ---------------------------------------------------------------------------
# Tests — deterministic ordering
# ---------------------------------------------------------------------------


class TestDeterministicOrdering:
    def test_plugins_sorted_by_distribution_then_entry_point(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        stubs = [
            _EntryPointStub(_BETA_ENTRY_POINT_NAME, _BetaRecognizer, _BETA_DISTRIBUTION),
            _EntryPointStub(_ALPHA_ENTRY_POINT_NAME, _AlphaRecognizer, _ALPHA_DISTRIBUTION),
        ]
        output = _invoke_plugins_list(monkeypatch, stubs)
        alpha_position = output.index(_ALPHA_RECOGNIZER_NAME)
        beta_position = output.index(_BETA_RECOGNIZER_NAME)
        assert alpha_position < beta_position

    def test_json_ordering_matches_table_ordering(self, monkeypatch: pytest.MonkeyPatch) -> None:
        stubs = [
            _EntryPointStub(_BETA_ENTRY_POINT_NAME, _BetaRecognizer, _BETA_DISTRIBUTION),
            _EntryPointStub(_ALPHA_ENTRY_POINT_NAME, _AlphaRecognizer, _ALPHA_DISTRIBUTION),
        ]
        output = _invoke_plugins_list(monkeypatch, stubs, is_json=True)
        parsed_output = json.loads(output)
        plugin_names = [
            plugin_record[_JSON_KEY_NAME] for plugin_record in parsed_output[_JSON_KEY_PLUGINS]
        ]
        assert plugin_names[0] == _ALPHA_RECOGNIZER_NAME
        assert plugin_names[1] == _BETA_RECOGNIZER_NAME


# ---------------------------------------------------------------------------
# Tests — JSON output
# ---------------------------------------------------------------------------


class TestJsonOutput:
    def test_json_output_is_parseable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        stubs = [
            _EntryPointStub(_ALPHA_ENTRY_POINT_NAME, _AlphaRecognizer, _ALPHA_DISTRIBUTION),
        ]
        output = _invoke_plugins_list(monkeypatch, stubs, is_json=True)
        parsed_output = json.loads(output)
        assert _JSON_KEY_PLUGINS in parsed_output

    def test_loaded_plugin_json_has_expected_keys(self, monkeypatch: pytest.MonkeyPatch) -> None:
        stubs = [
            _EntryPointStub(_ALPHA_ENTRY_POINT_NAME, _AlphaRecognizer, _ALPHA_DISTRIBUTION),
        ]
        output = _invoke_plugins_list(monkeypatch, stubs, is_json=True)
        parsed_output = json.loads(output)
        plugin_record = parsed_output[_JSON_KEY_PLUGINS][0]
        assert frozenset(plugin_record.keys()) == _EXPECTED_LOADED_JSON_KEYS

    def test_loaded_plugin_json_has_correct_metadata(self, monkeypatch: pytest.MonkeyPatch) -> None:
        stubs = [
            _EntryPointStub(_ALPHA_ENTRY_POINT_NAME, _AlphaRecognizer, _ALPHA_DISTRIBUTION),
        ]
        output = _invoke_plugins_list(monkeypatch, stubs, is_json=True)
        parsed_output = json.loads(output)
        plugin_record = parsed_output[_JSON_KEY_PLUGINS][0]
        assert plugin_record[_JSON_KEY_NAME] == _ALPHA_RECOGNIZER_NAME
        assert plugin_record[_JSON_KEY_API_VERSION] == PLUGIN_API_VERSION
        assert plugin_record[_JSON_KEY_ENTITY_TYPES] == [_ALPHA_ENTITY_TYPE]
        assert plugin_record[_JSON_KEY_STATUS] == _STATUS_LOADED_LABEL
        assert plugin_record[_JSON_KEY_DISTRIBUTION] == _ALPHA_DISTRIBUTION

    def test_skipped_plugin_json_has_expected_keys(self, monkeypatch: pytest.MonkeyPatch) -> None:
        stubs = [
            _EntryPointStub(
                _INVALID_ENTRY_POINT_NAME,
                _MismatchedVersionRecognizer,
                _INVALID_DISTRIBUTION,
            ),
        ]
        output = _invoke_plugins_list(monkeypatch, stubs, is_json=True)
        parsed_output = json.loads(output)
        plugin_record = parsed_output[_JSON_KEY_PLUGINS][0]
        assert frozenset(plugin_record.keys()) == _EXPECTED_SKIPPED_JSON_KEYS

    def test_skipped_plugin_json_includes_reason(self, monkeypatch: pytest.MonkeyPatch) -> None:
        stubs = [
            _EntryPointStub(
                _INVALID_ENTRY_POINT_NAME,
                _MismatchedVersionRecognizer,
                _INVALID_DISTRIBUTION,
            ),
        ]
        output = _invoke_plugins_list(monkeypatch, stubs, is_json=True)
        parsed_output = json.loads(output)
        plugin_record = parsed_output[_JSON_KEY_PLUGINS][0]
        assert plugin_record[_JSON_KEY_STATUS] == _STATUS_SKIPPED_LABEL
        assert "plugin_api_version" in plugin_record[_JSON_KEY_REASON]

    def test_mixed_plugins_json_count_matches(self, monkeypatch: pytest.MonkeyPatch) -> None:
        stubs = [
            _EntryPointStub(_ALPHA_ENTRY_POINT_NAME, _AlphaRecognizer, _ALPHA_DISTRIBUTION),
            _EntryPointStub(
                _INVALID_ENTRY_POINT_NAME,
                _MismatchedVersionRecognizer,
                _INVALID_DISTRIBUTION,
            ),
        ]
        output = _invoke_plugins_list(monkeypatch, stubs, is_json=True)
        parsed_output = json.loads(output)
        assert len(parsed_output[_JSON_KEY_PLUGINS]) == _TWO_PLUGIN_COUNT


# ---------------------------------------------------------------------------
# Tests — command integration
# ---------------------------------------------------------------------------


class TestCommandIntegration:
    def test_plugins_list_exits_cleanly(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_entry_point_discovery(monkeypatch, [])
        invocation_result = _cli_runner.invoke(app, ["plugins", "list"])
        assert invocation_result.exit_code == EXIT_CODE_CLEAN

    def test_plugins_help_shows_subcommand(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_entry_point_discovery(monkeypatch, [])
        invocation_result = _cli_runner.invoke(app, ["plugins", "--help"])
        assert "list" in invocation_result.output
