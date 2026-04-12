"""Tests for phi_scan.plugin_api and phi_scan.plugin_loader (Plugin API v1).

The loader tests install synthetic ``EntryPoint`` stand-ins by
monkey-patching ``phi_scan.plugin_loader.entry_points`` so the suite
exercises the full discover / validate / instantiate / register
pipeline without needing to build installable fixture packages.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from phi_scan import (
    PLUGIN_API_VERSION,
    BaseRecognizer,
    ScanContext,
    ScanFinding,
)
from phi_scan.plugin_api import RECOGNIZER_NAME_PATTERN
from phi_scan.plugin_loader import (
    PLUGIN_ENTRY_POINT_GROUP,
    LoadedPlugin,
    SkippedPlugin,
    load_plugin_registry,
)

_ENTRY_POINTS_PATCH_TARGET: str = "phi_scan.plugin_loader.entry_points"

_FAKE_DISTRIBUTION_ALPHA: str = "phi-scan-ext-alpha"
_FAKE_DISTRIBUTION_BETA: str = "phi-scan-ext-beta"

_ALPHA_RECOGNIZER_NAME: str = "alpha_recognizer"
_BETA_RECOGNIZER_NAME: str = "beta_recognizer"
_ALPHA_ENTITY_TYPE: str = "ALPHA_IDENTIFIER"
_BETA_ENTITY_TYPE: str = "BETA_IDENTIFIER"

_ALPHA_ENTRY_POINT_NAME: str = "alpha_entry_point"
_BETA_ENTRY_POINT_NAME: str = "beta_entry_point"

_FIXTURES_SUBDIRECTORY: str = "fixtures"
_SAMPLE_FILE_NAME: str = "phi-scan-plugin-test-file.py"
# Deterministic, test-local path. Never opened (per the ScanContext contract);
# used only as metadata so plugins can gate on file extension and line number.
_SAMPLE_FILE_PATH: Path = Path(__file__).parent / _FIXTURES_SUBDIRECTORY / _SAMPLE_FILE_NAME
_SAMPLE_FILE_EXTENSION: str = ".py"
_SAMPLE_LINE_NUMBER: int = 10
_SAMPLE_START_OFFSET: int = 2
_SAMPLE_END_OFFSET: int = 8
_SAMPLE_CONFIDENCE_SCORE: float = 0.85

_VERSION_TWO_POINT_ZERO: str = "2.0"
_BAD_NAME_WITH_HYPHEN: str = "Invalid-Name"
_BAD_ENTITY_TYPE_LOWERCASE: str = "lowercase_type"
_DUPLICATED_ENTITY_TYPE: str = "DUPLICATED_TYPE"
_MALFORMED_RECOGNIZER_NAME: str = "1_starts_with_digit"


class _DistributionStub:
    """Minimal stand-in for ``importlib.metadata.Distribution``."""

    def __init__(self, distribution_name: str) -> None:
        self.name = distribution_name


class _EntryPointStub:
    """Minimal stand-in for ``importlib.metadata.EntryPoint``.

    Only exposes the attributes the loader touches:
    ``name``, ``dist``, and ``load()``.
    """

    def __init__(
        self,
        entry_point_name: str,
        loaded_object: object,
        distribution_name: str | None = None,
        load_error: Exception | None = None,
    ) -> None:
        self.name = entry_point_name
        self._loaded_object = loaded_object
        self._distribution_name = distribution_name
        self._load_error = load_error

    def load(self) -> object:
        if self._load_error is not None:
            raise self._load_error
        return self._loaded_object

    @property
    def dist(self) -> _DistributionStub | None:
        if self._distribution_name is None:
            return None
        return _DistributionStub(self._distribution_name)


def _patch_entry_point_discovery(
    monkeypatch: pytest.MonkeyPatch,
    fake_entry_points: list[_EntryPointStub],
) -> None:
    def _entry_points_replacement(*, group: str) -> list[_EntryPointStub]:
        if group != PLUGIN_ENTRY_POINT_GROUP:
            return []
        return list(fake_entry_points)

    monkeypatch.setattr(_ENTRY_POINTS_PATCH_TARGET, _entry_points_replacement)


class _ValidAlphaRecognizer(BaseRecognizer):
    name = _ALPHA_RECOGNIZER_NAME
    entity_types = [_ALPHA_ENTITY_TYPE]

    def detect(self, line: str, context: ScanContext) -> list[ScanFinding]:
        del line, context
        return []


class _ValidBetaRecognizer(BaseRecognizer):
    name = _BETA_RECOGNIZER_NAME
    entity_types = [_BETA_ENTITY_TYPE]

    def detect(self, line: str, context: ScanContext) -> list[ScanFinding]:
        del line, context
        return []


_TUPLE_RECOGNIZER_NAME: str = "tuple_types_recognizer"
_TUPLE_ENTITY_TYPE: str = "TUPLE_IDENTIFIER"


class _TupleEntityTypesRecognizer(BaseRecognizer):
    name = _TUPLE_RECOGNIZER_NAME
    entity_types = (_TUPLE_ENTITY_TYPE,)

    def detect(self, line: str, context: ScanContext) -> list[ScanFinding]:
        del line, context
        return []


class _MismatchedVersionRecognizer(BaseRecognizer):
    name = "mismatched_version"
    entity_types = ["MISMATCHED_TYPE"]
    plugin_api_version = _VERSION_TWO_POINT_ZERO

    def detect(self, line: str, context: ScanContext) -> list[ScanFinding]:
        del line, context
        return []


class _HyphenNameRecognizer(BaseRecognizer):
    name = _BAD_NAME_WITH_HYPHEN
    entity_types = ["VALID_TYPE"]

    def detect(self, line: str, context: ScanContext) -> list[ScanFinding]:
        del line, context
        return []


class _DigitStartNameRecognizer(BaseRecognizer):
    name = _MALFORMED_RECOGNIZER_NAME
    entity_types = ["VALID_TYPE"]

    def detect(self, line: str, context: ScanContext) -> list[ScanFinding]:
        del line, context
        return []


class _EmptyEntityTypesRecognizer(BaseRecognizer):
    name = "empty_entity_types"
    entity_types: list[str] = []

    def detect(self, line: str, context: ScanContext) -> list[ScanFinding]:
        del line, context
        return []


class _NonListEntityTypesRecognizer(BaseRecognizer):
    name = "non_list_entity_types"
    entity_types = "NOT_A_LIST"  # type: ignore[assignment]

    def detect(self, line: str, context: ScanContext) -> list[ScanFinding]:
        del line, context
        return []


class _LowercaseEntityTypeRecognizer(BaseRecognizer):
    name = "lowercase_entity_type"
    entity_types = [_BAD_ENTITY_TYPE_LOWERCASE]

    def detect(self, line: str, context: ScanContext) -> list[ScanFinding]:
        del line, context
        return []


class _DuplicateEntityTypesRecognizer(BaseRecognizer):
    name = "duplicate_entity_types"
    entity_types = [_DUPLICATED_ENTITY_TYPE, _DUPLICATED_ENTITY_TYPE]

    def detect(self, line: str, context: ScanContext) -> list[ScanFinding]:
        del line, context
        return []


_CONSTRUCTOR_SENSITIVE_MESSAGE: str = "patient_name=Jane Doe MRN=12345"


class _ConstructorRaisingRecognizer(BaseRecognizer):
    name = "constructor_raises"
    entity_types = ["BROKEN_TYPE"]

    def __init__(self) -> None:
        raise RuntimeError(_CONSTRUCTOR_SENSITIVE_MESSAGE)

    def detect(self, line: str, context: ScanContext) -> list[ScanFinding]:
        del line, context
        return []


class _MissingApiVersionRecognizer(BaseRecognizer):
    name = "missing_api_version"
    entity_types = ["VALID_TYPE"]
    plugin_api_version = None  # type: ignore[assignment]

    def detect(self, line: str, context: ScanContext) -> list[ScanFinding]:
        del line, context
        return []


class _MissingNameRecognizer(BaseRecognizer):
    entity_types = ["VALID_TYPE"]

    def detect(self, line: str, context: ScanContext) -> list[ScanFinding]:
        del line, context
        return []


class _MissingEntityTypesRecognizer(BaseRecognizer):
    name = "missing_entity_types"

    def detect(self, line: str, context: ScanContext) -> list[ScanFinding]:
        del line, context
        return []


class _NotARecognizerClass:
    """Plain class that does not inherit from BaseRecognizer."""


def _plain_function_not_a_class() -> None:
    return None


# ---------------------------------------------------------------------------
# ScanFinding and ScanContext __post_init__ validation
# ---------------------------------------------------------------------------


def test_scan_finding_accepts_valid_arguments() -> None:
    finding = ScanFinding(
        entity_type=_ALPHA_ENTITY_TYPE,
        start_offset=_SAMPLE_START_OFFSET,
        end_offset=_SAMPLE_END_OFFSET,
        confidence=_SAMPLE_CONFIDENCE_SCORE,
    )
    assert finding.entity_type == _ALPHA_ENTITY_TYPE
    assert finding.start_offset == _SAMPLE_START_OFFSET
    assert finding.end_offset == _SAMPLE_END_OFFSET
    assert finding.confidence == pytest.approx(_SAMPLE_CONFIDENCE_SCORE)


def test_scan_finding_rejects_lowercase_entity_type() -> None:
    with pytest.raises(ValueError, match="entity_type"):
        ScanFinding(
            entity_type=_BAD_ENTITY_TYPE_LOWERCASE,
            start_offset=_SAMPLE_START_OFFSET,
            end_offset=_SAMPLE_END_OFFSET,
            confidence=_SAMPLE_CONFIDENCE_SCORE,
        )


def test_scan_finding_rejects_negative_start_offset() -> None:
    with pytest.raises(ValueError, match="start_offset"):
        ScanFinding(
            entity_type=_ALPHA_ENTITY_TYPE,
            start_offset=-1,
            end_offset=_SAMPLE_END_OFFSET,
            confidence=_SAMPLE_CONFIDENCE_SCORE,
        )


def test_scan_finding_rejects_end_offset_not_after_start() -> None:
    with pytest.raises(ValueError, match="strictly greater"):
        ScanFinding(
            entity_type=_ALPHA_ENTITY_TYPE,
            start_offset=_SAMPLE_END_OFFSET,
            end_offset=_SAMPLE_END_OFFSET,
            confidence=_SAMPLE_CONFIDENCE_SCORE,
        )


def test_scan_finding_rejects_confidence_above_one() -> None:
    with pytest.raises(ValueError, match="confidence"):
        ScanFinding(
            entity_type=_ALPHA_ENTITY_TYPE,
            start_offset=_SAMPLE_START_OFFSET,
            end_offset=_SAMPLE_END_OFFSET,
            confidence=1.5,
        )


def test_scan_finding_rejects_confidence_below_zero() -> None:
    with pytest.raises(ValueError, match="confidence"):
        ScanFinding(
            entity_type=_ALPHA_ENTITY_TYPE,
            start_offset=_SAMPLE_START_OFFSET,
            end_offset=_SAMPLE_END_OFFSET,
            confidence=-0.1,
        )


def test_scan_context_rejects_zero_line_number() -> None:
    with pytest.raises(ValueError, match="line_number"):
        ScanContext(
            file_path=_SAMPLE_FILE_PATH,
            line_number=0,
            file_extension=_SAMPLE_FILE_EXTENSION,
        )


def test_scan_context_accepts_valid_arguments() -> None:
    context = ScanContext(
        file_path=_SAMPLE_FILE_PATH,
        line_number=_SAMPLE_LINE_NUMBER,
        file_extension=_SAMPLE_FILE_EXTENSION,
    )
    assert context.file_path == _SAMPLE_FILE_PATH
    assert context.line_number == _SAMPLE_LINE_NUMBER
    assert context.file_extension == _SAMPLE_FILE_EXTENSION


# ---------------------------------------------------------------------------
# Happy-path discovery
# ---------------------------------------------------------------------------


def test_empty_entry_point_group_yields_empty_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_entry_point_discovery(monkeypatch, [])
    registry = load_plugin_registry()
    assert registry.loaded == ()
    assert registry.skipped == ()


def test_single_valid_plugin_is_loaded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_entry_point_discovery(
        monkeypatch,
        [
            _EntryPointStub(
                _ALPHA_ENTRY_POINT_NAME,
                _ValidAlphaRecognizer,
                _FAKE_DISTRIBUTION_ALPHA,
            ),
        ],
    )
    registry = load_plugin_registry()
    assert len(registry.loaded) == 1
    assert registry.skipped == ()
    loaded_plugin = registry.loaded[0]
    assert isinstance(loaded_plugin, LoadedPlugin)
    assert loaded_plugin.entry_point_name == _ALPHA_ENTRY_POINT_NAME
    assert loaded_plugin.distribution_name == _FAKE_DISTRIBUTION_ALPHA
    assert isinstance(loaded_plugin.recognizer, _ValidAlphaRecognizer)
    assert loaded_plugin.recognizer.name == _ALPHA_RECOGNIZER_NAME
    assert loaded_plugin.recognizer.entity_types == [_ALPHA_ENTITY_TYPE]


def test_multiple_valid_plugins_are_sorted_deterministically(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_entry_point_discovery(
        monkeypatch,
        [
            _EntryPointStub(
                _BETA_ENTRY_POINT_NAME,
                _ValidBetaRecognizer,
                _FAKE_DISTRIBUTION_BETA,
            ),
            _EntryPointStub(
                _ALPHA_ENTRY_POINT_NAME,
                _ValidAlphaRecognizer,
                _FAKE_DISTRIBUTION_ALPHA,
            ),
        ],
    )
    registry = load_plugin_registry()
    loaded_distribution_names = [
        loaded_plugin.distribution_name for loaded_plugin in registry.loaded
    ]
    assert loaded_distribution_names == [_FAKE_DISTRIBUTION_ALPHA, _FAKE_DISTRIBUTION_BETA]


def test_plugin_without_distribution_still_loads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_entry_point_discovery(
        monkeypatch,
        [_EntryPointStub(_ALPHA_ENTRY_POINT_NAME, _ValidAlphaRecognizer)],
    )
    registry = load_plugin_registry()
    assert len(registry.loaded) == 1
    assert registry.loaded[0].distribution_name is None


# ---------------------------------------------------------------------------
# Validation failures — each produces a SkippedPlugin
# ---------------------------------------------------------------------------


def test_mismatched_api_version_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_entry_point_discovery(
        monkeypatch,
        [
            _EntryPointStub(
                _ALPHA_ENTRY_POINT_NAME,
                _MismatchedVersionRecognizer,
                _FAKE_DISTRIBUTION_ALPHA,
            ),
        ],
    )
    registry = load_plugin_registry()
    assert registry.loaded == ()
    assert len(registry.skipped) == 1
    skipped_plugin = registry.skipped[0]
    assert isinstance(skipped_plugin, SkippedPlugin)
    assert _VERSION_TWO_POINT_ZERO in skipped_plugin.reason
    assert PLUGIN_API_VERSION in skipped_plugin.reason


def test_name_with_hyphen_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_entry_point_discovery(
        monkeypatch,
        [_EntryPointStub(_ALPHA_ENTRY_POINT_NAME, _HyphenNameRecognizer)],
    )
    registry = load_plugin_registry()
    assert registry.loaded == ()
    assert RECOGNIZER_NAME_PATTERN.pattern in registry.skipped[0].reason


def test_name_starting_with_digit_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_entry_point_discovery(
        monkeypatch,
        [_EntryPointStub(_ALPHA_ENTRY_POINT_NAME, _DigitStartNameRecognizer)],
    )
    registry = load_plugin_registry()
    assert registry.loaded == ()
    assert _MALFORMED_RECOGNIZER_NAME in registry.skipped[0].reason


def test_empty_entity_types_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_entry_point_discovery(
        monkeypatch,
        [_EntryPointStub(_ALPHA_ENTRY_POINT_NAME, _EmptyEntityTypesRecognizer)],
    )
    registry = load_plugin_registry()
    assert registry.loaded == ()
    assert "empty" in registry.skipped[0].reason


def test_non_sequence_entity_types_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_entry_point_discovery(
        monkeypatch,
        [_EntryPointStub(_ALPHA_ENTRY_POINT_NAME, _NonListEntityTypesRecognizer)],
    )
    registry = load_plugin_registry()
    assert registry.loaded == ()
    assert "must be a tuple or list" in registry.skipped[0].reason


def test_tuple_entity_types_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_entry_point_discovery(
        monkeypatch,
        [_EntryPointStub(_ALPHA_ENTRY_POINT_NAME, _TupleEntityTypesRecognizer)],
    )
    registry = load_plugin_registry()
    assert registry.skipped == ()
    assert len(registry.loaded) == 1
    assert registry.loaded[0].recognizer.name == _TUPLE_RECOGNIZER_NAME


def test_lowercase_entity_type_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_entry_point_discovery(
        monkeypatch,
        [_EntryPointStub(_ALPHA_ENTRY_POINT_NAME, _LowercaseEntityTypeRecognizer)],
    )
    registry = load_plugin_registry()
    assert registry.loaded == ()
    assert _BAD_ENTITY_TYPE_LOWERCASE in registry.skipped[0].reason


def test_duplicate_entity_types_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_entry_point_discovery(
        monkeypatch,
        [_EntryPointStub(_ALPHA_ENTRY_POINT_NAME, _DuplicateEntityTypesRecognizer)],
    )
    registry = load_plugin_registry()
    assert registry.loaded == ()
    assert "duplicate" in registry.skipped[0].reason


def test_non_recognizer_class_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_entry_point_discovery(
        monkeypatch,
        [_EntryPointStub(_ALPHA_ENTRY_POINT_NAME, _NotARecognizerClass)],
    )
    registry = load_plugin_registry()
    assert registry.loaded == ()
    assert "BaseRecognizer" in registry.skipped[0].reason


def test_non_class_entry_point_target_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_entry_point_discovery(
        monkeypatch,
        [_EntryPointStub(_ALPHA_ENTRY_POINT_NAME, _plain_function_not_a_class)],
    )
    registry = load_plugin_registry()
    assert registry.loaded == ()
    assert "did not resolve to a class" in registry.skipped[0].reason


def test_entry_point_import_error_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_entry_point_discovery(
        monkeypatch,
        [
            _EntryPointStub(
                _ALPHA_ENTRY_POINT_NAME,
                loaded_object=None,
                load_error=ImportError("module missing"),
            ),
        ],
    )
    registry = load_plugin_registry()
    assert registry.loaded == ()
    assert "load failed" in registry.skipped[0].reason


def test_missing_api_version_attribute_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_entry_point_discovery(
        monkeypatch,
        [_EntryPointStub(_ALPHA_ENTRY_POINT_NAME, _MissingApiVersionRecognizer)],
    )
    registry = load_plugin_registry()
    assert registry.loaded == ()
    assert "plugin_api_version" in registry.skipped[0].reason


def test_missing_name_attribute_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_entry_point_discovery(
        monkeypatch,
        [_EntryPointStub(_ALPHA_ENTRY_POINT_NAME, _MissingNameRecognizer)],
    )
    registry = load_plugin_registry()
    assert registry.loaded == ()
    assert "'name'" in registry.skipped[0].reason


def test_missing_entity_types_attribute_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_entry_point_discovery(
        monkeypatch,
        [_EntryPointStub(_ALPHA_ENTRY_POINT_NAME, _MissingEntityTypesRecognizer)],
    )
    registry = load_plugin_registry()
    assert registry.loaded == ()
    assert "entity_types" in registry.skipped[0].reason


def test_recognizer_constructor_failure_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_entry_point_discovery(
        monkeypatch,
        [_EntryPointStub(_ALPHA_ENTRY_POINT_NAME, _ConstructorRaisingRecognizer)],
    )
    registry = load_plugin_registry()
    assert registry.loaded == ()
    skipped_reason = registry.skipped[0].reason
    assert "constructor raised" in skipped_reason
    assert "RuntimeError" in skipped_reason


def test_recognizer_constructor_error_message_is_not_leaked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_entry_point_discovery(
        monkeypatch,
        [_EntryPointStub(_ALPHA_ENTRY_POINT_NAME, _ConstructorRaisingRecognizer)],
    )
    registry = load_plugin_registry()
    skipped_reason = registry.skipped[0].reason
    assert _CONSTRUCTOR_SENSITIVE_MESSAGE not in skipped_reason
    assert "Jane Doe" not in skipped_reason
    assert "12345" not in skipped_reason


# ---------------------------------------------------------------------------
# Name collisions — first wins, second is skipped
# ---------------------------------------------------------------------------


def test_name_collision_first_wins_second_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _AlphaClone(BaseRecognizer):
        name = _ALPHA_RECOGNIZER_NAME
        entity_types = ["CLONE_TYPE"]

        def detect(self, line: str, context: ScanContext) -> list[ScanFinding]:
            del line, context
            return []

    _patch_entry_point_discovery(
        monkeypatch,
        [
            _EntryPointStub(
                _ALPHA_ENTRY_POINT_NAME,
                _ValidAlphaRecognizer,
                _FAKE_DISTRIBUTION_ALPHA,
            ),
            _EntryPointStub(
                _BETA_ENTRY_POINT_NAME,
                _AlphaClone,
                _FAKE_DISTRIBUTION_BETA,
            ),
        ],
    )
    registry = load_plugin_registry()
    assert len(registry.loaded) == 1
    assert registry.loaded[0].distribution_name == _FAKE_DISTRIBUTION_ALPHA
    assert len(registry.skipped) == 1
    assert _ALPHA_RECOGNIZER_NAME in registry.skipped[0].reason
    assert "already registered" in registry.skipped[0].reason


# ---------------------------------------------------------------------------
# Public API re-exports from phi_scan package root
# ---------------------------------------------------------------------------


def test_package_root_reexports_plugin_api_names() -> None:
    import phi_scan

    assert phi_scan.PLUGIN_API_VERSION == PLUGIN_API_VERSION
    assert phi_scan.BaseRecognizer is BaseRecognizer
    assert phi_scan.ScanContext is ScanContext
    assert phi_scan.ScanFinding is ScanFinding
