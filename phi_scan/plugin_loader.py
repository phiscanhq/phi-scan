"""Plugin discovery and registration for PhiScan recognizer plugins.

Loads third-party plugins that register under the
``phi_scan.plugins`` entry-point group, validates each one against
the Plugin API v1 contract defined in ``phi_scan.plugin_api``, and
returns a ``PluginRegistry`` capturing both the recognizers that
passed validation and the ones that were skipped with the reason.

Load failures are fail-safe: a broken plugin is logged at WARNING
level and added to the skipped list, but never raises. A scan with
no installed plugins is indistinguishable from one where every
installed plugin happened to be invalid — both produce an empty
loaded list and the rest of the scan proceeds unchanged.

PR-1 scope: discover → validate → instantiate → register. Nothing
in this module wires plugins into the scan pipeline yet; that is
done in a follow-up PR that adds ``phi-scan plugins list`` and
plumbs execution through ``detection_coordinator``. The registry
returned here is the hand-off point for that later work.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib.metadata import EntryPoint, entry_points

from phi_scan.exceptions import PluginValidationError
from phi_scan.logging_config import get_logger
from phi_scan.plugin_api import (
    ENTITY_TYPE_PATTERN,
    PLUGIN_API_VERSION,
    RECOGNIZER_NAME_PATTERN,
    BaseRecognizer,
)

__all__ = [
    "LoadedPlugin",
    "PLUGIN_ENTRY_POINT_GROUP",
    "PluginRegistry",
    "SkippedPlugin",
    "load_plugin_registry",
]

PLUGIN_ENTRY_POINT_GROUP: str = "phi_scan.plugins"

_UNKNOWN_DISTRIBUTION_LABEL: str = "<unknown distribution>"

_NOT_A_CLASS_REASON: str = "entry point did not resolve to a class"
_NOT_A_RECOGNIZER_REASON: str = "class does not inherit from BaseRecognizer"
_MISSING_NAME_REASON: str = "class does not declare a 'name' attribute"
_INVALID_NAME_REASON: str = "name {name!r} does not match pattern {pattern}"
_MISSING_ENTITY_TYPES_REASON: str = "class does not declare 'entity_types'"
_ENTITY_TYPES_NOT_LIST_REASON: str = "entity_types must be a list, got {type_name}"
_EMPTY_ENTITY_TYPES_REASON: str = "entity_types is empty — recognizer cannot emit any findings"
_INVALID_ENTITY_TYPE_REASON: str = (
    "entity_types[{index}] {value!r} does not match pattern {pattern}"
)
_DUPLICATE_ENTITY_TYPE_REASON: str = "entity_types contains duplicate entry {value!r}"
_MISSING_API_VERSION_REASON: str = "class does not declare 'plugin_api_version'"
_API_VERSION_MISMATCH_REASON: str = (
    "plugin_api_version {plugin_version!r} does not match host {host_version!r}"
)
_NAME_COLLISION_REASON: str = "name {name!r} already registered by a previous plugin"
_IMPORT_FAILURE_REASON: str = "entry-point load failed with {error_type}"
_INSTANTIATION_FAILURE_REASON: str = "recognizer constructor raised {error_type}"

_SKIPPED_PLUGIN_LOG_MESSAGE: str = "Skipping plugin %r from %s: %s"


@dataclass(frozen=True)
class LoadedPlugin:
    """A recognizer plugin that passed validation and was instantiated.

    Attributes:
        entry_point_name: The ``name`` field on the setuptools entry
            point (left-hand side of the ``name = module:Class``
            line in the publishing package's ``pyproject.toml``).
        distribution_name: Name of the installed distribution that
            provided the entry point, or ``None`` if the metadata
            was unavailable.
        recognizer: The instantiated recognizer, ready to be invoked
            by ``detect(line, context)``.
    """

    entry_point_name: str
    distribution_name: str | None
    recognizer: BaseRecognizer


@dataclass(frozen=True)
class SkippedPlugin:
    """A recognizer plugin that failed validation or instantiation.

    Attributes:
        entry_point_name: Same semantics as ``LoadedPlugin``.
        distribution_name: Same semantics as ``LoadedPlugin``.
        reason: Human-readable description of why the plugin was
            rejected. Safe to display directly in
            ``phi-scan plugins list`` output.
    """

    entry_point_name: str
    distribution_name: str | None
    reason: str


@dataclass(frozen=True)
class PluginRegistry:
    """The result of one plugin-discovery pass over the entry-point group.

    Attributes:
        loaded: Tuple of recognizers that passed validation, in the
            deterministic discovery order (sorted by distribution
            name then entry-point name).
        skipped: Tuple of recognizers that were rejected, in the
            same deterministic order.
    """

    loaded: tuple[LoadedPlugin, ...] = ()
    skipped: tuple[SkippedPlugin, ...] = ()


def load_plugin_registry() -> PluginRegistry:
    """Discover, validate, and instantiate every plugin under the entry-point group.

    Returns:
        A ``PluginRegistry`` with the successfully loaded recognizers
        in ``loaded`` and the rejected ones in ``skipped``. Both
        tuples preserve deterministic discovery order. Never raises;
        all per-plugin failures are converted to ``SkippedPlugin``
        entries and logged at WARNING level.
    """
    sorted_entry_points = _sort_entry_points_deterministically(_discover_entry_points())
    loaded_plugins, skipped_plugins = _collect_plugin_outcomes(sorted_entry_points)
    return PluginRegistry(
        loaded=tuple(loaded_plugins),
        skipped=tuple(skipped_plugins),
    )


def _collect_plugin_outcomes(
    sorted_entry_points: tuple[EntryPoint, ...],
) -> tuple[list[LoadedPlugin], list[SkippedPlugin]]:
    loaded_plugins: list[LoadedPlugin] = []
    skipped_plugins: list[SkippedPlugin] = []
    reserved_names: set[str] = set()
    for entry_point in sorted_entry_points:
        load_outcome = _evaluate_entry_point(entry_point, reserved_names)
        if isinstance(load_outcome, LoadedPlugin):
            loaded_plugins.append(load_outcome)
            reserved_names.add(load_outcome.recognizer.name)
            continue
        skipped_plugins.append(load_outcome)
        _log_skipped_plugin(load_outcome)
    return loaded_plugins, skipped_plugins


def _discover_entry_points() -> tuple[EntryPoint, ...]:
    return tuple(entry_points(group=PLUGIN_ENTRY_POINT_GROUP))


def _sort_entry_points_deterministically(
    discovered_entry_points: tuple[EntryPoint, ...],
) -> tuple[EntryPoint, ...]:
    return tuple(
        sorted(
            discovered_entry_points,
            key=lambda entry_point: (
                _resolve_distribution_name(entry_point) or "",
                entry_point.name,
            ),
        )
    )


def _resolve_distribution_name(entry_point: EntryPoint) -> str | None:
    distribution = entry_point.dist
    if distribution is None:
        return None
    return distribution.name


def _evaluate_entry_point(
    entry_point: EntryPoint,
    reserved_names: set[str],
) -> LoadedPlugin | SkippedPlugin:
    distribution_name = _resolve_distribution_name(entry_point)
    try:
        recognizer_class = _load_entry_point_class(entry_point)
        _validate_recognizer_class(recognizer_class)
        _reject_reserved_name(recognizer_class.name, reserved_names)
        recognizer_instance = _instantiate_recognizer(recognizer_class)
    except PluginValidationError as validation_error:
        return SkippedPlugin(
            entry_point_name=entry_point.name,
            distribution_name=distribution_name,
            reason=str(validation_error),
        )
    return LoadedPlugin(
        entry_point_name=entry_point.name,
        distribution_name=distribution_name,
        recognizer=recognizer_instance,
    )


def _load_entry_point_class(entry_point: EntryPoint) -> type[BaseRecognizer]:
    try:
        loaded_object = entry_point.load()
    except (ImportError, AttributeError) as load_error:
        raise PluginValidationError(
            _IMPORT_FAILURE_REASON.format(error_type=type(load_error).__name__)
        ) from load_error
    if not isinstance(loaded_object, type):
        raise PluginValidationError(_NOT_A_CLASS_REASON)
    if not issubclass(loaded_object, BaseRecognizer):
        raise PluginValidationError(_NOT_A_RECOGNIZER_REASON)
    return loaded_object


def _validate_recognizer_class(recognizer_class: type[BaseRecognizer]) -> None:
    _validate_api_version(recognizer_class)
    _validate_recognizer_name(recognizer_class)
    _validate_entity_types_list(recognizer_class)


def _validate_api_version(recognizer_class: type[BaseRecognizer]) -> None:
    declared_version = getattr(recognizer_class, "plugin_api_version", None)
    if declared_version is None:
        raise PluginValidationError(_MISSING_API_VERSION_REASON)
    if declared_version != PLUGIN_API_VERSION:
        raise PluginValidationError(
            _API_VERSION_MISMATCH_REASON.format(
                plugin_version=declared_version,
                host_version=PLUGIN_API_VERSION,
            )
        )


def _validate_recognizer_name(recognizer_class: type[BaseRecognizer]) -> None:
    declared_name = getattr(recognizer_class, "name", None)
    if declared_name is None:
        raise PluginValidationError(_MISSING_NAME_REASON)
    if not isinstance(declared_name, str) or not RECOGNIZER_NAME_PATTERN.match(declared_name):
        raise PluginValidationError(
            _INVALID_NAME_REASON.format(
                name=declared_name,
                pattern=RECOGNIZER_NAME_PATTERN.pattern,
            )
        )


def _validate_entity_types_list(recognizer_class: type[BaseRecognizer]) -> None:
    declared_types = getattr(recognizer_class, "entity_types", None)
    if declared_types is None:
        raise PluginValidationError(_MISSING_ENTITY_TYPES_REASON)
    if not isinstance(declared_types, list):
        raise PluginValidationError(
            _ENTITY_TYPES_NOT_LIST_REASON.format(type_name=type(declared_types).__name__)
        )
    if not declared_types:
        raise PluginValidationError(_EMPTY_ENTITY_TYPES_REASON)
    _validate_entity_type_values(declared_types)


def _validate_entity_type_values(declared_types: list[str]) -> None:
    seen_entity_types: set[str] = set()
    for type_index, entity_type_value in enumerate(declared_types):
        _reject_malformed_entity_type(type_index, entity_type_value)
        _reject_duplicate_entity_type(entity_type_value, seen_entity_types)
        seen_entity_types.add(entity_type_value)


def _reject_malformed_entity_type(type_index: int, entity_type_value: object) -> None:
    if isinstance(entity_type_value, str) and ENTITY_TYPE_PATTERN.match(entity_type_value):
        return
    raise PluginValidationError(
        _INVALID_ENTITY_TYPE_REASON.format(
            index=type_index,
            value=entity_type_value,
            pattern=ENTITY_TYPE_PATTERN.pattern,
        )
    )


def _reject_duplicate_entity_type(
    entity_type_value: str,
    seen_entity_types: set[str],
) -> None:
    if entity_type_value not in seen_entity_types:
        return
    raise PluginValidationError(_DUPLICATE_ENTITY_TYPE_REASON.format(value=entity_type_value))


def _reject_reserved_name(recognizer_name: str, reserved_names: set[str]) -> None:
    if recognizer_name not in reserved_names:
        return
    raise PluginValidationError(_NAME_COLLISION_REASON.format(name=recognizer_name))


def _instantiate_recognizer(
    recognizer_class: type[BaseRecognizer],
) -> BaseRecognizer:
    # Third-party plugin constructors may raise anything. Catching the full
    # Exception hierarchy is the intentional trust-boundary behaviour: a broken
    # plugin must never crash the scan or leak a raw traceback to the CLI. The
    # exception is re-raised as PluginValidationError so the loader records it
    # in the skipped list and continues. BaseException (SystemExit,
    # KeyboardInterrupt) is deliberately not caught. Only the exception type
    # name is embedded in the reason — the raw message is intentionally
    # dropped because a plugin constructor may have read a value from the
    # environment (env var, file, DB) that could incidentally contain PHI,
    # and the reason string is logged at WARNING level.
    try:
        return recognizer_class()
    except Exception as init_error:  # noqa: BLE001 — see comment above
        raise PluginValidationError(
            _INSTANTIATION_FAILURE_REASON.format(error_type=type(init_error).__name__)
        ) from init_error


def _log_skipped_plugin(skipped_plugin: SkippedPlugin) -> None:
    logger = get_logger("plugin_loader")
    logger.warning(
        _SKIPPED_PLUGIN_LOG_MESSAGE,
        skipped_plugin.entry_point_name,
        skipped_plugin.distribution_name or _UNKNOWN_DISTRIBUTION_LABEL,
        skipped_plugin.reason,
    )
