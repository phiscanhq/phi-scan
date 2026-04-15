"""Plugins command group — phi-scan plugins <subcommand>."""

from __future__ import annotations

import json

import typer
from rich import box as rich_box
from rich.markup import escape as escape_rich_markup
from rich.table import Table

from phi_scan.constants import EXIT_CODE_CLEAN
from phi_scan.output import get_console
from phi_scan.plugin_loader import (
    LoadedPlugin,
    LoadedSuppressor,
    PluginRegistry,
    SkippedPlugin,
    discover_plugin_registry,
)

__all__ = ["plugins_app"]

plugins_app = typer.Typer(
    name="plugins",
    help="Discover and inspect installed recognizer plugins.",
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_NO_PLUGINS_MESSAGE: str = "No recognizer plugins discovered."
_NO_SUPPRESSORS_MESSAGE: str = "No suppressor plugins discovered."

_STATUS_LOADED: str = "loaded"
_STATUS_SKIPPED: str = "skipped-invalid"

_TABLE_TITLE: str = "Installed Recognizer Plugins"
_SUPPRESSOR_TABLE_TITLE: str = "Installed Suppressor Plugins"
_COLUMN_NAME: str = "Name"
_COLUMN_VERSION: str = "Version"
_COLUMN_API_VERSION: str = "API Version"
_COLUMN_ENTITY_TYPES: str = "Entity Types"
_COLUMN_STATUS: str = "Status"

_ENTITY_TYPE_SEPARATOR: str = ", "
_EMPTY_CELL: str = ""

_JSON_KEY_PLUGINS: str = "plugins"
_JSON_KEY_SUPPRESSORS: str = "suppressors"
_JSON_KEY_NAME: str = "name"
_JSON_KEY_VERSION: str = "version"
_JSON_KEY_API_VERSION: str = "api_version"
_JSON_KEY_ENTITY_TYPES: str = "entity_types"
_JSON_KEY_STATUS: str = "status"
_JSON_KEY_REASON: str = "reason"
_JSON_KEY_DISTRIBUTION: str = "distribution"
_JSON_KEY_ENTRY_POINT: str = "entry_point"

_JSON_INDENT: int = 2


# ---------------------------------------------------------------------------
# Public command
# ---------------------------------------------------------------------------


@plugins_app.command("list")
def list_plugins(
    is_json_output: bool = typer.Option(
        False,
        "--json",
        help="Output plugin list as machine-readable JSON.",
    ),
) -> None:
    """Discover installed recognizer plugins and display their metadata."""
    registry = discover_plugin_registry()
    if is_json_output:
        _print_json_output(registry)
    else:
        _print_table_output(registry)
    raise typer.Exit(code=EXIT_CODE_CLEAN)


# ---------------------------------------------------------------------------
# Table output
# ---------------------------------------------------------------------------


def _print_table_output(registry: PluginRegistry) -> None:
    _print_recognizer_table(registry)
    _print_suppressor_table(registry)


def _print_recognizer_table(registry: PluginRegistry) -> None:
    if not registry.loaded and not registry.skipped:
        get_console().print(_NO_PLUGINS_MESSAGE)
        return
    table = _build_plugin_table(registry)
    get_console().print(table)


def _print_suppressor_table(registry: PluginRegistry) -> None:
    if not registry.loaded_suppressors and not registry.skipped_suppressors:
        get_console().print(_NO_SUPPRESSORS_MESSAGE)
        return
    table = _build_suppressor_table(registry)
    get_console().print(table)


def _build_suppressor_table(registry: PluginRegistry) -> Table:
    table = Table(
        title=_SUPPRESSOR_TABLE_TITLE,
        box=rich_box.ROUNDED,
        show_lines=True,
    )
    table.add_column(_COLUMN_NAME, style="bold")
    table.add_column(_COLUMN_VERSION)
    table.add_column(_COLUMN_API_VERSION)
    table.add_column(_COLUMN_STATUS)
    for loaded_suppressor in registry.loaded_suppressors:
        _add_loaded_suppressor_row(table, loaded_suppressor)
    for skipped_suppressor in registry.skipped_suppressors:
        _add_skipped_suppressor_row(table, skipped_suppressor)
    return table


def _add_loaded_suppressor_row(table: Table, loaded_suppressor: LoadedSuppressor) -> None:
    suppressor = loaded_suppressor.suppressor
    table.add_row(
        suppressor.name,
        suppressor.version,
        suppressor.plugin_api_version,
        f"[green]{_STATUS_LOADED}[/green]",
    )


def _add_skipped_suppressor_row(table: Table, skipped_suppressor: SkippedPlugin) -> None:
    table.add_row(
        skipped_suppressor.entry_point_name,
        _EMPTY_CELL,
        _EMPTY_CELL,
        f"[red]{_STATUS_SKIPPED}: {escape_rich_markup(skipped_suppressor.reason)}[/red]",
    )


def _build_plugin_table(registry: PluginRegistry) -> Table:
    table = Table(
        title=_TABLE_TITLE,
        box=rich_box.ROUNDED,
        show_lines=True,
    )
    table.add_column(_COLUMN_NAME, style="bold")
    table.add_column(_COLUMN_VERSION)
    table.add_column(_COLUMN_API_VERSION)
    table.add_column(_COLUMN_ENTITY_TYPES)
    table.add_column(_COLUMN_STATUS)
    for loaded_plugin in registry.loaded:
        _add_loaded_row(table, loaded_plugin)
    for skipped_plugin in registry.skipped:
        _add_skipped_row(table, skipped_plugin)
    return table


def _add_loaded_row(table: Table, loaded_plugin: LoadedPlugin) -> None:
    recognizer = loaded_plugin.recognizer
    table.add_row(
        recognizer.name,
        recognizer.version,
        recognizer.plugin_api_version,
        _ENTITY_TYPE_SEPARATOR.join(recognizer.entity_types),
        f"[green]{_STATUS_LOADED}[/green]",
    )


def _add_skipped_row(table: Table, skipped_plugin: SkippedPlugin) -> None:
    table.add_row(
        skipped_plugin.entry_point_name,
        _EMPTY_CELL,
        _EMPTY_CELL,
        _EMPTY_CELL,
        f"[red]{_STATUS_SKIPPED}: {escape_rich_markup(skipped_plugin.reason)}[/red]",
    )


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------


def _print_json_output(registry: PluginRegistry) -> None:
    plugin_records = _build_json_records(registry)
    suppressor_records = _build_suppressor_json_records(registry)
    serialized_output = json.dumps(
        {
            _JSON_KEY_PLUGINS: plugin_records,
            _JSON_KEY_SUPPRESSORS: suppressor_records,
        },
        indent=_JSON_INDENT,
    )
    get_console().print(serialized_output, highlight=False)


def _build_json_records(registry: PluginRegistry) -> list[dict[str, object]]:
    loaded_records = [_serialize_loaded_plugin(lp) for lp in registry.loaded]
    skipped_records = [_serialize_skipped_plugin(sp) for sp in registry.skipped]
    return loaded_records + skipped_records


def _build_suppressor_json_records(registry: PluginRegistry) -> list[dict[str, object]]:
    loaded_records = [_serialize_loaded_suppressor(ls) for ls in registry.loaded_suppressors]
    skipped_records = [_serialize_skipped_plugin(sp) for sp in registry.skipped_suppressors]
    return loaded_records + skipped_records


def _serialize_loaded_suppressor(loaded_suppressor: LoadedSuppressor) -> dict[str, object]:
    suppressor = loaded_suppressor.suppressor
    return {
        _JSON_KEY_NAME: suppressor.name,
        _JSON_KEY_VERSION: suppressor.version,
        _JSON_KEY_API_VERSION: suppressor.plugin_api_version,
        _JSON_KEY_STATUS: _STATUS_LOADED,
        _JSON_KEY_DISTRIBUTION: loaded_suppressor.distribution_name,
        _JSON_KEY_ENTRY_POINT: loaded_suppressor.entry_point_name,
    }


def _serialize_loaded_plugin(loaded_plugin: LoadedPlugin) -> dict[str, object]:
    recognizer = loaded_plugin.recognizer
    return {
        _JSON_KEY_NAME: recognizer.name,
        _JSON_KEY_VERSION: recognizer.version,
        _JSON_KEY_API_VERSION: recognizer.plugin_api_version,
        _JSON_KEY_ENTITY_TYPES: list(recognizer.entity_types),
        _JSON_KEY_STATUS: _STATUS_LOADED,
        _JSON_KEY_DISTRIBUTION: loaded_plugin.distribution_name,
        _JSON_KEY_ENTRY_POINT: loaded_plugin.entry_point_name,
    }


def _serialize_skipped_plugin(skipped_plugin: SkippedPlugin) -> dict[str, object]:
    return {
        _JSON_KEY_NAME: skipped_plugin.entry_point_name,
        _JSON_KEY_STATUS: _STATUS_SKIPPED,
        _JSON_KEY_REASON: skipped_plugin.reason,
        _JSON_KEY_DISTRIBUTION: skipped_plugin.distribution_name,
        _JSON_KEY_ENTRY_POINT: skipped_plugin.entry_point_name,
    }
