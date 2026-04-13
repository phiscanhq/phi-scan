"""Config command group — phi-scan config <subcommand>."""

from __future__ import annotations

from pathlib import Path

import typer

from phi_scan.config import create_default_config
from phi_scan.constants import DEFAULT_CONFIG_FILENAME, EXIT_CODE_CLEAN

config_app = typer.Typer(name="config", help="Manage PhiScan configuration.")

_CONFIG_CREATED_MESSAGE: str = "Configuration file created: {path}"
_CONFIG_ALREADY_EXISTS_MESSAGE: str = "Config file already exists at {path} — not overwriting."


@config_app.command("init")
def initialize_config() -> None:
    """Generate a default .phi-scanner.yml configuration file."""
    config_file_path = Path(DEFAULT_CONFIG_FILENAME)
    if config_file_path.exists():
        typer.echo(_CONFIG_ALREADY_EXISTS_MESSAGE.format(path=config_file_path))
        raise typer.Exit(code=EXIT_CODE_CLEAN)
    create_default_config(config_file_path)
    typer.echo(_CONFIG_CREATED_MESSAGE.format(path=config_file_path))
