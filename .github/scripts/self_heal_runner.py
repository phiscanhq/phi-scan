"""
Self-heal runner for GitHub Actions.

Invokes the /self-heal skill via the Claude Agent SDK with hard budget and
turn limits. Replaces the CLI invocation (claude --dangerously-skip-permissions)
so the workflow gets proper cost visibility and structured exit codes.
"""

import asyncio
import os
import sys
from dataclasses import dataclass
from enum import StrEnum

from claude_agent_sdk import AssistantMessage, ClaudeAgentOptions, ResultMessage, query

MAX_BUDGET_USD: float = 15.00
MAX_TURNS: int = 50
MAX_SUMMARY_LENGTH: int = 500
RESULT_OUTPUT_FILE: str = "self_heal_result.txt"
ANTHROPIC_API_KEY_ENV_VAR: str = "ANTHROPIC_API_KEY"

PERMISSION_MODE_BYPASS: str = "bypassPermissions"
DEFAULT_MODEL: str = "claude-sonnet-4-6"
DEFAULT_EFFORT: str = "high"

TOOL_USE_BLOCK_TYPE: str = "tool_use"
TOOL_LOG_PREFIX: str = "  [tool] "

ALLOWED_SDK_TOOLS: tuple[str, ...] = ("Bash", "Read", "Write", "Edit", "Glob", "Grep", "Agent")


class ResultSubtype(StrEnum):
    SUCCESS = "success"
    UNKNOWN = "unknown"
    MAX_BUDGET = "error_max_budget_usd"
    MAX_TURNS = "error_max_turns"


DEFAULT_RESULT_SUBTYPE: ResultSubtype = ResultSubtype.UNKNOWN

EXIT_CODE_SUCCESS: int = 0
EXIT_CODE_FAILURE: int = 1

SELF_HEAL_PROMPT: str = """Execute the /self-heal skill now.

You are running in GitHub Actions as part of the automated PR feedback resolution
and codebase health cycle. Read .claude/skills/self-heal/SKILL.md and follow its
instructions exactly — Phase A if there are open PRs with unresolved review feedback,
Phase B for codebase health, or both if applicable.

You have full autonomy. No human approval is needed for any action including
commits, pushes, PR creation, and merges.

Stack context:
- Package manager: uv (never pip directly)
- Test: uv run pytest tests/ -v --cov=phi_scan
- Lint: uv run ruff check . --fix && uv run ruff format .
- Type check: uv run mypy phi_scan/
- Python 3.12, Typer CLI, Rich, SQLite, HIPAA compliance

Commit rules:
- No Co-Authored-By tags in any commit message
- No Anthropic or AI attribution in commits or PR bodies
- Branch naming for health cycles: chore/self-heal-YYYYMMDD-HHMM
"""


@dataclass
class RunMetrics:
    """Collected metrics from a completed self-heal agent run."""

    result_subtype: ResultSubtype
    run_cost_usd: float
    turns_used: int
    run_completion_text: str


def _print_tool_call_name(message: AssistantMessage) -> None:
    """Print each tool call name for workflow log visibility."""
    for block in message.content:
        if hasattr(block, "type") and block.type == TOOL_USE_BLOCK_TYPE:
            print(f"{TOOL_LOG_PREFIX}{block.name}")


def _write_result_file(metrics: RunMetrics) -> None:
    """Write a machine-readable result file for downstream workflow steps."""
    with open(RESULT_OUTPUT_FILE, "w", encoding="utf-8") as output_file:
        output_file.write(f"subtype: {metrics.result_subtype}\n")
        output_file.write(f"cost_usd: {metrics.run_cost_usd:.4f}\n")
        output_file.write(f"turns: {metrics.turns_used}\n")
        if metrics.run_completion_text:
            # Truncate to avoid oversized workflow logs
            output_file.write(f"summary: {metrics.run_completion_text[:MAX_SUMMARY_LENGTH]}\n")


def _map_subtype_to_exit_code(result_subtype: ResultSubtype) -> int:
    """Return 0 on success, 1 on any failure or limit hit."""
    if result_subtype == ResultSubtype.SUCCESS:
        return EXIT_CODE_SUCCESS
    return EXIT_CODE_FAILURE


def _print_run_outcome(metrics: RunMetrics) -> None:
    """Print a human-readable outcome message for the workflow log."""
    if metrics.result_subtype == ResultSubtype.SUCCESS:
        print("Self-heal completed successfully.")
    elif metrics.result_subtype == ResultSubtype.MAX_BUDGET:
        print(f"Self-heal hit the ${MAX_BUDGET_USD:.2f} budget cap.")
        print("Increase MAX_BUDGET_USD in self_heal_runner.py if needed.")
    elif metrics.result_subtype == ResultSubtype.MAX_TURNS:
        print(f"Self-heal hit the {MAX_TURNS}-turn limit.")
        print("Increase MAX_TURNS in self_heal_runner.py if needed.")
    else:
        print(f"Self-heal stopped: {metrics.result_subtype}")


def _print_result_summary(metrics: RunMetrics) -> None:
    """Print the result summary line for the workflow log."""
    print(f"Result:     {metrics.result_subtype}")
    print(f"Turns used: {metrics.turns_used}")
    print(f"Cost:       ${metrics.run_cost_usd:.4f}")


def _extract_metrics_from_result(message: ResultMessage) -> RunMetrics:
    """Extract RunMetrics from a completed ResultMessage.

    Args:
        message: The SDK ResultMessage containing subtype, turns, cost, and result.

    Returns:
        RunMetrics populated from the message fields.
    """
    result_subtype = ResultSubtype(message.subtype)
    run_cost_usd = message.total_cost_usd if message.total_cost_usd is not None else 0.0
    run_completion_text = (
        message.result if result_subtype == ResultSubtype.SUCCESS and message.result else ""
    )
    return RunMetrics(
        result_subtype=result_subtype,
        run_cost_usd=run_cost_usd,
        turns_used=message.num_turns,
        run_completion_text=run_completion_text,
    )


async def _collect_run_metrics() -> RunMetrics:
    """Stream the self-heal agent run and collect result metrics.

    Returns:
        RunMetrics dataclass with subtype, cost, turns, and completion text.
    """
    metrics = RunMetrics(
        result_subtype=DEFAULT_RESULT_SUBTYPE,
        run_cost_usd=0.0,
        turns_used=0,
        run_completion_text="",
    )

    async for message in query(
        prompt=SELF_HEAL_PROMPT,
        options=ClaudeAgentOptions(
            permission_mode=PERMISSION_MODE_BYPASS,
            max_budget_usd=MAX_BUDGET_USD,
            max_turns=MAX_TURNS,
            allowed_tools=list(ALLOWED_SDK_TOOLS),
            setting_sources=["project"],
            effort=DEFAULT_EFFORT,
            model=DEFAULT_MODEL,
        ),
    ):
        if isinstance(message, AssistantMessage):
            _print_tool_call_name(message)

        if isinstance(message, ResultMessage):
            metrics = _extract_metrics_from_result(message)
            _print_result_summary(metrics)

    return metrics


async def execute_self_heal_cycle() -> int:
    """Orchestrate the self-heal run and return an exit code for the workflow.

    Returns:
        0 on success, 1 on any failure or limit hit.
    """
    print(f"Starting self-heal run — budget cap: ${MAX_BUDGET_USD:.2f} | max turns: {MAX_TURNS}")

    metrics = await _collect_run_metrics()

    _write_result_file(metrics)
    _print_run_outcome(metrics)

    return _map_subtype_to_exit_code(metrics.result_subtype)


if __name__ == "__main__":
    if not os.environ.get(ANTHROPIC_API_KEY_ENV_VAR):
        print(f"ERROR: {ANTHROPIC_API_KEY_ENV_VAR} is not set.")
        sys.exit(EXIT_CODE_FAILURE)

    sys.exit(asyncio.run(execute_self_heal_cycle()))
