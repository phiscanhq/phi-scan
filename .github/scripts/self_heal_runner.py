"""
Self-heal runner for GitHub Actions.

Invokes the /self-heal skill via the Claude Agent SDK with hard budget and
turn limits. Replaces the CLI invocation (claude --dangerously-skip-permissions)
so the workflow gets proper cost visibility and structured exit codes.
"""

import asyncio
import os
import sys

from claude_agent_sdk import AssistantMessage, ClaudeAgentOptions, ResultMessage, query

MAX_BUDGET_USD: float = 15.00
MAX_TURNS: int = 50
MAX_SUMMARY_LENGTH: int = 500
RESULT_OUTPUT_FILE: str = "self_heal_result.txt"
ANTHROPIC_API_KEY_ENV_VAR: str = "ANTHROPIC_API_KEY"

RESULT_SUBTYPE_SUCCESS: str = "success"
RESULT_SUBTYPE_UNKNOWN: str = "unknown"
RESULT_SUBTYPE_MAX_BUDGET: str = "error_max_budget_usd"
RESULT_SUBTYPE_MAX_TURNS: str = "error_max_turns"

PERMISSION_MODE_BYPASS: str = "bypassPermissions"
DEFAULT_MODEL: str = "claude-sonnet-4-6"
DEFAULT_EFFORT: str = "high"

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


def _print_tool_call_name(message: AssistantMessage) -> None:
    """Print each tool call name for workflow log visibility."""
    for block in message.content:
        if hasattr(block, "type") and block.type == "tool_use":
            print(f"  [tool] {block.name}")


def _write_result_file(
    result_subtype: str,
    total_cost_usd: float,
    num_turns: int,
    result_summary_text: str,
) -> None:
    """Write a machine-readable result file for downstream workflow steps."""
    with open(RESULT_OUTPUT_FILE, "w", encoding="utf-8") as output_file:
        output_file.write(f"subtype: {result_subtype}\n")
        output_file.write(f"cost_usd: {total_cost_usd:.4f}\n")
        output_file.write(f"turns: {num_turns}\n")
        if result_summary_text:
            # Truncate to avoid oversized workflow logs
            output_file.write(f"summary: {result_summary_text[:MAX_SUMMARY_LENGTH]}\n")


def _map_subtype_to_exit_code(result_subtype: str) -> int:
    """Return 0 on success, 1 on any failure or limit hit."""
    if result_subtype == RESULT_SUBTYPE_SUCCESS:
        return EXIT_CODE_SUCCESS
    return EXIT_CODE_FAILURE


def _print_run_outcome(result_subtype: str) -> None:
    """Print a human-readable outcome message for the workflow log."""
    if result_subtype == RESULT_SUBTYPE_SUCCESS:
        print("Self-heal completed successfully.")
    elif result_subtype == RESULT_SUBTYPE_MAX_BUDGET:
        print(f"Self-heal hit the ${MAX_BUDGET_USD:.2f} budget cap — increase MAX_BUDGET_USD if needed.")
    elif result_subtype == RESULT_SUBTYPE_MAX_TURNS:
        print(f"Self-heal hit the {MAX_TURNS}-turn limit — increase MAX_TURNS if needed.")
    else:
        print(f"Self-heal stopped: {result_subtype}")


async def _collect_run_metrics() -> tuple[str, float, int, str]:
    """Run the self-heal skill and collect result metrics from the message stream.

    Returns:
        Tuple of (result_subtype, total_cost_usd, num_turns, final_result_text).
    """
    result_subtype: str = RESULT_SUBTYPE_UNKNOWN
    total_cost_usd: float = 0.0
    num_turns: int = 0
    final_result_text: str = ""

    async for message in query(
        prompt=SELF_HEAL_PROMPT,
        options=ClaudeAgentOptions(
            permission_mode=PERMISSION_MODE_BYPASS,
            max_budget_usd=MAX_BUDGET_USD,
            max_turns=MAX_TURNS,
            allowed_tools=["Bash", "Read", "Write", "Edit", "Glob", "Grep", "Agent"],
            setting_sources=["project"],
            effort=DEFAULT_EFFORT,
            model=DEFAULT_MODEL,
        ),
    ):
        if isinstance(message, AssistantMessage):
            _print_tool_call_name(message)

        if isinstance(message, ResultMessage):
            result_subtype = message.subtype
            num_turns = message.num_turns

            if message.total_cost_usd is not None:
                total_cost_usd = message.total_cost_usd

            if result_subtype == RESULT_SUBTYPE_SUCCESS and message.result:
                final_result_text = message.result

            print(f"Result:     {result_subtype}")
            print(f"Turns used: {num_turns}")
            print(f"Cost:       ${total_cost_usd:.4f}")

    return result_subtype, total_cost_usd, num_turns, final_result_text


async def run_self_heal() -> int:
    """Orchestrate the self-heal run and return an exit code for the workflow.

    Returns:
        0 on success, 1 on any failure or limit hit.
    """
    print(f"Starting self-heal run — budget cap: ${MAX_BUDGET_USD:.2f} | max turns: {MAX_TURNS}")

    result_subtype, total_cost_usd, num_turns, final_result_text = await _collect_run_metrics()

    _write_result_file(result_subtype, total_cost_usd, num_turns, final_result_text)
    _print_run_outcome(result_subtype)

    return _map_subtype_to_exit_code(result_subtype)


if __name__ == "__main__":
    if not os.environ.get(ANTHROPIC_API_KEY_ENV_VAR):
        print(f"ERROR: {ANTHROPIC_API_KEY_ENV_VAR} is not set.")
        sys.exit(EXIT_CODE_FAILURE)

    sys.exit(asyncio.run(run_self_heal()))
