"""
Claude automated PR review script.

Reads the PR diff, sends it to Claude with PhiScan code standards as context,
and writes the review to review_comment.txt for posting as a PR comment.
"""

import os
import sys
import time
from enum import StrEnum

import anthropic

MAX_DIFF_CHARACTERS = 30_000
MAX_RETRY_ATTEMPTS = 3
OVERLOADED_STATUS_CODE = 529
RETRY_BASE_DELAY_SECONDS = 10
RETRY_BACKOFF_MULTIPLIER = 2
REVIEW_OUTPUT_FILE = "review_comment.txt"
DIFF_INPUT_FILE = "pr_diff.txt"

SYSTEM_PROMPT = """You are a senior software engineer reviewing a pull request for PhiScan,
a HIPAA & FHIR compliant PHI/PII scanner for CI/CD pipelines built in Python 3.12.

Review the diff against these non-negotiable code standards:

NAMING:
- Variables and functions: snake_case
- Classes: PascalCase (nouns only)
- Constants: UPPER_SNAKE_CASE
- Booleans must start with: is_, has_, can_, should_, was_
- Function names must be verb-noun pairs (e.g. calculate_tax_total, not process)
- No abbreviations — write the full word (no usr, cfg, tmp, val, res)
- No class names ending in: Manager, Handler, Processor, Helper, Util

FUNCTIONS:
- Maximum 30 lines per function
- Maximum 3 arguments (use @dataclass for 4+)
- Single responsibility — describable in one sentence with no "and"
- Guard clauses over nested conditionals — return early

NO MAGIC VALUES:
- Zero numeric or string literals in logic code
- All literals in named constants at module level or constants.py
- Enums for any finite set of string values

ERROR HANDLING:
- Never catch bare Exception without re-raising
- Custom exceptions for domain errors
- Never silence errors with pass or empty except blocks

SECURITY (critical for a PHI scanner):
- Never store raw PHI values — always SHA-256 hash
- Never send PHI to any external API
- Never follow symlinks during traversal

BANNED:
- Magic numbers or strings in logic
- Functions named: handle, process, do, run, manage, data, info
- Nested conditionals deeper than 2 levels
- Mutable default arguments
- Bare except: clauses
- Commented-out code
- Vague variable names: data, info, result, temp, value, obj, item, thing

Provide a concise, constructive review. Format your response as markdown.
Start with a one-line summary, then list specific issues found (if any) with file:line references.
If the code looks good, say so clearly. Be direct and specific — not vague.

IMPORTANT: At the very end of your response, after all human-readable content, append a
machine-readable findings block in this exact format (do not omit it):

<!-- REVIEW_RESULT
verdict: CLEAN | CRITICAL | WARNING
critical_count: <integer>
warning_count: <integer>
-->

Use CLEAN when no issues are found. Use CRITICAL when there are security, PHI, or logic
errors. Use WARNING when there are code standard violations but no security issues."""


def load_diff() -> str:
    """Load the PR diff from file, truncating if over token limit."""
    if not os.path.exists(DIFF_INPUT_FILE):
        return ""

    with open(DIFF_INPUT_FILE, encoding="utf-8") as diff_file:
        diff_content = diff_file.read()

    if len(diff_content) > MAX_DIFF_CHARACTERS:
        truncation_notice = f"\n\n[Diff truncated at {MAX_DIFF_CHARACTERS} characters]"
        return diff_content[:MAX_DIFF_CHARACTERS] + truncation_notice

    return diff_content


def build_review_prompt(pr_title: str, diff: str) -> str:
    """Build the user prompt combining PR context and diff."""
    return f"""PR Title: {pr_title}

Diff:
```
{diff}
```

Review this PR against the PhiScan code standards. Be specific about any violations found."""


def _send_to_claude(client: anthropic.Anthropic, prompt: str) -> str:
    """Send a single review prompt to Claude and return the response text."""
    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )
    return message.content[0].text  # type: ignore[return-value]


def _sleep_before_retry(attempt: int) -> None:
    """Sleep with exponential backoff before retrying a Claude API call."""
    delay = RETRY_BASE_DELAY_SECONDS * (RETRY_BACKOFF_MULTIPLIER**attempt)
    print(
        f"API overloaded (529) — retrying in {delay}s (attempt {attempt + 1}/{MAX_RETRY_ATTEMPTS})"
    )  # noqa: E501
    time.sleep(delay)


def request_claude_review(pr_title: str, diff: str) -> str:
    """Send the diff to Claude and return the review text, retrying on 529 overload."""
    client = anthropic.Anthropic()
    prompt = build_review_prompt(pr_title, diff)

    for attempt in range(MAX_RETRY_ATTEMPTS):
        try:
            return _send_to_claude(client, prompt)
        except anthropic.APIStatusError as error:
            is_overloaded = error.status_code == OVERLOADED_STATUS_CODE
            is_final_attempt = attempt == MAX_RETRY_ATTEMPTS - 1
            if not is_overloaded or is_final_attempt:
                raise
            _sleep_before_retry(attempt)

    raise RuntimeError("All retry attempts exhausted without returning or raising")


REVIEW_RESULT_FILE = "review_result.txt"
REVIEW_COMMENT_HEADER = "## Claude Code Review\n\n"
VERDICT_LINE_PREFIX = "verdict:"


class ReviewVerdict(StrEnum):
    CLEAN = "CLEAN"
    CRITICAL = "CRITICAL"
    WARNING = "WARNING"


DEFAULT_VERDICT: ReviewVerdict = ReviewVerdict.WARNING


def _extract_verdict(review_text: str) -> ReviewVerdict:
    """Extract the machine-readable verdict from the structured REVIEW_RESULT block.

    Args:
        review_text: Full review text from Claude, expected to contain a verdict line.

    Returns:
        ReviewVerdict enum value. Defaults to WARNING if not found or unrecognized
        so unreadable results trigger a fix attempt rather than silently passing.
    """
    for line in review_text.splitlines():
        stripped_line = line.strip()
        if stripped_line.startswith(VERDICT_LINE_PREFIX):
            verdict_text = stripped_line.split(":", maxsplit=1)[1].strip()
            try:
                return ReviewVerdict(verdict_text)
            except ValueError:
                return DEFAULT_VERDICT
    return DEFAULT_VERDICT


def _write_review_comment_file(review_text: str) -> None:
    """Write the human-readable review comment to the output file for posting."""
    with open(REVIEW_OUTPUT_FILE, "w", encoding="utf-8") as output_file:
        output_file.write(REVIEW_COMMENT_HEADER + review_text)


def _write_verdict_file(review_text: str) -> None:
    """Write the machine-readable verdict to the result file for the auto-resolve workflow."""
    verdict = _extract_verdict(review_text)
    with open(REVIEW_RESULT_FILE, "w", encoding="utf-8") as result_file:
        result_file.write(verdict)


def write_review_output(review_text: str) -> None:
    """Write the human-readable review comment and machine-readable verdict files.

    Args:
        review_text: Full review text returned by Claude.
    """
    _write_review_comment_file(review_text)
    _write_verdict_file(review_text)


def run_review() -> None:
    """Orchestrate the full review flow."""
    pr_title = os.environ.get("PR_TITLE", "Untitled PR")
    diff = load_diff()

    if not diff:
        print("No diff found — skipping review.")
        return

    print(f"Reviewing PR: {pr_title}")
    print(f"Diff size: {len(diff)} characters")

    review_text = request_claude_review(pr_title, diff)
    write_review_output(review_text)

    print(f"Review written to {REVIEW_OUTPUT_FILE}")


if __name__ == "__main__":
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ERROR: ANTHROPIC_API_KEY not set.")
        sys.exit(1)

    run_review()
