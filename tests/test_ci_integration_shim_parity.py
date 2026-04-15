"""Parity tests for the ``phi_scan.ci_integration`` compatibility shim.

Phase-3 extraction moved comment-body formatting to
``phi_scan.ci.comment_body`` and orchestration dispatch to
``phi_scan.ci.dispatch``. These tests pin the contract that every
symbol still imports cleanly from ``phi_scan.ci_integration`` and that
each re-export is the same object as its new canonical home.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from phi_scan import ci_integration
from phi_scan.ci import comment_body as canonical_comment_body
from phi_scan.ci import dispatch as canonical_dispatch
from phi_scan.ci._detect import CIPlatform, PullRequestContext
from phi_scan.models import ScanResult

# ---------------------------------------------------------------------------
# Slice A — comment_body identity
# ---------------------------------------------------------------------------


def test_build_comment_body_is_canonical_reexport() -> None:
    assert ci_integration.build_comment_body is canonical_comment_body.build_comment_body


def test_build_comment_body_with_baseline_is_canonical_reexport() -> None:
    assert (
        ci_integration.build_comment_body_with_baseline
        is canonical_comment_body.build_comment_body_with_baseline
    )


def test_baseline_comparison_is_canonical_reexport() -> None:
    assert ci_integration.BaselineComparison is canonical_comment_body.BaselineComparison


# ---------------------------------------------------------------------------
# Slice B — dispatch identity
# ---------------------------------------------------------------------------


def test_post_pr_comment_is_canonical_reexport() -> None:
    assert ci_integration.post_pr_comment is canonical_dispatch.post_pr_comment


def test_post_pull_request_comment_is_alias_for_post_pr_comment() -> None:
    assert ci_integration.post_pull_request_comment is canonical_dispatch.post_pull_request_comment
    assert ci_integration.post_pull_request_comment is ci_integration.post_pr_comment


def test_set_commit_status_is_canonical_reexport() -> None:
    assert ci_integration.set_commit_status is canonical_dispatch.set_commit_status


# ---------------------------------------------------------------------------
# Behavioral smoke — comment body
# ---------------------------------------------------------------------------


def test_build_comment_body_clean_scan_produces_no_violations_header() -> None:
    clean_scan = MagicMock(spec=ScanResult)
    clean_scan.is_clean = True
    clean_scan.files_scanned = 7
    clean_scan.scan_duration = 0.25

    body = ci_integration.build_comment_body(clean_scan)

    assert "No PHI/PII Violations Found" in str(body)
    assert "Scanned **7** file(s)" in str(body)


# ---------------------------------------------------------------------------
# Behavioral smoke — dispatch with monkeypatched adapter resolution
# ---------------------------------------------------------------------------


def test_post_pr_comment_forwards_to_resolved_adapter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_adapter = MagicMock()
    monkeypatch.setattr(canonical_dispatch, "resolve_adapter", lambda _platform: fake_adapter)

    clean_scan = MagicMock(spec=ScanResult)
    clean_scan.is_clean = True
    clean_scan.files_scanned = 1
    clean_scan.scan_duration = 0.01

    pr_context = PullRequestContext(
        platform=CIPlatform.GITHUB_ACTIONS,
        pull_request_number="42",
        repository="acme/example",
        sha="deadbeef",
        branch="feature",
        base_branch="main",
    )

    ci_integration.post_pr_comment(clean_scan, pr_context)

    assert fake_adapter.post_pull_request_comment.call_count == 1
    posted_body, posted_context = fake_adapter.post_pull_request_comment.call_args.args
    assert "No PHI/PII Violations Found" in str(posted_body)
    assert posted_context is pr_context


def test_set_commit_status_forwards_to_resolved_adapter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_adapter = MagicMock()
    fake_adapter.can_post_commit_status = True
    monkeypatch.setattr(canonical_dispatch, "resolve_adapter", lambda _platform: fake_adapter)

    clean_scan = MagicMock(spec=ScanResult)
    pr_context = PullRequestContext(
        platform=CIPlatform.GITHUB_ACTIONS,
        pull_request_number="42",
        repository="acme/example",
        sha="deadbeef",
        branch="feature",
        base_branch="main",
    )

    ci_integration.set_commit_status(clean_scan, pr_context)

    assert fake_adapter.set_commit_status.call_count == 1
    forwarded_scan, forwarded_context = fake_adapter.set_commit_status.call_args.args
    assert forwarded_scan is clean_scan
    assert forwarded_context is pr_context


def test_set_commit_status_returns_early_when_sha_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_adapter = MagicMock()
    monkeypatch.setattr(canonical_dispatch, "resolve_adapter", lambda _platform: fake_adapter)

    pr_context = PullRequestContext(
        platform=CIPlatform.GITHUB_ACTIONS,
        pull_request_number="42",
        repository="acme/example",
        sha=None,
        branch="feature",
        base_branch="main",
    )

    ci_integration.set_commit_status(MagicMock(spec=ScanResult), pr_context)

    assert fake_adapter.set_commit_status.call_count == 0


def test_set_commit_status_returns_early_when_adapter_unsupported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_adapter = MagicMock()
    fake_adapter.can_post_commit_status = False
    monkeypatch.setattr(canonical_dispatch, "resolve_adapter", lambda _platform: fake_adapter)

    pr_context = PullRequestContext(
        platform=CIPlatform.GITHUB_ACTIONS,
        pull_request_number="42",
        repository="acme/example",
        sha="deadbeef",
        branch="feature",
        base_branch="main",
    )

    ci_integration.set_commit_status(MagicMock(spec=ScanResult), pr_context)

    assert fake_adapter.set_commit_status.call_count == 0
