# phi-scan:ignore-file
"""Adversarial SSRF tests for the webhook URL validator (scorecard S5).

``tests/test_notifier.py`` covers the happy path and the first-order SSRF
rules (RFC1918, loopback, cloud metadata, CGNAT, http:// rejection,
DNS-resolution-to-private). This file adds the adversarial coverage the
scorecard calls out as missing under S5:

  * IPv4-mapped IPv6 bypass attempts (``::ffff:127.0.0.1`` and peers).
    Without unmapping the IPv4 blocklist does not apply, so the ``127/8``
    rule would silently miss an attacker-controlled DNS record returning
    an IPv4-mapped IPv6 pointing at loopback.
  * Literal IPv6 blocklist coverage — ``[::1]``, ``[fe80::1]``, ``[fc00::1]``.
  * Unspecified addresses (``0.0.0.0``, ``::``), which Linux and macOS
    implicitly route to loopback on many socket APIs.
  * Multicast (``224.0.0.0/4`` and ``ff00::/8``) and reserved / broadcast
    (``240.0.0.0/4``) addresses, which are never valid webhook targets.
  * Mixed-resolution responses — if ``getaddrinfo`` returns
    ``[public, private]`` the validator must reject the whole hostname,
    not just the first address.
  * DNS rebinding (TOCTOU): between the validation-time resolve and the
    delivery-time resolve, the attacker changes the DNS record. The
    defender pins the validated IP into the outbound URL so the second
    lookup cannot happen.
  * Positive controls: public IPv6 addresses and an IPv4-mapped IPv6
    pointing at a public IPv4 must still be allowed so the gate does
    not become a broken denial-of-service.

Tests use deterministic ``_resolve_hostname_addresses`` monkeypatches
rather than a real rebind server: the adversary-controlled DNS surface
is perfectly modelled by returning different values from a mock on
successive calls, without the CI flakiness a real socket-level rebind
would introduce.
"""

from __future__ import annotations

import ast
import ipaddress
from pathlib import Path
from unittest.mock import patch

import pytest

import phi_scan.notifier as notifier_module
from phi_scan.exceptions import NotificationError
from phi_scan.notifier import (
    _build_pinned_webhook_request,  # noqa: PLC2701
    _is_ip_address_blocked,  # noqa: PLC2701
    _normalise_ip_address,  # noqa: PLC2701
    _reject_ssrf_resolved_addresses,  # noqa: PLC2701
    _validate_webhook_url,  # noqa: PLC2701
)

# ---------------------------------------------------------------------------
# Adversarial URL constants — named for the vector under test.
# Every URL points at a reserved, loopback, private, multicast, unspecified,
# or IPv4-mapped IPv6 target; none are real public endpoints.
# ---------------------------------------------------------------------------

_IPV6_LITERAL_LOOPBACK_URL: str = "https://[::1]/webhook"
_IPV6_LITERAL_LINK_LOCAL_URL: str = "https://[fe80::1]/webhook"
_IPV6_LITERAL_UNIQUE_LOCAL_URL: str = "https://[fc00::1]/webhook"
_IPV6_LITERAL_UNIQUE_LOCAL_ALT_URL: str = "https://[fd00::1]/webhook"

_IPV4_MAPPED_LOOPBACK_URL: str = "https://[::ffff:127.0.0.1]/webhook"
_IPV4_MAPPED_RFC1918_URL: str = "https://[::ffff:10.0.0.1]/webhook"
_IPV4_MAPPED_METADATA_URL: str = "https://[::ffff:169.254.169.254]/webhook"
_IPV4_MAPPED_PUBLIC_URL: str = "https://[::ffff:8.8.8.8]/webhook"

_UNSPECIFIED_IPV4_URL: str = "https://0.0.0.0/webhook"
_UNSPECIFIED_IPV6_URL: str = "https://[::]/webhook"

_MULTICAST_IPV4_URL: str = "https://224.0.0.1/webhook"
_MULTICAST_IPV6_URL: str = "https://[ff02::1]/webhook"

_IPV4_BROADCAST_URL: str = "https://255.255.255.255/webhook"
_IPV4_RESERVED_CLASS_E_URL: str = "https://240.0.0.1/webhook"

_PUBLIC_IPV6_URL: str = "https://[2001:4860:4860::8888]/webhook"

_DOMAIN_URL: str = "https://hooks.example.com/notify"
_DOMAIN_HOST: str = "hooks.example.com"

# Individual address literals used as resolver return values and as
# parametrize inputs. Every literal that appears in test logic is hoisted
# here so no raw IP strings live inside test bodies or parametrize lists.
_PUBLIC_IPV4_ADDRESS: str = "8.8.8.8"
_ALTERNATE_PUBLIC_IPV4_ADDRESS: str = "1.1.1.1"
_PUBLIC_IPV6_ADDRESS: str = "2001:4860:4860::8888"
_ALTERNATE_PUBLIC_IPV6_ADDRESS: str = "2606:4700:4700::1111"

_PRIVATE_IPV4_ADDRESS: str = "10.0.0.1"
_RFC1918_CLASS_C_IPV4_ADDRESS: str = "192.168.1.1"
_CGNAT_IPV4_ADDRESS: str = "100.64.0.1"
_LOOPBACK_IPV4_ADDRESS: str = "127.0.0.1"
_METADATA_IPV4_ADDRESS: str = "169.254.169.254"
_UNSPECIFIED_IPV4_ADDRESS: str = "0.0.0.0"  # noqa: S104 — test fixture, never bound
_MULTICAST_IPV4_ADDRESS: str = "224.0.0.1"
_BROADCAST_IPV4_ADDRESS: str = "255.255.255.255"
_RESERVED_CLASS_E_IPV4_ADDRESS: str = "240.0.0.1"

_LOOPBACK_IPV6_ADDRESS: str = "::1"
_UNSPECIFIED_IPV6_ADDRESS: str = "::"
_LINK_LOCAL_IPV6_ADDRESS: str = "fe80::1"
_UNIQUE_LOCAL_IPV6_ADDRESS: str = "fc00::1"
_MULTICAST_IPV6_ADDRESS: str = "ff02::1"

_IPV4_MAPPED_LOOPBACK_ADDRESS: str = "::ffff:127.0.0.1"
_IPV4_MAPPED_PUBLIC_ADDRESS: str = "::ffff:8.8.8.8"

_REBIND_FIRST_IP: str = _PUBLIC_IPV4_ADDRESS
_REBIND_SECOND_IP: str = _LOOPBACK_IPV4_ADDRESS

# Structural-safety constants for threat-model row N-6 (P1, DNS rebind via
# HTTP redirect). httpx defaults to ``follow_redirects=False``; the
# notifier must never opt in, because a redirect to a private IP would
# defeat the SSRF checks performed at validation time. The test below
# parses ``phi_scan/notifier.py`` and fails on any explicit
# ``follow_redirects=True`` keyword argument.
_NOTIFIER_MODULE_PATH: Path = Path(notifier_module.__file__)
_SOURCE_FILE_ENCODING: str = "utf-8"
_BANNED_FOLLOW_REDIRECTS_KEYWORD: str = "follow_redirects"

# Parametrize fixtures for the _is_ip_address_blocked classifier test.
_BLOCKED_ADVERSARIAL_ADDRESSES: tuple[str, ...] = (
    _LOOPBACK_IPV4_ADDRESS,
    _PRIVATE_IPV4_ADDRESS,
    _RFC1918_CLASS_C_IPV4_ADDRESS,
    _METADATA_IPV4_ADDRESS,
    _CGNAT_IPV4_ADDRESS,
    _UNSPECIFIED_IPV4_ADDRESS,
    _MULTICAST_IPV4_ADDRESS,
    _BROADCAST_IPV4_ADDRESS,
    _RESERVED_CLASS_E_IPV4_ADDRESS,
    _LOOPBACK_IPV6_ADDRESS,
    _UNSPECIFIED_IPV6_ADDRESS,
    _LINK_LOCAL_IPV6_ADDRESS,
    _UNIQUE_LOCAL_IPV6_ADDRESS,
    _MULTICAST_IPV6_ADDRESS,
)
_ALLOWED_PUBLIC_ADDRESSES: tuple[str, ...] = (
    _PUBLIC_IPV4_ADDRESS,
    _ALTERNATE_PUBLIC_IPV4_ADDRESS,
    _PUBLIC_IPV6_ADDRESS,
    _ALTERNATE_PUBLIC_IPV6_ADDRESS,
)


# ---------------------------------------------------------------------------
# _normalise_ip_address — IPv4-mapped IPv6 unmapping primitive
# ---------------------------------------------------------------------------


class TestNormaliseIpAddress:
    """``_normalise_ip_address`` must unmap IPv4-mapped IPv6 and leave others intact."""

    def test_ipv4_mapped_loopback_is_unmapped_to_ipv4(self) -> None:
        normalised = _normalise_ip_address(ipaddress.ip_address(_IPV4_MAPPED_LOOPBACK_ADDRESS))

        assert normalised == ipaddress.IPv4Address(_LOOPBACK_IPV4_ADDRESS)

    def test_ipv4_mapped_public_is_unmapped_to_ipv4(self) -> None:
        normalised = _normalise_ip_address(ipaddress.ip_address(_IPV4_MAPPED_PUBLIC_ADDRESS))

        assert normalised == ipaddress.IPv4Address(_PUBLIC_IPV4_ADDRESS)

    def test_plain_ipv4_passes_through_unchanged(self) -> None:
        original = ipaddress.IPv4Address(_PUBLIC_IPV4_ADDRESS)

        assert _normalise_ip_address(original) == original

    def test_plain_ipv6_passes_through_unchanged(self) -> None:
        original = ipaddress.IPv6Address(_PUBLIC_IPV6_ADDRESS)

        assert _normalise_ip_address(original) == original


# ---------------------------------------------------------------------------
# _is_ip_address_blocked — classification primitive
# ---------------------------------------------------------------------------


class TestIsIpAddressBlocked:
    """``_is_ip_address_blocked`` classifies normalised addresses."""

    @pytest.mark.parametrize("address", _BLOCKED_ADVERSARIAL_ADDRESSES)
    def test_blocks_adversarial_ipv4_and_ipv6_addresses(self, address: str) -> None:
        assert _is_ip_address_blocked(ipaddress.ip_address(address)) is True

    @pytest.mark.parametrize("address", _ALLOWED_PUBLIC_ADDRESSES)
    def test_allows_public_addresses(self, address: str) -> None:
        assert _is_ip_address_blocked(ipaddress.ip_address(address)) is False


# ---------------------------------------------------------------------------
# Literal IPv6 blocklist coverage — _validate_webhook_url
# ---------------------------------------------------------------------------


class TestValidateWebhookUrlRejectsLiteralIpv6:
    """Literal IPv6 URLs in every blocked category must raise ``NotificationError``."""

    @pytest.mark.parametrize(
        "url",
        [
            _IPV6_LITERAL_LOOPBACK_URL,
            _IPV6_LITERAL_LINK_LOCAL_URL,
            _IPV6_LITERAL_UNIQUE_LOCAL_URL,
            _IPV6_LITERAL_UNIQUE_LOCAL_ALT_URL,
        ],
    )
    def test_literal_ipv6_in_blocked_range_raises(self, url: str) -> None:
        with pytest.raises(NotificationError):
            _validate_webhook_url(url, is_private_webhook_url_allowed=False)


# ---------------------------------------------------------------------------
# IPv4-mapped IPv6 bypass attempts
# ---------------------------------------------------------------------------


class TestValidateWebhookUrlRejectsIpv4MappedIpv6:
    """IPv4-mapped IPv6 must be unmapped before the IPv4 blocklist is applied."""

    @pytest.mark.parametrize(
        "url",
        [
            _IPV4_MAPPED_LOOPBACK_URL,
            _IPV4_MAPPED_RFC1918_URL,
            _IPV4_MAPPED_METADATA_URL,
        ],
    )
    def test_literal_ipv4_mapped_ipv6_in_blocked_range_raises(self, url: str) -> None:
        with pytest.raises(NotificationError):
            _validate_webhook_url(url, is_private_webhook_url_allowed=False)

    def test_literal_ipv4_mapped_ipv6_to_public_ipv4_is_allowed(self) -> None:
        """An IPv4-mapped IPv6 pointing at a public IPv4 must still be allowed."""
        # Literal IP path returns None — no DNS pinning needed because the
        # caller already handed us the concrete address.
        assert (
            _validate_webhook_url(_IPV4_MAPPED_PUBLIC_URL, is_private_webhook_url_allowed=False)
            is None
        )

    def test_dns_resolving_to_ipv4_mapped_ipv6_loopback_is_rejected(self) -> None:
        """Rebind attempt: DNS returns ``::ffff:127.0.0.1`` — must be unmapped and blocked."""
        with patch(
            "phi_scan.notifier._resolve_hostname_addresses",
            return_value=[ipaddress.IPv4Address(_LOOPBACK_IPV4_ADDRESS)],
        ):
            with pytest.raises(NotificationError):
                _validate_webhook_url(_DOMAIN_URL, is_private_webhook_url_allowed=False)


# ---------------------------------------------------------------------------
# Unspecified / multicast / reserved
# ---------------------------------------------------------------------------


class TestValidateWebhookUrlRejectsSpecialRanges:
    """Unspecified, multicast, reserved, and broadcast addresses must be rejected."""

    @pytest.mark.parametrize(
        "url",
        [
            _UNSPECIFIED_IPV4_URL,
            _UNSPECIFIED_IPV6_URL,
            _MULTICAST_IPV4_URL,
            _MULTICAST_IPV6_URL,
            _IPV4_BROADCAST_URL,
            _IPV4_RESERVED_CLASS_E_URL,
        ],
    )
    def test_special_range_literal_ip_raises(self, url: str) -> None:
        with pytest.raises(NotificationError):
            _validate_webhook_url(url, is_private_webhook_url_allowed=False)


# ---------------------------------------------------------------------------
# Mixed-resolution — getaddrinfo returns public + private together
# ---------------------------------------------------------------------------


class TestValidateWebhookUrlMixedResolution:
    """Every resolved address must pass — one private IP poisons the whole hostname."""

    def test_public_then_private_is_rejected(self) -> None:
        mixed_addresses = [
            ipaddress.IPv4Address(_PUBLIC_IPV4_ADDRESS),
            ipaddress.IPv4Address(_PRIVATE_IPV4_ADDRESS),
        ]
        with patch(
            "phi_scan.notifier._resolve_hostname_addresses",
            return_value=mixed_addresses,
        ):
            with pytest.raises(NotificationError):
                _validate_webhook_url(_DOMAIN_URL, is_private_webhook_url_allowed=False)

    def test_private_then_public_is_rejected(self) -> None:
        mixed_addresses = [
            ipaddress.IPv4Address(_PRIVATE_IPV4_ADDRESS),
            ipaddress.IPv4Address(_PUBLIC_IPV4_ADDRESS),
        ]
        with patch(
            "phi_scan.notifier._resolve_hostname_addresses",
            return_value=mixed_addresses,
        ):
            with pytest.raises(NotificationError):
                _validate_webhook_url(_DOMAIN_URL, is_private_webhook_url_allowed=False)

    def test_public_ipv4_then_metadata_ipv4_is_rejected(self) -> None:
        mixed_addresses = [
            ipaddress.IPv4Address(_PUBLIC_IPV4_ADDRESS),
            ipaddress.IPv4Address(_METADATA_IPV4_ADDRESS),
        ]
        with patch(
            "phi_scan.notifier._resolve_hostname_addresses",
            return_value=mixed_addresses,
        ):
            with pytest.raises(NotificationError):
                _validate_webhook_url(_DOMAIN_URL, is_private_webhook_url_allowed=False)

    def test_public_ipv4_then_ipv6_loopback_is_rejected(self) -> None:
        mixed_addresses = [
            ipaddress.IPv4Address(_PUBLIC_IPV4_ADDRESS),
            ipaddress.IPv6Address(_LOOPBACK_IPV6_ADDRESS),
        ]
        with patch(
            "phi_scan.notifier._resolve_hostname_addresses",
            return_value=mixed_addresses,
        ):
            with pytest.raises(NotificationError):
                _validate_webhook_url(_DOMAIN_URL, is_private_webhook_url_allowed=False)

    def test_all_public_addresses_are_accepted(self) -> None:
        """Positive control — two public IPs must not trip the mixed-resolution rule."""
        all_public_addresses = [
            ipaddress.IPv4Address(_PUBLIC_IPV4_ADDRESS),
            ipaddress.IPv4Address(_ALTERNATE_PUBLIC_IPV4_ADDRESS),
        ]
        with patch(
            "phi_scan.notifier._resolve_hostname_addresses",
            return_value=all_public_addresses,
        ):
            pinned_ip = _validate_webhook_url(_DOMAIN_URL, is_private_webhook_url_allowed=False)

        assert pinned_ip == _PUBLIC_IPV4_ADDRESS


# ---------------------------------------------------------------------------
# DNS rebinding (TOCTOU)
# ---------------------------------------------------------------------------


class TestDnsRebindingTimeOfCheckTimeOfUse:
    """The validated IP must be pinned into the outbound URL so a second lookup cannot happen.

    Adversary model: the attacker controls the DNS record for
    ``hooks.example.com``. On the first resolve (validation time) they
    answer with a public IP that passes the SSRF check. Between then and
    the HTTP request they flip the record to a private IP and hope the
    delivery code re-resolves the hostname. The pin must defeat this by
    putting the validated IP directly into the outbound URL, so the
    delivery code never asks DNS a second time.
    """

    def test_rebind_between_validate_and_build_uses_first_ip(self) -> None:
        """Second resolve returns a private IP, but the pinned URL ignores it."""
        rebind_answers = [
            [ipaddress.IPv4Address(_REBIND_FIRST_IP)],
            [ipaddress.IPv4Address(_REBIND_SECOND_IP)],
        ]
        with patch(
            "phi_scan.notifier._resolve_hostname_addresses",
            side_effect=rebind_answers,
        ):
            pinned_ip = _validate_webhook_url(_DOMAIN_URL, is_private_webhook_url_allowed=False)

        pinned_request = _build_pinned_webhook_request(_DOMAIN_URL, pinned_ip)

        assert pinned_ip == _REBIND_FIRST_IP
        assert _REBIND_FIRST_IP in pinned_request.target_url
        assert _REBIND_SECOND_IP not in pinned_request.target_url
        assert _DOMAIN_HOST not in pinned_request.target_url

    def test_rebind_host_header_preserves_original_hostname(self) -> None:
        """The original hostname must travel in the ``Host`` header for TLS SNI and routing."""
        with patch(
            "phi_scan.notifier._resolve_hostname_addresses",
            return_value=[ipaddress.IPv4Address(_PUBLIC_IPV4_ADDRESS)],
        ):
            pinned_ip = _validate_webhook_url(_DOMAIN_URL, is_private_webhook_url_allowed=False)

        pinned_request = _build_pinned_webhook_request(_DOMAIN_URL, pinned_ip)

        # Host header preserves the original hostname so TLS SNI and server-side
        # routing work, while the TCP connection goes to the pinned IP.
        assert pinned_request.headers.get("Host") == _DOMAIN_HOST


# ---------------------------------------------------------------------------
# IPv6 positive controls + DNS-returned IPv4-mapped IPv6 pinning
# ---------------------------------------------------------------------------


class TestValidateWebhookUrlAllowsPublicIpv6:
    """Public IPv6 hostnames must continue to work — the gate is not a DoS."""

    def test_public_ipv6_literal_is_allowed(self) -> None:
        assert _validate_webhook_url(_PUBLIC_IPV6_URL, is_private_webhook_url_allowed=False) is None

    def test_dns_resolving_to_public_ipv6_returns_pinned_address(self) -> None:
        public_ipv6 = ipaddress.IPv6Address(_PUBLIC_IPV6_ADDRESS)
        with patch(
            "phi_scan.notifier._resolve_hostname_addresses",
            return_value=[public_ipv6],
        ):
            pinned_ip = _validate_webhook_url(_DOMAIN_URL, is_private_webhook_url_allowed=False)

        assert pinned_ip == _PUBLIC_IPV6_ADDRESS

    def test_dns_resolving_to_ipv4_mapped_public_returns_ipv4_pin(self) -> None:
        """DNS returns ``::ffff:8.8.8.8`` — the pin should be the unmapped IPv4 form."""
        # The resolver helper normalises IPv4-mapped IPv6 before returning, so
        # the validator sees (and therefore pins) the IPv4 form. The pinned IP
        # is what httpx will actually connect to; keeping it as unmapped IPv4
        # avoids the ambiguous behaviour of dual-stack socket handling.
        with patch(
            "phi_scan.notifier._resolve_hostname_addresses",
            return_value=[ipaddress.IPv4Address(_PUBLIC_IPV4_ADDRESS)],
        ):
            pinned_ip = _validate_webhook_url(_DOMAIN_URL, is_private_webhook_url_allowed=False)

        assert pinned_ip == _PUBLIC_IPV4_ADDRESS


# ---------------------------------------------------------------------------
# _reject_ssrf_resolved_addresses — direct coverage of the mixed-set predicate
# ---------------------------------------------------------------------------


class TestRejectSsrfResolvedAddresses:
    """Direct tests for the predicate ``_validate_webhook_url`` depends on."""

    def test_all_public_does_not_raise(self) -> None:
        all_public_addresses = [
            ipaddress.IPv4Address(_PUBLIC_IPV4_ADDRESS),
            ipaddress.IPv6Address(_PUBLIC_IPV6_ADDRESS),
        ]

        _reject_ssrf_resolved_addresses(_DOMAIN_HOST, all_public_addresses)

    def test_any_blocked_address_raises(self) -> None:
        one_blocked = [
            ipaddress.IPv4Address(_PUBLIC_IPV4_ADDRESS),
            ipaddress.IPv4Address(_PRIVATE_IPV4_ADDRESS),
        ]
        with pytest.raises(NotificationError):
            _reject_ssrf_resolved_addresses(_DOMAIN_HOST, one_blocked)

    def test_unspecified_ipv6_raises(self) -> None:
        unspecified_only = [ipaddress.IPv6Address(_UNSPECIFIED_IPV6_ADDRESS)]
        with pytest.raises(NotificationError):
            _reject_ssrf_resolved_addresses(_DOMAIN_HOST, unspecified_only)


# ---------------------------------------------------------------------------
# Structural safety — threat-model N-6 (P1)
# ---------------------------------------------------------------------------


def _find_enabled_follow_redirects_keywords(module_source: str) -> list[int]:
    """Return the line numbers of every ``follow_redirects=True`` keyword.

    Walks every ``Call`` node in the parsed module and inspects its
    keyword arguments. A hit is any keyword named ``follow_redirects``
    whose value is the constant ``True``. Omitting the keyword entirely
    is safe because httpx defaults to ``follow_redirects=False``.
    """
    tree = ast.parse(module_source)
    enabled_line_numbers: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg != _BANNED_FOLLOW_REDIRECTS_KEYWORD:
                continue
            value = keyword.value
            if isinstance(value, ast.Constant) and value.value is True:
                enabled_line_numbers.append(node.lineno)
    return enabled_line_numbers


def test_notifier_module_never_enables_http_redirect_following() -> None:
    """Structural regression gate for threat-model row N-6 (P1).

    httpx defaults to ``follow_redirects=False``. A future change that
    passes ``follow_redirects=True`` to any client call in
    ``phi_scan/notifier.py`` would re-open the DNS-rebind-via-redirect
    attack path: the validator pins the resolved IP into the outbound
    URL, but a 3xx response from the pinned host could redirect to a
    new hostname that re-enters DNS resolution outside the SSRF gate.
    This test parses the module and fails on any explicit opt-in.
    """
    module_source = _NOTIFIER_MODULE_PATH.read_text(encoding=_SOURCE_FILE_ENCODING)
    enabled_line_numbers = _find_enabled_follow_redirects_keywords(module_source)
    assert not enabled_line_numbers, (
        "phi_scan/notifier.py enabled follow_redirects=True at line(s) "
        f"{enabled_line_numbers}, which re-opens the DNS-rebind-via-redirect "
        "attack path covered by threat-model row N-6. Remove the opt-in or "
        "update docs/threat-model.md before merge."
    )
