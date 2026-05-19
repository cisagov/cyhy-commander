"""Unit tests for _authenticate() bearer token middleware.

Tests the authentication logic for the /metrics endpoint, covering:
- No token configured (open access)
- Valid bearer token
- Missing Authorization header
- Malformed Authorization header
- Wrong token
- Constant-time comparison via hmac.compare_digest

**Validates: Requirements 7.1, 7.2, 7.3, 7.4, 7.5**
"""

from unittest.mock import patch

import cyhy_commander.metrics as metrics
from cyhy_commander.metrics import _authenticate, get_bearer_token


class TestAuthenticateNoToken:
    """Tests when no bearer token is configured (Requirement 7.3)."""

    def test_returns_true_when_no_token_configured(self) -> None:
        """All requests are allowed when _bearer_token is None."""
        with patch.object(metrics, "_bearer_token", None):
            environ = {"HTTP_AUTHORIZATION": "Bearer anything"}
            assert _authenticate(environ) is True

    def test_returns_true_with_no_auth_header_when_no_token(self) -> None:
        """Missing auth header is fine when no token is configured."""
        with patch.object(metrics, "_bearer_token", None):
            environ = {}
            assert _authenticate(environ) is True


class TestAuthenticateWithToken:
    """Tests when a bearer token is configured (Requirements 7.1, 7.2, 7.4)."""

    def test_returns_true_for_valid_token(self) -> None:
        """Valid Bearer token matches configured token."""
        with patch.object(metrics, "_bearer_token", "my-secret-token"):
            environ = {"HTTP_AUTHORIZATION": "Bearer my-secret-token"}
            assert _authenticate(environ) is True

    def test_returns_false_for_missing_auth_header(self) -> None:
        """Missing Authorization header returns False."""
        with patch.object(metrics, "_bearer_token", "my-secret-token"):
            environ = {}
            assert _authenticate(environ) is False

    def test_returns_false_for_empty_auth_header(self) -> None:
        """Empty Authorization header returns False."""
        with patch.object(metrics, "_bearer_token", "my-secret-token"):
            environ = {"HTTP_AUTHORIZATION": ""}
            assert _authenticate(environ) is False

    def test_returns_false_for_wrong_token(self) -> None:
        """Wrong token value returns False."""
        with patch.object(metrics, "_bearer_token", "my-secret-token"):
            environ = {"HTTP_AUTHORIZATION": "Bearer wrong-token"}
            assert _authenticate(environ) is False

    def test_returns_false_for_malformed_header_no_bearer_prefix(self) -> None:
        """Header without 'Bearer ' prefix returns False."""
        with patch.object(metrics, "_bearer_token", "my-secret-token"):
            environ = {"HTTP_AUTHORIZATION": "Basic my-secret-token"}
            assert _authenticate(environ) is False

    def test_returns_false_for_bearer_lowercase(self) -> None:
        """'bearer' (lowercase) prefix is not accepted."""
        with patch.object(metrics, "_bearer_token", "my-secret-token"):
            environ = {"HTTP_AUTHORIZATION": "bearer my-secret-token"}
            assert _authenticate(environ) is False

    def test_returns_false_for_token_only_no_prefix(self) -> None:
        """Token without any prefix returns False."""
        with patch.object(metrics, "_bearer_token", "my-secret-token"):
            environ = {"HTTP_AUTHORIZATION": "my-secret-token"}
            assert _authenticate(environ) is False

    def test_uses_hmac_compare_digest(self) -> None:
        """Verify constant-time comparison is used (Requirement 7.4)."""
        with patch.object(metrics, "_bearer_token", "my-secret-token"):
            with patch("cyhy_commander.metrics.hmac.compare_digest") as mock_compare:
                mock_compare.return_value = True
                environ = {"HTTP_AUTHORIZATION": "Bearer my-secret-token"}
                result = _authenticate(environ)
                mock_compare.assert_called_once_with(
                    "my-secret-token", "my-secret-token"
                )
                assert result is True


class TestGetBearerTokenWarning:
    """Tests for token length warning at startup (Requirement 7.5)."""

    def test_logs_warning_for_short_token(self, caplog) -> None:
        """Token shorter than 8 chars logs a warning."""
        import logging

        with caplog.at_level(logging.WARNING):
            with patch.dict("os.environ", {"CYHY_METRICS_BEARER_TOKEN": "short"}):
                token = get_bearer_token()
                assert token == "short"
                assert "shorter than 8 characters" in caplog.text

    def test_no_warning_for_long_token(self, caplog) -> None:
        """Token of 8+ chars does not log a warning."""
        import logging

        with caplog.at_level(logging.WARNING):
            with patch.dict(
                "os.environ", {"CYHY_METRICS_BEARER_TOKEN": "long-enough-token"}
            ):
                token = get_bearer_token()
                assert token == "long-enough-token"
                assert "shorter than 8 characters" not in caplog.text

    def test_returns_none_when_unset(self) -> None:
        """Returns None when env var is not set."""
        import os

        env = os.environ.copy()
        env.pop("CYHY_METRICS_BEARER_TOKEN", None)
        with patch.dict("os.environ", env, clear=True):
            assert get_bearer_token() is None

    def test_returns_none_when_empty(self) -> None:
        """Returns None when env var is empty string."""
        with patch.dict("os.environ", {"CYHY_METRICS_BEARER_TOKEN": ""}):
            assert get_bearer_token() is None
