from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from daily_darkweb.core.models import (
    Alert,
    CollectionStatus,
    CollectResult,
    Match,
    MatchField,
    Report,
    Severity,
)
from daily_darkweb.interface.email_send import (
    EmailConfig,
    build_message,
    send_message,
    should_notify,
)
from tests.conftest import make_item


def _config(**overrides: object) -> EmailConfig:
    defaults: dict[str, object] = {
        "smtp_user": "me@gmail.com",
        "smtp_password": "app-password",
        "email_to": "me@gmail.com, boss@example.com",
    }
    defaults.update(overrides)
    return EmailConfig(_env_file=None, **defaults)  # type: ignore[arg-type]


def _report(alerts: list[Alert], has_failure: bool = False) -> Report:
    results = [CollectResult(source="ransomware_live", status=CollectionStatus.OK, items=[])]
    if has_failure:
        results.append(
            CollectResult(source="cisa_kev", status=CollectionStatus.FAILED, error="timeout")
        )
    return Report(
        generated_at=datetime(2026, 7, 27, tzinfo=UTC),
        collector_results=results,
        alerts=alerts,
        observations=[],
    )


def _alert(severity: Severity, score: int) -> Alert:
    item = make_item(sector=None, country=None, victim_domain=None)
    return Alert(
        item=item,
        matches=[Match(field=MatchField.ORG, watch_value="x", matched_text="x")],
        score=score,
        severity=severity,
    )


def test_should_notify_true_on_alerts() -> None:
    assert should_notify(_report([_alert(Severity.HIGH, 68)])) is True


def test_should_notify_true_on_failure_even_without_alerts() -> None:
    assert should_notify(_report([], has_failure=True)) is True


def test_should_notify_false_on_clean_run() -> None:
    assert should_notify(_report([])) is False


def test_config_defaults_from_missing_email_from() -> None:
    config = _config()
    assert config.email_from == "me@gmail.com"
    assert config.recipients == ["me@gmail.com", "boss@example.com"]


def test_config_requires_identity() -> None:
    with pytest.raises(ValidationError):
        EmailConfig(_env_file=None)  # type: ignore[call-arg]


def test_config_raises_when_password_missing_everywhere() -> None:
    with (
        patch("daily_darkweb.interface.email_send.keychain_password", return_value=None),
        pytest.raises(ValidationError, match="no SMTP password"),
    ):
        EmailConfig(  # type: ignore[call-arg]
            _env_file=None, smtp_user="me@gmail.com", email_to="me@gmail.com"
        )


def test_config_falls_back_to_keychain_password() -> None:
    with patch(
        "daily_darkweb.interface.email_send.keychain_password", return_value="from-keychain"
    ) as mock_kc:
        config = EmailConfig(  # type: ignore[call-arg]
            _env_file=None, smtp_user="me@gmail.com", email_to="me@gmail.com"
        )
        assert config.smtp_password == "from-keychain"
        mock_kc.assert_called_once_with("claude-email-notify")


def test_config_env_password_takes_priority_over_keychain() -> None:
    with patch("daily_darkweb.interface.email_send.keychain_password") as mock_kc:
        config = _config(smtp_password="from-env")
        assert config.smtp_password == "from-env"
        mock_kc.assert_not_called()


def test_subject_reflects_failure_over_alerts() -> None:
    msg = build_message(
        _report([_alert(Severity.CRITICAL, 95)], has_failure=True), "<p>x</p>", _config()
    )
    assert "FAILURE" in msg["Subject"]


def test_subject_reflects_top_alert_severity() -> None:
    msg = build_message(_report([_alert(Severity.HIGH, 68)]), "<p>x</p>", _config())
    assert "1 alert" in msg["Subject"]
    assert "high" in msg["Subject"]


def test_message_has_html_and_attachment_parts() -> None:
    msg = build_message(_report([_alert(Severity.MEDIUM, 56)]), "<p>hello</p>", _config())
    content_types = {part.get_content_type() for part in msg.walk()}
    assert "text/plain" in content_types  # inline fallback for plain-text mail clients
    assert "text/html" in content_types  # inline body, readable without opening the attachment
    assert "application/html" in content_types  # the .html attachment


def test_send_message_uses_smtp_ssl_and_login() -> None:
    config = _config()
    msg = build_message(_report([_alert(Severity.HIGH, 68)]), "<p>x</p>", config)
    with patch("daily_darkweb.interface.email_send.smtplib.SMTP_SSL") as smtp_cls:
        server = MagicMock()
        smtp_cls.return_value.__enter__.return_value = server
        send_message(msg, config)
        smtp_cls.assert_called_once_with(config.smtp_host, config.smtp_port, timeout=30)
        server.login.assert_called_once_with(config.smtp_user, config.smtp_password)
        server.sendmail.assert_called_once()
