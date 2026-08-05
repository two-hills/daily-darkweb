"""Email delivery — a redundant notification channel on top of the archived .md/.html
files, which remain the source of truth if delivery fails. Sends only when there is
something to see (alerts or a collector failure), matching the macOS notify behavior.
"""

from __future__ import annotations

import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from daily_darkweb.core.models import Report


class EmailConfig(BaseSettings):
    """SMTP credentials, loaded from env / .env only — never hardcoded."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str
    smtp_password: str
    email_from: str = ""
    email_to: str

    @model_validator(mode="after")
    def _default_from(self) -> EmailConfig:
        if not self.email_from:
            self.email_from = self.smtp_user
        return self

    @property
    def recipients(self) -> list[str]:
        return [addr.strip() for addr in self.email_to.split(",") if addr.strip()]


def should_notify(report: Report) -> bool:
    return report.has_failures or bool(report.alerts)


def build_message(report: Report, html_body: str, config: EmailConfig) -> MIMEMultipart:
    msg = MIMEMultipart("mixed")
    msg["Subject"] = _subject(report)
    msg["From"] = config.email_from
    msg["To"] = ", ".join(config.recipients)

    alt = MIMEMultipart("alternative")
    alt.attach(MIMEText(_plain_text_summary(report), "plain"))
    alt.attach(MIMEText(html_body, "html"))
    msg.attach(alt)

    attachment = MIMEApplication(html_body.encode("utf-8"), _subtype="html")
    filename = f"daily-darkweb-{report.generated_at:%Y-%m-%d}.html"
    attachment.add_header("Content-Disposition", "attachment", filename=filename)
    msg.attach(attachment)
    return msg


def send_message(msg: MIMEMultipart, config: EmailConfig) -> None:
    with smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=30) as server:
        server.starttls()
        server.login(config.smtp_user, config.smtp_password)
        server.sendmail(config.email_from, config.recipients, msg.as_string())


def _subject(report: Report) -> str:
    if report.has_failures:
        return "[Daily Darkweb] Collector FAILURE - do not treat as all-clear"
    if report.alerts:
        # alerts are score-sorted descending by the pipeline, so [0] is the top severity
        top = report.alerts[0].severity.value
        return f"[Daily Darkweb] {len(report.alerts)} alert(s), top severity {top}"
    return "[Daily Darkweb] Clean run, no new alerts"


def _plain_text_summary(report: Report) -> str:
    lines = [f"Daily Darkweb digest — {report.generated_at:%Y-%m-%d %H:%M} UTC", ""]
    for result in report.collector_results:
        status = "OK" if result.status.value == "ok" else f"FAILED ({result.error})"
        lines.append(f"- {result.source}: {status}")
    lines.append("")
    lines.append(f"Watchlist alerts: {len(report.alerts)}")
    lines.append("See the attached/inline HTML report for full details.")
    return "\n".join(lines)
