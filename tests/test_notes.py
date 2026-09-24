from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from daily_darkweb.core.models import AnalystNotes


def _notes(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "headline": "Edge-device exploitation is accelerating",
        "points": ["KEV additions doubled week over week."],
        "actions": ["Patch internet-facing gateways first."],
        "caveats": ["History covers 5 days only."],
    }
    base.update(overrides)
    return base


def test_valid_notes_are_accepted_and_trimmed() -> None:
    notes = AnalystNotes.model_validate(_notes(points=["  padded point  "]))
    assert notes.points == ["padded point"]


def test_actions_and_caveats_are_optional() -> None:
    notes = AnalystNotes.model_validate({"headline": "h", "points": ["p"]})
    assert notes.actions == []
    assert notes.caveats == []


@pytest.mark.parametrize(
    "text",
    [
        "Details at https://evil.example/login",
        "see http://x.example",
        "mirror: ftp://files.example/drop",
        "visit www.evil.example today",
        "HTTPS://SHOUTING.EXAMPLE",
    ],
)
def test_links_are_rejected_in_any_field(text: str) -> None:
    for field in ("headline", "points", "actions", "caveats"):
        value = text if field == "headline" else [text]
        with pytest.raises(ValidationError, match="links are not allowed"):
            AnalystNotes.model_validate(_notes(**{field: value}))


def test_plain_domain_names_are_allowed() -> None:
    # Victim names are often domains; only clickable URL forms are refused.
    notes = AnalystNotes.model_validate(_notes(points=["goldstarfinancial.com was claimed."]))
    assert "goldstarfinancial.com" in notes.points[0]


@pytest.mark.parametrize(
    "overrides",
    [
        {"points": []},
        {"points": ["p"] * 7},
        {"points": ["   "]},
        {"points": ["x" * 401]},
        {"headline": "x" * 201},
        {"actions": ["a"] * 6},
        {"caveats": ["c"] * 4},
        {"unexpected": "field"},
    ],
)
def test_out_of_bounds_notes_are_rejected(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        AnalystNotes.model_validate(_notes(**overrides))
