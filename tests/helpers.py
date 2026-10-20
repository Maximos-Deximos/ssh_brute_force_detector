# Arquivo feito para testar se a bomba que estou criando realmente funiona
from __future__ import annotations

import datetime as dt
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@dataclass
class FakeClock:
    current: dt.datetime

    def now(self) -> dt.datetime:
        return self.current

    def advance(self, seconds: float) -> None:
        self.current += dt.timedelta(seconds=seconds)


class RecordingNotifier:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def emit(self, kind: str, details: dict[str, Any]) -> None:
        self.events.append((kind, details))


@dataclass
class FakeRunner:
    result: Any = None
    calls: list[list[str]] = field(default_factory=list)
    error: Exception | None = None

    def run(self, argv: list[str], timeout: float) -> Any:
        self.calls.append(list(argv))
        if self.error is not None:
            raise self.error
        return self.result
