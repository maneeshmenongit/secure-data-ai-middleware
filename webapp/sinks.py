"""Observable mock sinks: they record what reached them and never touch the network."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class MockPaymentTool:
    def __init__(self) -> None:
        self.calls: list[Any] = []

    def call(self, args: Any) -> str:
        self.calls.append(args)
        return f"payment tool invoked (call #{len(self.calls)}, nothing was really sent)"

    def reset(self) -> None:
        self.calls.clear()


@dataclass
class Sinks:
    payment: MockPaymentTool = field(default_factory=MockPaymentTool)

    def reset(self) -> None:
        self.payment.reset()
