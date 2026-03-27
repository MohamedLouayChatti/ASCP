from enum import Enum
from dataclasses import dataclass, field


class ScanSurface(Enum):
    OUTPUT = "OUTPUT"
    TOOL_ARGS = "TOOL_ARGS"
    TOOL_RESULT = "TOOL_RESULT"


class DLPAction(Enum):
    ALLOW = 0
    REDACT = 1
    ESCALATE = 2
    BLOCK = 3

    @property
    def priority(self) -> int:
        return self.value

    # Allow comparison based on priority
    def __lt__(self, other: "DLPAction") -> bool:
        return self.priority < other.priority

    def __le__(self, other: "DLPAction") -> bool:
        return self.priority <= other.priority

    def __gt__(self, other: "DLPAction") -> bool:
        return self.priority > other.priority

    def __ge__(self, other: "DLPAction") -> bool:
        return self.priority >= other.priority


@dataclass
class DLPMatch:
    pattern_name: str
    category: str  # "secret" or "pii"
    action: DLPAction
    value: str     # The actual matched string
    spans: list[tuple[int, int]]  # List of (start, end) tuples
    surface: ScanSurface


@dataclass
class CanaryHit:
    token: str
    label: str
    context_excerpt: str
    surface: ScanSurface


@dataclass
class DLPResult:
    original_text: str
    clean_text: str
    action: DLPAction
    surface: ScanSurface
    canary_hits: list[CanaryHit] = field(default_factory=list)
    secret_matches: list[DLPMatch] = field(default_factory=list)
    pii_matches: list[DLPMatch] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)

    @property
    def has_violations(self) -> bool:
        return bool(self.canary_hits or self.secret_matches or self.pii_matches)

    @property
    def should_block(self) -> bool:
        return self.action == DLPAction.BLOCK

    @property
    def invariant_violated(self) -> str | None:
        if self.canary_hits or self.secret_matches:
            return "I3"
        return None


@dataclass
class EnforcementDecision:
    action: DLPAction
    clean_text: str
    violations: list[str]
    should_block: bool
    should_escalate: bool
    safe_message: str | None = None
    escalation_event: dict | None = None
    dlp_result: DLPResult | None = None
