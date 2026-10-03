"""Signal, Event, Alert, and Incident data structures."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EventKind(str, Enum):
    CONN = "conn"
    DNS = "dns"
    AUTH = "auth"
    HTTP = "http"
    TLS = "tls"


class Tactic(str, Enum):
    """MITRE ATT&CK enterprise tactics used by sentry_ai."""

    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial-access"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
    UNKNOWN = "unknown"

    @property
    def stage(self) -> int:
        """Position in the kill chain, or -1 for tactics outside it."""
        return KILL_CHAIN.index(self) if self in KILL_CHAIN else -1

    @property
    def attack_id(self) -> str:
        return TACTIC_IDS.get(self, "")


KILL_CHAIN: tuple[Tactic, ...] = (
    Tactic.RECONNAISSANCE,
    Tactic.INITIAL_ACCESS,
    Tactic.CREDENTIAL_ACCESS,
    Tactic.DISCOVERY,
    Tactic.LATERAL_MOVEMENT,
    Tactic.COLLECTION,
    Tactic.COMMAND_AND_CONTROL,
    Tactic.EXFILTRATION,
    Tactic.IMPACT,
)

TACTIC_IDS: dict[Tactic, str] = {
    Tactic.RECONNAISSANCE: "TA0043",
    Tactic.INITIAL_ACCESS: "TA0001",
    Tactic.CREDENTIAL_ACCESS: "TA0006",
    Tactic.DISCOVERY: "TA0007",
    Tactic.LATERAL_MOVEMENT: "TA0008",
    Tactic.COLLECTION: "TA0009",
    Tactic.COMMAND_AND_CONTROL: "TA0011",
    Tactic.EXFILTRATION: "TA0010",
    Tactic.IMPACT: "TA0040",
}


@dataclass(frozen=True, slots=True)
class Event:
    """A normalized telemetry event.

    ``state`` holds the Zeek ``conn_state`` for connections, the response
    code (for example ``NXDOMAIN``) for DNS, and the TLS version for TLS.
    ``query`` is the queried name for DNS, the ``Host`` header for HTTP, and
    the SNI server name for TLS. For HTTP, ``bytes_out``/``bytes_in`` are the
    request and response body sizes. ``label`` is ground truth used only for
    evaluation; detectors must never read it.
    """

    ts: float
    kind: EventKind
    src: str
    dst: str = ""
    dst_port: int = 0
    proto: str = ""
    bytes_out: int = 0
    bytes_in: int = 0
    state: str = ""
    query: str = ""
    user: str = ""
    success: bool = True
    label: str = ""
    method: str = ""
    uri: str = ""
    status: int = 0
    user_agent: str = ""


@dataclass(frozen=True, slots=True)
class Alert:
    """A scored detection for one entity. ``score`` is in [0, 1]."""

    ts: float
    detector: str
    entity: str
    score: float
    tactic: Tactic
    technique: str
    summary: str
    related: tuple[str, ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict, hash=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts": self.ts,
            "detector": self.detector,
            "entity": self.entity,
            "score": round(self.score, 4),
            "tactic": self.tactic.value,
            "tactic_id": self.tactic.attack_id,
            "technique": self.technique,
            "summary": self.summary,
            "related": list(self.related),
            "evidence": self.evidence,
        }


@dataclass(slots=True)
class Incident:
    """An open or closed investigation for one entity."""

    id: str
    entity: str
    opened: float
    updated: float
    risk: float
    level: str
    stage: str
    tactics: list[str]
    next_stages: list[str]
    alerts: list[Alert]
    related_entities: list[str]
    explanation: list[dict[str, Any]]
    closed: float | None = None

    @property
    def is_open(self) -> bool:
        return self.closed is None

    def to_dict(self, max_alerts: int = 50) -> dict[str, Any]:
        return {
            "id": self.id,
            "entity": self.entity,
            "opened": self.opened,
            "updated": self.updated,
            "closed": self.closed,
            "status": "open" if self.is_open else "closed",
            "risk": round(self.risk, 4),
            "level": self.level,
            "stage": self.stage,
            "tactics": self.tactics,
            "next_stages": self.next_stages,
            "related_entities": self.related_entities,
            "explanation": self.explanation,
            "alerts": [a.to_dict() for a in self.alerts[-max_alerts:]],
        }
