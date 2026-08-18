"""
Posture-gated access control for incoming pings.

Zero-trust by identity, not by a scalar: the gate keys on the SENDER'S POSTURE — a structural fact
(known / vouched / unknown) — never a 0.0-1.0 trust number. The scalar is dead.

Three zones map directly from posture:
    KNOWN   → GROEN — auto-allow
    VOUCHED → GEEL  — pending (rules or HITL)
    UNKNOWN → ROOD  — silent drop (no info leak)
"""

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple

from .proto import PingDecision, PingPacket


class Posture(Enum):
    """The sender's structural standing — the trust input, replacing the legacy scalar."""
    KNOWN = "known"
    VOUCHED = "vouched"
    UNKNOWN = "unknown"


class AirlockZone(Enum):
    """Three-zone access model."""
    GROEN = "GROEN"
    GEEL = "GEEL"
    ROOD = "ROOD"


# Posture is the whole trust input now — a structural fact maps straight to a zone.
_POSTURE_ZONE: Dict[Posture, AirlockZone] = {
    Posture.KNOWN: AirlockZone.GROEN,
    Posture.VOUCHED: AirlockZone.GEEL,
    Posture.UNKNOWN: AirlockZone.ROOD,
}


@dataclass
class AirlockRule:
    """
    Pattern-based auto-decision rule (checked before the posture default; highest priority first).

    Patterns support simple glob on identity/intent fields (never a trust number):
        {"source_did": "jis:home:*", "intent": "temperature.*"} → GROEN
        {"intent": "door.unlock"} → GEEL (force HITL)
        {"min_posture": "known"} → require at least a known sender
    """
    rule_id: str
    name: str
    pattern: Dict[str, str]
    decision: PingDecision
    zone: AirlockZone
    priority: int = 50  # Higher = checked first

    def matches(self, packet: PingPacket, posture: Posture) -> bool:
        """Check if packet matches this rule's pattern."""
        _rank = {Posture.UNKNOWN: 0, Posture.VOUCHED: 1, Posture.KNOWN: 2}
        for key, pattern in self.pattern.items():
            if key == "source_did":
                if not _glob_match(packet.source_did, pattern):
                    return False
            elif key == "intent":
                if not _glob_match(packet.intent, pattern):
                    return False
            elif key == "pod_id":
                if packet.pod_id != pattern:
                    return False
            elif key == "ping_type":
                if packet.ping_type.value != pattern:
                    return False
            elif key == "min_posture":
                if _rank.get(posture, 0) < _rank.get(Posture(pattern), 0):
                    return False
        return True


def _glob_match(value: str, pattern: str) -> bool:
    """Simple glob: *, prefix*, *suffix, exact."""
    if pattern == "*":
        return True
    if pattern.startswith("*") and pattern.endswith("*") and len(pattern) > 2:
        return pattern[1:-1] in value
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    if pattern.startswith("*"):
        return value.endswith(pattern[1:])
    return value == pattern


@dataclass
class PendingPing:
    """Ping awaiting HITL decision."""
    packet: PingPacket
    posture: Posture
    reason: str


class Airlock:
    """
    Posture-gated access control.

    Rules are checked first (highest priority wins); otherwise the sender's posture maps to a zone.
    GEEL pings go to the pending queue and trigger on_hitl_needed.
    """

    def __init__(
        self,
        on_hitl_needed: Optional[Callable[[PendingPing], None]] = None,
    ) -> None:
        self.on_hitl_needed = on_hitl_needed
        self._rules: List[AirlockRule] = []
        self.pending: Dict[str, PendingPing] = {}

    def add_rule(self, rule: AirlockRule) -> None:
        """Add a rule (auto-sorted by priority, highest first)."""
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority, reverse=True)

    @property
    def rules(self) -> List[AirlockRule]:
        return list(self._rules)

    def gate(
        self, packet: PingPacket, posture: Posture
    ) -> Tuple[AirlockZone, Optional[AirlockRule]]:
        """Determine zone for a packet. Returns (zone, matched_rule_or_None)."""
        for rule in self._rules:
            if rule.matches(packet, posture):
                return (rule.zone, rule)
        return (_POSTURE_ZONE[posture], None)

    def process(self, packet: PingPacket, posture: Posture) -> PingDecision:
        """Full processing: gate → decision → pending queue if GEEL."""
        zone, rule = self.gate(packet, posture)

        if zone == AirlockZone.GROEN:
            return PingDecision.ACCEPT
        if zone == AirlockZone.ROOD:
            return PingDecision.REJECT

        # GEEL: add to pending
        pending = PendingPing(
            packet=packet,
            posture=posture,
            reason=f"Posture {posture.value} in GEEL zone"
            + (f" (rule: {rule.name})" if rule else ""),
        )
        self.pending[packet.packet_id] = pending

        if self.on_hitl_needed:
            self.on_hitl_needed(pending)

        return PingDecision.PENDING

    def approve_pending(self, packet_id: str) -> bool:
        """HITL approves a pending ping."""
        return self.pending.pop(packet_id, None) is not None

    def reject_pending(self, packet_id: str) -> bool:
        """HITL rejects a pending ping."""
        return self.pending.pop(packet_id, None) is not None

    def stats(self) -> dict:
        return {
            "rules": len(self._rules),
            "pending_count": len(self.pending),
            "model": "posture (known->GROEN, vouched->GEEL, unknown->ROOD)",
        }
