"""
Ping processing engine.

Integrates nonce tracking, airlock posture-gating, vouching, and TIBET provenance.
Zero-trust by identity: the gate keys on posture (known / vouched / unknown), never a scalar.
"""

import secrets
from datetime import datetime, timezone
from typing import Dict, Iterable, Optional, Tuple

from .airlock import Airlock, Posture
from .nonce import NonceTracker
from .proto import PingDecision, PingPacket, PingResponse
from .vouch import VouchRegistry

# Optional tibet-core integration
try:
    from tibet_core import Provider, MemoryStore
    HAS_TIBET_CORE = True
except ImportError:
    HAS_TIBET_CORE = False


class PingHandler:
    """
    Process incoming ping packets.

    Pipeline:
        1. Replay check (nonce)
        2. Posture lookup (known devices + vouching)
        3. Airlock posture-gating (GROEN/GEEL/ROOD)
        4. TIBET audit token (if tibet-core available)
        5. Response
    """

    def __init__(
        self,
        device_did: str,
        airlock: Airlock,
        nonce_tracker: NonceTracker,
        vouch_registry: VouchRegistry,
        known_devices: Optional[Iterable[str]] = None,
        tibet_actor: Optional[str] = None,
    ) -> None:
        self.device_did = device_did
        self.airlock = airlock
        self.nonce_tracker = nonce_tracker
        self.vouch_registry = vouch_registry
        self._known: set = set(known_devices or ())

        # TIBET provenance (optional)
        self._tibet = None
        if HAS_TIBET_CORE:
            self._tibet = Provider(
                actor=tibet_actor or device_did,
                store=MemoryStore(),
            )

    def set_known(self, did: str) -> None:
        """Mark a device as a KNOWN sender (a structural fact — no scalar)."""
        self._known.add(did)

    def forget(self, did: str) -> None:
        """Drop a device back to UNKNOWN posture."""
        self._known.discard(did)

    def handle(self, packet: PingPacket) -> PingResponse:
        """Process an incoming ping packet. Returns PingResponse with decision."""
        start = datetime.now(timezone.utc)

        # 1. Replay protection
        if self.nonce_tracker.is_replay(packet.nonce, packet.timestamp):
            return self._make_response(
                packet, PingDecision.REJECT, "ROOD",
                posture=Posture.UNKNOWN, reason="replay_detected",
            )

        # 2. Sender posture (structural, not scalar)
        posture, fira = self._get_sender_posture(packet.source_did)

        # 3. Airlock posture-gating
        decision = self.airlock.process(packet, posture)
        zone, rule = self.airlock.gate(packet, posture)

        # 4. TIBET audit token
        token_id = None
        if self._tibet:
            token = self._tibet.create(
                action="ping_received",
                erin=packet.to_tibet_erin(),
                eraan=[packet.tibet_token_id] if packet.tibet_token_id else [],
                eromheen={
                    **packet.to_tibet_eromheen(),
                    "handler_did": self.device_did,
                    "sender_posture": posture.value,
                    "decision": decision.value,
                },
                erachter=packet.purpose,
            )
            token_id = token.token_id

        # 5. Build response
        end = datetime.now(timezone.utc)
        rtt_ms = (end - start).total_seconds() * 1000

        return PingResponse(
            response_id=f"resp_{secrets.token_hex(8)}",
            in_response_to=packet.packet_id,
            responder_did=self.device_did,
            decision=decision,
            posture=posture.value,
            fira_breakdown=fira,
            tibet_token_id=token_id,
            airlock_zone=zone.value,
            applied_rule=rule.name if rule else None,
            rtt_ms=rtt_ms,
        )

    def _get_sender_posture(self, source_did: str) -> Tuple[Posture, dict]:
        """
        The sender's structural posture — the whole trust input.

        Priority:
            1. Known devices set     -> KNOWN
            2. Vouch registry        -> VOUCHED
            3. Neither               -> UNKNOWN
        """
        if source_did in self._known:
            return (Posture.KNOWN, {"posture": "known", "source": "known"})

        if self.vouch_registry.get_trust_for_device(source_did) is not None:
            vouches = self.vouch_registry.get_vouches_for_device(source_did)
            return (Posture.VOUCHED, {"posture": "vouched", "source": "vouched",
                                      "vouch_count": len(vouches)})

        return (Posture.UNKNOWN, {"posture": "unknown", "source": "unknown"})

    def _make_response(
        self,
        packet: PingPacket,
        decision: PingDecision,
        zone: str,
        posture: Posture = Posture.UNKNOWN,
        reason: str = "",
    ) -> PingResponse:
        """Quick helper for simple responses."""
        return PingResponse(
            response_id=f"resp_{secrets.token_hex(8)}",
            in_response_to=packet.packet_id,
            responder_did=self.device_did,
            decision=decision,
            airlock_zone=zone,
            posture=posture.value,
            payload={"reason": reason} if reason else {},
        )
