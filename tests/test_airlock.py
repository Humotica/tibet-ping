"""Tests for airlock.py — posture-gated access control (the trust scalar is dead)."""

from tibet_ping.airlock import Airlock, AirlockRule, AirlockZone, PendingPing, Posture
from tibet_ping.proto import PingDecision, PingPacket, PingType, Priority, RoutingMode


def _pkt(**kwargs):
    defaults = dict(
        packet_id="ping_001",
        source_did="jis:home:sensor",
        target_did="jis:home:hub",
        ping_type=PingType.INTENT,
        priority=Priority.NORMAL,
        routing_mode=RoutingMode.DIRECT,
        intent="temperature.read",
        purpose="Read temp",
    )
    defaults.update(kwargs)
    return PingPacket(**defaults)


def test_groen_zone_known():
    zone, rule = Airlock().gate(_pkt(), Posture.KNOWN)
    assert zone == AirlockZone.GROEN
    assert rule is None


def test_rood_zone_unknown():
    zone, rule = Airlock().gate(_pkt(), Posture.UNKNOWN)
    assert zone == AirlockZone.ROOD


def test_geel_zone_vouched():
    zone, rule = Airlock().gate(_pkt(), Posture.VOUCHED)
    assert zone == AirlockZone.GEEL


def test_rule_override_posture():
    """A rule can force GROEN even for an UNKNOWN sender."""
    airlock = Airlock()
    airlock.add_rule(AirlockRule(
        rule_id="r1", name="Allow all temperature reads",
        pattern={"intent": "temperature.*"},
        decision=PingDecision.ACCEPT, zone=AirlockZone.GROEN,
    ))
    zone, matched = airlock.gate(_pkt(intent="temperature.read"), Posture.UNKNOWN)
    assert zone == AirlockZone.GROEN
    assert matched.name == "Allow all temperature reads"


def test_rule_force_hitl():
    """A rule can force GEEL for a KNOWN sender."""
    airlock = Airlock()
    airlock.add_rule(AirlockRule(
        rule_id="r1", name="Door unlock needs HITL",
        pattern={"intent": "door.unlock"},
        decision=PingDecision.PENDING, zone=AirlockZone.GEEL,
    ))
    zone, _ = airlock.gate(_pkt(intent="door.unlock"), Posture.KNOWN)
    assert zone == AirlockZone.GEEL


def test_min_posture_rule():
    """A rule can require at least a given posture (min_posture)."""
    airlock = Airlock()
    airlock.add_rule(AirlockRule(
        rule_id="r1", name="Known-only unlock",
        pattern={"intent": "door.unlock", "min_posture": "known"},
        decision=PingDecision.ACCEPT, zone=AirlockZone.GROEN,
    ))
    # KNOWN meets the floor -> rule matches -> GROEN
    assert airlock.gate(_pkt(intent="door.unlock"), Posture.KNOWN)[0] == AirlockZone.GROEN
    # VOUCHED does not meet the floor -> rule skipped -> posture default (GEEL)
    assert airlock.gate(_pkt(intent="door.unlock"), Posture.VOUCHED)[0] == AirlockZone.GEEL


def test_rule_priority_ordering():
    """Higher priority rules are checked first."""
    airlock = Airlock()
    airlock.add_rule(AirlockRule(
        rule_id="r_low", name="Low", pattern={"intent": "temperature.*"},
        decision=PingDecision.REJECT, zone=AirlockZone.ROOD, priority=10,
    ))
    airlock.add_rule(AirlockRule(
        rule_id="r_high", name="High", pattern={"intent": "temperature.*"},
        decision=PingDecision.ACCEPT, zone=AirlockZone.GROEN, priority=90,
    ))
    zone, matched = airlock.gate(_pkt(intent="temperature.read"), Posture.VOUCHED)
    assert zone == AirlockZone.GROEN
    assert matched.name == "High"


def test_process_groen_returns_accept():
    assert Airlock().process(_pkt(), Posture.KNOWN) == PingDecision.ACCEPT


def test_process_rood_returns_reject():
    assert Airlock().process(_pkt(), Posture.UNKNOWN) == PingDecision.REJECT


def test_process_geel_adds_to_pending():
    airlock = Airlock()
    decision = airlock.process(_pkt(packet_id="pending_001"), Posture.VOUCHED)
    assert decision == PingDecision.PENDING
    assert "pending_001" in airlock.pending


def test_hitl_callback():
    received = []
    airlock = Airlock(on_hitl_needed=lambda p: received.append(p))
    airlock.process(_pkt(packet_id="hitl_001"), Posture.VOUCHED)
    assert len(received) == 1
    assert received[0].packet.packet_id == "hitl_001"


def test_approve_pending():
    airlock = Airlock()
    airlock.process(_pkt(packet_id="p1"), Posture.VOUCHED)
    assert airlock.approve_pending("p1") is True
    assert "p1" not in airlock.pending
    assert airlock.approve_pending("p1") is False


def test_reject_pending():
    airlock = Airlock()
    airlock.process(_pkt(packet_id="p1"), Posture.VOUCHED)
    assert airlock.reject_pending("p1") is True
    assert "p1" not in airlock.pending


def test_source_did_glob():
    airlock = Airlock()
    airlock.add_rule(AirlockRule(
        rule_id="r1", name="Home devices",
        pattern={"source_did": "jis:home:*"},
        decision=PingDecision.ACCEPT, zone=AirlockZone.GROEN,
    ))
    # rule matches home:* even for an unknown sender
    assert airlock.gate(_pkt(source_did="jis:home:sensor_x"), Posture.UNKNOWN)[0] == AirlockZone.GROEN
    # off-home unknown -> no rule -> ROOD
    assert airlock.gate(_pkt(source_did="jis:office:sensor_x"), Posture.UNKNOWN)[0] == AirlockZone.ROOD


def test_stats():
    airlock = Airlock()
    airlock.add_rule(AirlockRule(
        rule_id="r1", name="Test", pattern={"intent": "*"},
        decision=PingDecision.ACCEPT, zone=AirlockZone.GROEN,
    ))
    stats = airlock.stats()
    assert stats["rules"] == 1
    assert stats["pending_count"] == 0
