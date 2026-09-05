"""Conformance-vectoren voor de relationele stilte (#169, Jaspers fiat 5 sep 2026).

    Stil voor de peer mag; onzichtbaar voor iedereen niet.
    A null route is not an empty answer; it is a refusal to spend the system
    on an unadmitted question.

Elke guard wordt op z'n WEIGERING getoetst, niet op z'n groen.
"""
from __future__ import annotations

import asyncio

import pytest

from tibet_ping import PingDecision, PingResponse
from tibet_ping.refusal import (
    HELD_CODE,
    REFUSAL_CODE,
    SPEAKS_OUTWARD,
    RefusalMeter,
    refusal_response,
)
from tibet_ping.transport.iot_node import IoTNode

from conftest_transport import MockTransport


def _full_response(posture: str = "known") -> PingResponse:
    r = PingResponse(response_id="resp_1", in_response_to="pkt_1",
                     responder_did="jis:dl360:hub", decision=PingDecision.REJECT)
    r.posture = posture
    r.capabilities = ["mcp", "cmail", "overlay"]
    r.fira_breakdown = {"familiarity": 0.1, "intent": 0.0}
    r.payload = {"internal": "why exactly it was refused"}
    r.tibet_token_id = "tok_secret"
    return r


# --- 1. DE PROJECTIE TREKT AF -------------------------------------------------------------

def test_refusal_strips_everything_the_peer_may_not_learn():
    out = refusal_response(_full_response())
    assert out.payload == {"status": "refused", "code": REFUSAL_CODE}
    # HET VOLLE ANTWOORD DRAAGT capabilities/fira/posture — dat rauw terugsturen ZOU het lek zijn
    # dat de oorspronkelijke stilte juist voorkwam.
    assert not out.capabilities and not out.fira_breakdown
    assert out.tibet_token_id is None
    assert out.posture == "unknown"          # de dataclass-default, niet de echte posture
    # DE TWEE DIE IK MISTE MET EEN ZWARTE LIJST, en die deze vector vond:
    assert out.applied_rule is None          # zou zeggen WELKE regel je weigerde
    # `airlock_zone` is GEEN lek: "ROOD" is de hardgecodeerde dataclass-default (een verse
    # ACCEPT zegt 'm ook), dus het veld draagt niets uit het origineel mee en zegt niets over
    # DIT besluit. De guard toetst daarom op "gelijk aan een verse response", niet op leeg.
    blank = PingResponse(response_id="", in_response_to="", responder_did="",
                         decision=PingDecision.REJECT)
    assert out.airlock_zone == blank.airlock_zone


def test_the_peer_can_still_correlate_his_own_request():
    out = refusal_response(_full_response())
    assert out.in_response_to == "pkt_1" and out.responder_did == "jis:dl360:hub"


def test_the_code_stays_blunt_never_diagnostic():
    # Een fijnmazige code is een orakel dat een vreemde vertelt welke deur hij raakte.
    assert REFUSAL_CODE == "0x0000:unauthorized-or-not-admitted"
    assert HELD_CODE == "0x0000:held-for-review"
    assert "nonce" not in REFUSAL_CODE and "replay" not in REFUSAL_CODE


def test_only_an_established_relationship_is_spoken_to():
    # `vouched` is onderhandeling, nog geen relatie -> stilte beschermt daar nog.
    # `unknown` is de deflectie-vloer.
    assert SPEAKS_OUTWARD == ("known",)
    assert "vouched" not in SPEAKS_OUTWARD and "unknown" not in SPEAKS_OUTWARD


# --- 2. DE METER MAG DE AANVAL NIET WORDEN ------------------------------------------------

def test_an_unadmitted_flood_costs_counters_not_records():
    """Richard haalde 3,1 miljoen acties in seconden uit een 32GB-GPU met agents.

    Als elke gedropte ping een record schrijft is de WAARNEMING de amplificatie geworden.
    """
    m = RefusalMeter(log_every=100_000)
    for i in range(50_000):
        m.record(posture="unknown", source_did="jis:flood:%d" % i, spoke=False)
    assert m.total == 50_000
    # BEGRENSD: hooguit 32 distincte bronnen onthouden, de rest eerlijk als overflow geteld.
    assert len(m.sources) == 32
    assert m.overflowed == 50_000 - 32
    snap = m.snapshot()
    assert snap["sources_untracked"] == m.overflowed
    assert len(snap["top_sources"]) <= 8


def test_the_meter_separates_silent_from_answered():
    m = RefusalMeter(log_every=100_000)
    m.record(posture="known", source_did="jis:laptop:jasper", spoke=True)
    for _ in range(9):
        m.record(posture="unknown", source_did="jis:stranger:x", spoke=False)
    snap = m.snapshot()
    assert snap["total"] == 10 and snap["answered_outward"] == 1 and snap["silent"] == 9
    assert snap["by_posture"] == {"known": 1, "unknown": 9}


def test_the_meter_surfaces_itself_periodically():
    """`decision_without_observation` was de fout: de beslissing bestond, niemand zag 'm."""
    m = RefusalMeter(log_every=5)
    out = [m.record(posture="unknown", source_did="jis:x:1", spoke=False) for _ in range(10)]
    assert sum(1 for o in out if o is not None) == 2      # bij 5 en bij 10
    assert all(o is None for o in out[:4])


def test_the_snapshot_carries_only_sums_never_events():
    m = RefusalMeter()
    m.record(posture="unknown", source_did="jis:x:1", spoke=False)
    snap = m.snapshot()
    for forbidden in ("packet_id", "intent", "payload", "nonce"):
        assert forbidden not in snap


# --- 3. HET DROPPUNT ZELF ------------------------------------------------------------------

def _reject_at(node: IoTNode, posture: str):
    """Laat de node een REJECT verwerken met een gegeven posture, en meld wat er verzonden is."""
    resp = _full_response(posture)
    node._ping_node.receive = lambda packet: resp           # type: ignore[assignment]
    packet = node._ping_node.ping(target=node.device_did, intent="lan.test", purpose="p")
    packet.source_did = "jis:peer:test"
    before = len(node._transport.sent_raw)
    asyncio.run(
        node._handle_incoming(packet, ("127.0.0.1", 7151)))
    return len(node._transport.sent_raw) - before


@pytest.mark.parametrize("posture,expected_sent", [
    ("known", 1),        # relatie bestaat -> stilte zou 'm beschadigen
    ("vouched", 0),      # onderhandeling -> stilte beschermt nog
    ("unknown", 0),      # geen relatie -> de deflectie-vloer, 0x0000 blijft
])
def test_the_silence_is_relational(posture, expected_sent):
    t = MockTransport()
    node = IoTNode("jis:dl360:hub", transport=t)
    assert _reject_at(node, posture) == expected_sent
    # EN ALTIJD GETELD — onzichtbaar voor iedereen mag nooit.
    assert node._refusals.total == 1
    assert node._refusals.by_posture == {posture: 1}


def test_a_refused_known_peer_gets_the_stripped_projection_not_the_answer():
    t = MockTransport()
    node = IoTNode("jis:dl360:hub", transport=t)
    _reject_at(node, "known")
    raw, _addr = t.sent_raw[-1]
    body = raw.decode("utf-8", "replace")
    assert "refused" in body and REFUSAL_CODE in body
    # De interne velden van het volle antwoord mogen er NIET in zitten.
    for leak in ("why exactly it was refused", "tok_secret", "cmail", "familiarity"):
        assert leak not in body, "refusal leaked %r" % leak
