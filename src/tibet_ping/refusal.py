"""refusal — de stilte is relationeel, en de waarneming mag de aanval niet worden.

Jasper, 5 september 2026, na een live meting waarin de hub op .76 elke ping stil liet vallen en
geweigerd, vastgehouden en onbereikbaar bij de beller als één timeout aankwamen:

    Stil voor de peer mag; onzichtbaar voor iedereen niet.
    De beslissing is 1 maar de projectie relationeel.
    Voor consent beschermt stilte de relatie die nog niet bestaat;
    na consent beschadigt stilte de relatie die wél bestaat.

## WAAROM DE NULL ROUTE BLIJFT, EN WAAROM DIT MODULE ZUINIG IS

    A null route is not an empty answer;
    it is a refusal to spend the system on an unadmitted question.

Dat is geen filosofie maar de vloer onder een DDoS-afweer: Richard haalde 3,1 miljoen acties in
luttele seconden uit één 32GB-GPU met agents. Als elke gedropte ping een record schrijft, dan is
de WAARNEMING de amplificatie geworden en hebben we het gat zelf gegraven — zie
`the auditor may not become the attack`.

Daarom kost een niet-toegelaten vraag hier precies één integer-ophoging. Geen record, geen
allocatie per pakket, geen antwoord. Wie wél een relatie heeft, krijgt een antwoord én een
regel; wie er geen heeft, telt mee in een som die de eigenaar kan lezen.

## DRIE ASSEN VOOR ÉÉN GEBEURTENIS (Jaspers splitsing)

    silent_drop                    wat de PEER ziet:      geen antwoord
    intentional_drop               wat de RECEIVER doet:  bewust geen route materialiseren
    decision_without_observation   wat het SYSTEEM fout doet: de beslissing bestaat,
                                                             maar geen lokale lezer ziet 'm

De derde is de fout die we hier repareren. Hij was live aanwezig: de ROOD-drop logde op `debug`
terwijl het proces op `info` draait — aanwezig, correct, en voor niemand waarneembaar.
"""

from __future__ import annotations

from dataclasses import fields
from typing import Dict, Optional

from .proto import PingDecision, PingResponse

# WELKE POSTURE EEN GEVESTIGDE RELATIE DRAAGT. Alleen deze trede krijgt een weigering te horen.
# `vouched` staat er met opzet NIET in: dat is onderhandeling, nog geen relatie, dus de stilte
# beschermt daar nog. `unknown` is de deflectie-vloer.
SPEAKS_OUTWARD = ("known",)

# CANONIEKE CODES. Kort en stomp: ze zeggen DAT er geweigerd is, nooit waarom precies. Een
# fijnmazige code is een orakel dat een vreemde vertelt welke deur hij raakte.
REFUSAL_CODE = "0x0000:unauthorized-or-not-admitted"
HELD_CODE = "0x0000:held-for-review"

# WAT EEN GEWEIGERDE PEER WÉL MAG ZIEN. Een WITTE lijst, met opzet.
#
# Ik begon met een zwarte lijst van vijf verboden velden. De testvector vond er meteen twee die
# ik gemist had: `airlock_zone` (die "ROOD" naar buiten droeg) en `applied_rule` (die zou zeggen
# WELKE regel je weigerde — precies het orakel dat we dichthouden). PingResponse heeft dertien
# velden; een zwarte lijst moet je bijhouden en een nieuw veld glipt er stilzwijgend langs.
#
# Omgekeerd weigert 'ie vanzelf: alles wat hier niet staat MOET gelijk zijn aan de default, dus
# een veld dat morgen aan PingResponse wordt toegevoegd breekt de test i.p.v. te lekken.
_PEER_MAY_SEE = ("response_id", "in_response_to", "responder_did", "decision", "payload",
                 "timestamp")

# HOEVEEL DISTINCTE BRONNEN DE METER ONTHOUDT. Begrensd, want een aanvaller mag de meter niet
# als geheugenlek gebruiken — dat zou de tweede versie van dezelfde fout zijn.
_MAX_TRACKED = 32


def refusal_response(original: PingResponse, *, code: str = REFUSAL_CODE) -> PingResponse:
    """De `consented`-projectie van een REJECT: bereikbaar-en-weigerend, verder niets.

    Trekt af, voegt niets toe. De peer moet `geweigerd` van `onbereikbaar` kunnen onderscheiden
    en verder niets leren — extern zichtbaar betekent niet transparant in detail.
    """
    out = PingResponse(
        response_id=original.response_id,
        in_response_to=original.in_response_to,
        responder_did=original.responder_did,
        decision=original.decision,
    )
    out.payload = {"status": "refused", "code": code}

    # DE GUARD MEET TEGEN DE DEFAULT, NIET TEGEN "LEEG". `posture` heeft `"unknown"` als default:
    # een niet-leeg veld dat toch niets verraadt. Op leegte toetsen zou dit veld ten onrechte als
    # lek lezen — en, erger, een veld met een verraderlijke default ten onrechte GOEDKEUREN.
    blank = PingResponse(response_id="", in_response_to="", responder_did="",
                         decision=original.decision)
    for f in fields(PingResponse):
        if f.name in _PEER_MAY_SEE:
            continue
        assert getattr(out, f.name, None) == getattr(blank, f.name, None), (
            "refusal_response leaks %r — the projection must subtract, never carry. Add the "
            "field to _PEER_MAY_SEE only if a REFUSED stranger may genuinely see it." % f.name)
    return out


class RefusalMeter:
    """Begrensde waarneming: een niet-toegelaten vraag kost een teller, nooit een record.

    Dit is het antwoord op `decision_without_observation` zonder in `the auditor may not become
    the attack` te lopen. Per posture een som; daarnaast hooguit `_MAX_TRACKED` distincte
    bronnen, zodat een eigenaar ziet WIE er klopt zonder dat een aanvaller ons geheugen stuurt.
    """

    def __init__(self, *, log_every: int = 100) -> None:
        self.by_posture: Dict[str, int] = {}
        self.sources: Dict[str, int] = {}
        self.total = 0
        self.spoken = 0          # weigeringen die daadwerkelijk beantwoord zijn
        self.overflowed = 0      # bronnen die we NIET meer apart bijhouden — eerlijk, geen stilte
        self._log_every = max(1, log_every)

    def record(self, *, posture: str, source_did: str, spoke: bool) -> Optional[dict]:
        """Tel de weigering. Geeft af en toe een samenvatting terug om te loggen, anders None.

        De aanroeper logt; deze klasse doet geen IO. Dat houdt 'm testbaar en voorkomt dat een
        drukke lijn de logregel zelf tot kostenpost maakt.
        """
        self.total += 1
        self.by_posture[posture] = self.by_posture.get(posture, 0) + 1
        if spoke:
            self.spoken += 1
        if source_did in self.sources:
            self.sources[source_did] += 1
        elif len(self.sources) < _MAX_TRACKED:
            self.sources[source_did] = 1
        else:
            self.overflowed += 1
        if self.total % self._log_every == 0:
            return self.snapshot()
        return None

    def snapshot(self) -> dict:
        """Wat een lokale lezer mag zien. Alles hier is een SOM, geen gebeurtenis."""
        return {
            "kind": "org.ainternet.tping.refusal-meter.v1",
            "total": self.total,
            "by_posture": dict(self.by_posture),
            "answered_outward": self.spoken,
            "silent": self.total - self.spoken,
            "top_sources": sorted(self.sources.items(), key=lambda kv: -kv[1])[:8],
            "sources_untracked": self.overflowed,
            "bounded_by": _MAX_TRACKED,
            "why_bounded": ("a null route is a refusal to spend the system on an unadmitted "
                            "question — per-packet records would make the observation the attack"),
        }
