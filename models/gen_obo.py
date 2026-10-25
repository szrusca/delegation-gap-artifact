import sys
from pathlib import Path

VARIANTS = {
    "base": set(),
    "actbind": {"ACTBIND"},
    "dpop_client": {"DPOPC"},
    "dpop_client_actbind": {"DPOPC", "ACTBIND"},
    "dpop_actor": {"DPOPA"},
    "dpop_actor_actbind": {"DPOPA", "ACTBIND"},
}

KC_VARIANTS = {f"kc_{name}": f | {"KEYCOMP"} for name, f in VARIANTS.items()}

FIX_VARIANTS = {
    "opscope": {"OPSCOPE"},
    "obo_allfix": {"DPOPA", "ACTBIND", "OPSCOPE"},
}

MODES = {"steered": VARIANTS, "kc": KC_VARIANTS, "fix": FIX_VARIANTS}

OPSCOPE_RESTRICTION = """
restriction OperandScopesAreConcrete:
  "All H K Y op t #i. Consent(H, K, Y, <op, 'any'>, t) @ #i ==> F"
"""

REVEAL = """
rule Reveal_ltk:
  [ !Ltk($X, k) ]
  --[ Reveal($X) ]->
  [ Out(k) ]
"""


def unless(f, *parties):
    if "KEYCOMP" not in f:
        return ""
    return "".join(f"\n       | (Ex #r. Reveal({x}) @ #r)" for x in parties)


def none_revealed(f, *parties):
    if "KEYCOMP" not in f:
        return ""
    return "".join(f"\n     & not (Ex #r. Reveal({x}) @ #r)" for x in parties)


def no_reveal(f):
    return "\n     & not (Ex X #r. Reveal(X) @ #r)" if "KEYCOMP" in f else ""

HEADER = """theory OBO_{name}
begin

builtins: signing, hashing

restriction Equality:
  "All x y #i. Eq(x, y) @ #i ==> x = y"

restriction CaveatPermits:
  "All c a #i. Check(c, a) @ #i ==> (c = a | (Ex op x. a = <op, x> & c = <op, 'any'>))"

restriction ConcreteOperand:
  "All op #i. Act(<op, 'any'>) @ #i ==> F"

restriction UniqueKey:
  "All X #i #j. Register(X) @ #i & Register(X) @ #j ==> #i = #j"

restriction OneValuePerSourceAndTask:
  "All s t v w #i #j. Produced(s, t, v) @ #i & Produced(s, t, w) @ #j ==> #i = #j"

restriction HumanTaskOperandIsConcrete:
  "All H t op #i. Intends(H, t, <'fixed', op, 'any'>) @ #i ==> F"

rule Register:
  [ Fr(~k) ]
  --[ Register($X) ]->
  [ !Ltk($X, ~k), !Pk($X, pk(~k)), Out(pk(~k)) ]

rule Actor_joins_flow:
  let at = <'actor', $Y>
  in
  [ In(tid), !Ltk('AS', kAS), !Ltk($Y, kY) ]
  --[ ActorJoined($Y, tid) ]->
  [ Out(<at, sign(at, kAS), sign(<'join', $Y, tid>, kY)>) ]
"""


def consent_rule(kind, f=frozenset()):
    proposed = ""
    if kind == "static":
        acts = "Intends($H, ~tid, <'fixed', 'push', $repo>), TaskStatic(~tid)"
        extra = ""
        scope = "<'push', $repo>" if "OPSCOPE" in f else "<'push', 'any'>"
    else:
        acts = "Intends($H, ~tid, <'hole', 'push', $Src>), TaskDynamic(~tid)"
        extra = ", !TaskOpen(~tid, $Src)"
        scope = "<'push', v>" if "OPSCOPE" in f else "<'push', 'any'>"
        proposed = ", In(v)" if "OPSCOPE" in f else ""
    return f"""
rule Human_consents_{kind}:
  let s = {scope}
  in
  [ Fr(~tid), !Ltk($H, kH){proposed} ]
  --[ Consent($H, $K, $Y, s, ~tid), {acts} ]->
  [ CodeState(~tid, $H, $K, $Y, s), Out(<'code', ~tid, $K, $Y>){extra} ]
"""


SOURCE = """
rule Source_produces:
  [ !TaskOpen(tid, $Src), !Ltk($Src, ks) ]
  --[ Produced($Src, tid, $v) ]->
  [ Out(<'prov', $Src, tid, $v>) ]
"""

CLIENT_REDEEMS_DPOPC = """
rule Client_redeems_with_own_key:
  [ In(tid), !Ltk($K, kK) ]
  --[ ClientRedeemed($K, tid) ]->
  [ Out(<pk(kK), sign(<'dpop-tok', tid>, kK)>) ]
"""


def satoken_rule(f):
    checks = ["Eq(verify(sa, at, pk(kAS)), true)"]
    prem_in = ["In(<'tokreq', tid, at, sa, js, cnfk, cp>)"]
    if "ACTBIND" in f:
        checks.append("Eq(verify(js, <'join', Y, tid>, pkY), true)")
    if "DPOPC" in f:
        checks.append("Eq(verify(cp, <'dpop-tok', tid>, cnfk), true)")
        cnf = "cnfk"
    elif "DPOPA" in f:
        cnf = "pkY"
    else:
        cnf = "'none'"
    return f"""
rule AS_token_endpoint:
  let at  = <'actor', Y>
      tok = <'obo', H, K, Y, s, {cnf}, tid>
  in
  [ {", ".join(prem_in)}, CodeState(tid, H, K, Y, s), !Ltk('AS', kAS), !Pk(Y, pkY) ]
  --[ {", ".join(checks)}, Issued(tok) ]->
  [ Out(<tok, sign(tok, kAS)>) ]
"""


REQUEST = """
rule Agent_sends_request:
  let tok = <'obo', H, K, Y, s, cnf, tid>
  in
  [ In(<tok, ts>), In(<$R, a>), !Ltk($X, kX) ]
  --[ Request($X, a, tid) ]->
  [ Out(<'req', a, $R, tok, ts, sign(<'dpop', a, $R, h(<tok, ts>)>, kX)>) ]
"""


def rs_rule(f):
    checks = ["Eq(verify(ts, tok, pkYS), true)", "Check(s, a)", "Act(a)"]
    if "DPOPC" in f or "DPOPA" in f:
        checks.append("Eq(verify(pr, <'dpop', a, $R, h(<tok, ts>)>, cnf), true)")
    checks.append("Accept($R, H, K, Y, a, tid)")
    return f"""
rule Resource_accepts:
  let tok = <'obo', H, K, Y, s, cnf, tid>
  in
  [ In(<'req', a, $R, tok, ts, pr>), !Pk('AS', pkYS) ]
  --[ {", ".join(checks)} ]->
  [ ]
"""


KC_LEMMAS = """
lemma kc_witness_as_reveal_breaks_AUTH:
  exists-trace
  "Ex R H K Y a tid #i #r.
     Accept(R, H, K, Y, a, tid) @ #i & Reveal('AS') @ #r
     & not (Ex s #j. Consent(H, K, Y, s, tid) @ #j)"

lemma kc_witness_actor_reveal_breaks_ATTR:
  exists-trace
  "Ex R H K Y a tid #i #r.
     Accept(R, H, K, Y, a, tid) @ #i & Reveal(Y) @ #r
     & not (Ex #j. Request(Y, a, tid) @ #j)"
"""


def lemmas(f):
    return (KC_LEMMAS if "KEYCOMP" in f else "") + f"""
lemma executable_static_task_conformant:
  exists-trace
  "Ex R H K Y a tid #i #j #k #q.
     Accept(R, H, K, Y, a, tid) @ #i & TaskStatic(tid) @ #j & Intends(H, tid, <'fixed', a>) @ #k
     & Request(Y, a, tid) @ #q & not (K = Y){no_reveal(f)}"

lemma executable_dynamic_task_conformant:
  exists-trace
  "Ex R H K Y op v S tid #i #k #l #q.
     Accept(R, H, K, Y, <op, v>, tid) @ #i
     & Intends(H, tid, <'hole', op, S>) @ #k & Produced(S, tid, v) @ #l
     & Request(Y, <op, v>, tid) @ #q & not (K = Y){no_reveal(f)}"

lemma witness_client_acts_logged_as_actor:
  exists-trace
  "Ex R H K Y a tid #i #q.
     Accept(R, H, K, Y, a, tid) @ #i & Request(K, a, tid) @ #q
     & not (K = Y) & not (Ex #p. Request(Y, a, tid) @ #p){none_revealed(f, "'AS'", "Y")}"

lemma witness_actor_named_without_participation:
  exists-trace
  "Ex R H K Y a tid #i.
     Accept(R, H, K, Y, a, tid) @ #i & not (Ex #j. ActorJoined(Y, tid) @ #j){none_revealed(f, "'AS'", "Y")}"

lemma AUTH_consent_names_client_and_actor:
  "All R H K Y a tid #i.
     Accept(R, H, K, Y, a, tid) @ #i
     ==> (Ex s #j. Consent(H, K, Y, s, tid) @ #j & #j < #i){unless(f, "'AS'")}"

lemma PARTICIPATION_actor_joined_this_delegation:
  "All R H K Y a tid #i.
     Accept(R, H, K, Y, a, tid) @ #i
     ==> (Ex #j. ActorJoined(Y, tid) @ #j & #j < #i){unless(f, "'AS'", "Y")}"

lemma NOESC_action_within_consent:
  "All R H K Y a tid #i.
     Accept(R, H, K, Y, a, tid) @ #i
     ==> (Ex s #j. Consent(H, K, Y, s, tid) @ #j
         & (s = a | (Ex op x. a = <op, x> & s = <op, 'any'>))){unless(f, "'AS'")}"

lemma ATTR_actor_logged_actor_decided_request:
  "All R H K Y a tid #i.
     Accept(R, H, K, Y, a, tid) @ #i
     ==> (Ex #j. Request(Y, a, tid) @ #j & #j < #i){unless(f, "'AS'", "Y")}"

lemma TASK_static_task:
  "All R H K Y a tid #i #j.
     Accept(R, H, K, Y, a, tid) @ #i & TaskStatic(tid) @ #j
     ==> (Ex #k. Intends(H, tid, <'fixed', a>) @ #k){unless(f, "'AS'")}"

lemma TASK_dynamic_task:
  "All R H K Y op v tid #i #j.
     Accept(R, H, K, Y, <op, v>, tid) @ #i & TaskDynamic(tid) @ #j
     ==> (Ex S #k #l. Intends(H, tid, <'hole', op, S>) @ #k & Produced(S, tid, v) @ #l){unless(f, "'AS'")}"

end
"""



def render(name, f):
    return (HEADER.format(name=name) + (REVEAL if "KEYCOMP" in f else "") + (OPSCOPE_RESTRICTION if "OPSCOPE" in f else "")
            + consent_rule("static", f) + consent_rule("dynamic", f) + SOURCE
            + (CLIENT_REDEEMS_DPOPC if "DPOPC" in f else "")
            + satoken_rule(f) + REQUEST + rs_rule(f) + lemmas(f))


def main():
    outdir = Path(sys.argv[1])
    chosen = MODES[sys.argv[2] if len(sys.argv) > 2 else "steered"]
    outdir.mkdir(parents=True, exist_ok=True)
    for name, f in chosen.items():
        (outdir / f"OBO_{name}.spthy").write_text(render(name, f))
    (outdir / "variants.txt").write_text("\n".join(chosen) + "\n")


if __name__ == "__main__":
    main()
