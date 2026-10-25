import sys
from pathlib import Path

VARIANTS = {
    "base": set(),
    "mayact": {"MAYACT"},
    "dpop": {"DPOP"},
    "aud": {"AUD"},
    "dpop_aud": {"DPOP", "AUD"},
    "mayact_dpop_aud": {"MAYACT", "DPOP", "AUD"},
    "rarh": {"RARH"},
    "all": {"MAYACT", "DPOP", "AUD", "RARH"},
}

KC_VARIANTS = {f"kc_{name}": f | {"KEYCOMP"} for name, f in VARIANTS.items()}

HEADER = """theory RFC8693_{name}
begin

builtins: signing, hashing

restriction Equality:
  "All x y #i. Eq(x, y) @ #i ==> x = y"

restriction CaveatPermits:
  "All c a #i. Check(c, a) @ #i ==> (c = a | (Ex op x. a = <op, x> & c = <op, 'any'>))"

restriction ConcreteOperand:
  "All op #i. Act(<op, 'any'>) @ #i ==> F"

restriction HumanTaskOperandIsConcrete:
  "All H t op #i. Intends(H, t, <'fixed', op, 'any'>) @ #i ==> F"

restriction UniqueKey:
  "All X #i #j. Register(X) @ #i & Register(X) @ #j ==> #i = #j"

restriction OneValuePerSourceAndTask:
  "All s t v w #i #j. Produced(s, t, v) @ #i & Produced(s, t, w) @ #j ==> #i = #j"

rule Register:
  [ Fr(~k) ]
  --[ Register($X) ]->
  [ !Ltk($X, ~k), !Pk($X, pk(~k)), Out(pk(~k)) ]
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


def no_reveal(f):
    return "\n     & not (Ex X #r. Reveal(X) @ #r)" if "KEYCOMP" in f else ""


def none_revealed(f, *parties):
    if "KEYCOMP" not in f:
        return ""
    return "".join(f"\n     & not (Ex #r. Reveal({x}) @ #r)" for x in parties)


def human_rule(kind, f):
    if kind == "static":
        task = "<'fixed', 'push', $repo>"
        scope = "<'push', $repo>" if "RARH" in f else "<'push', 'any'>"
        tag = "TaskStatic(~tid)"
    else:
        task = "<'hole', 'push', $Src>"
        scope = "<'push', 'any'>"
        tag = "TaskDynamic(~tid)"
    cnf = "pkA1" if "DPOP" in f else "'none'"
    pkprem = ", !Pk($A1, pkA1)" if "DPOP" in f else ""
    extra = ", !TaskOpen(~tid, $Src)" if kind == "dynamic" else ""
    return f"""
rule Human_consents_{kind}_task:
  let t0 = <'at', $H, 'none', <'agent', $A1>, {scope}, {cnf}, ~tid>
  in
  [ Fr(~tid), !Ltk($H, kH), !Ltk('AS', kAS){pkprem} ]
  --[ Intends($H, ~tid, {task}), RootDelegated($H, $A1, {scope}, ~tid), {tag}, Issued(t0) ]->
  [ Out(<t0, sign(t0, kAS)>){extra} ]
"""


COMMON_AGENTS = """
rule Source_produces:
  [ !TaskOpen(tid, $Src), !Ltk($Src, ks) ]
  --[ Produced($Src, tid, $v) ]->
  [ Out(<'prov', $Src, tid, $v>) ]

rule Agent_requests_exchange:
  let st = <'at', H, act, aud, sc, cnf, tid>
      xr = <'xreq', $X, h(<st, ss>), naud, nsc>
  in
  [ In(<st, ss>), In(<naud, nsc>), !Ltk($X, kX), !Pk('AS', pkAS) ]
  --[ Eq(verify(ss, st, pkAS), true), Delegated($X, naud, tid) ]->
  [ Out(<st, ss, xr, sign(xr, kX)>) ]

rule Agent_sends_request:
  let tok = <'at', H, act, aud, sc, cnf, tid>
      pr  = <'dpop', a, $R, h(<tok, ts>)>
  in
  [ In(<tok, ts>), In(<$R, a>), !Ltk($X, kX) ]
  --[ Request($X, a, tid) ]->
  [ Out(<'req', a, $R, tok, ts, sign(pr, kX)>) ]
"""


def as_rule(f):
    checks = ["Eq(verify(ss, st, pk(kAS)), true)", "Eq(verify(xs, xr, pkX), true)", "Check(sc, nsc)"]
    if "MAYACT" in f:
        checks.append("Eq(aud, <'agent', X>)")
    ncnf = "pkX" if "DPOP" in f else "'none'"
    return f"""
rule AS_exchanges:
  let st = <'at', H, act, aud, sc, cnf, tid>
      xr = <'xreq', X, h(<st, ss>), naud, nsc>
      nt = <'at', H, <'act', X, act>, naud, nsc, {ncnf}, tid>
  in
  [ In(<st, ss, xr, xs>), !Pk(X, pkX), !Ltk('AS', kAS) ]
  --[ {", ".join(checks)}, Issued(nt) ]->
  [ Out(<nt, sign(nt, kAS)>) ]
"""


DEPTHS = [
    ("depth0", "'none'", "H", "NoActor($R, a, tid)"),
    ("depth1", "<'act', P, 'none'>", "P", None),
    ("depth2", "<'act', P, <'act', Q, 'none'>>", "P", "Chain($R, H, Q, P, tid)"),
    ("depth3plus", "<'act', P, <'act', Q, <'act', Z, rest>>>", "P", None),
]


def rs_rules(f):
    out = []
    for name, act, principal, chain in DEPTHS:
        checks = ["Eq(verify(ts, tok, pkAS), true)", "Check(sc, a)", "Act(a)"]
        if "AUD" in f:
            checks.append("Eq(aud, <'rs', $R>)")
        if "DPOP" in f:
            checks.append("Eq(verify(pr, <'dpop', a, $R, h(<tok, ts>)>, cnf), true)")
        checks.append(f"Accept($R, {principal}, a, tid)")
        if chain:
            checks.append(chain)
        out.append(f"""
rule Resource_accepts_{name}:
  let tok = <'at', H, {act}, aud, sc, cnf, tid>
  in
  [ In(<'req', a, $R, tok, ts, pr>), !Pk('AS', pkAS) ]
  --[ {", ".join(checks)} ]->
  [ ]
""")
    return "".join(out)


def executability(f):
    return f"""
lemma executable_static_task_conformant_two_hops:
  exists-trace
  "Ex R H A1 A2 a tid #i #j #k.
     Accept(R, A2, a, tid) @ #i & Chain(R, H, A1, A2, tid) @ #i
     & TaskStatic(tid) @ #j & Intends(H, tid, <'fixed', a>) @ #k
     & not (A1 = A2){no_reveal(f)}"

lemma executable_dynamic_task_conformant_two_hops:
  exists-trace
  "Ex R H A1 A2 op v S tid #i #k #l.
     Accept(R, A2, <op, v>, tid) @ #i & Chain(R, H, A1, A2, tid) @ #i
     & Intends(H, tid, <'hole', op, S>) @ #k & Produced(S, tid, v) @ #l
     & not (A1 = A2){no_reveal(f)}"

"""


def invariants(f):
    return f"""
lemma issued_scope_within_human_consent [use_induction, reuse]:
  "All H act aud sc cnf tid #i.
     Issued(<'at', H, act, aud, sc, cnf, tid>) @ #i
     ==> (Ex A1 c #j. RootDelegated(H, A1, c, tid) @ #j
         & (c = sc | (Ex op x. sc = <op, x> & c = <op, 'any'>))){unless(f, "'AS'")}"
"""


def mayact_invariants(f):
    return f"""
lemma first_actor_was_root_delegate [reuse]:
  "All H X aud sc cnf tid #i.
     Issued(<'at', H, <'act', X, 'none'>, aud, sc, cnf, tid>) @ #i
     ==> (Ex c #j. RootDelegated(H, X, c, tid) @ #j & #j < #i){unless(f, "'AS'")}"

lemma later_actor_was_delegated_by_previous [reuse]:
  "All H X Y rest aud sc cnf tid #i.
     Issued(<'at', H, <'act', X, <'act', Y, rest>>, aud, sc, cnf, tid>) @ #i
     ==> (Ex #j. Delegated(Y, <'agent', X>, tid) @ #j & #j < #i){unless(f, "'AS'", "Y")}"
"""


def lemmas(f):
    kc = ""
    if "KEYCOMP" in f:
        kc = """
lemma kc_witness_chain_party_reveal_breaks_AUTH:
  exists-trace
  "Ex R H A1 A2 tid #i #r.
     Chain(R, H, A1, A2, tid) @ #i & Reveal(A1) @ #r
     & not (Ex #e. Delegated(A1, <'agent', A2>, tid) @ #e)"

lemma kc_witness_actor_reveal_breaks_ATTR:
  exists-trace
  "Ex R P a tid #i #r.
     Accept(R, P, a, tid) @ #i & Reveal(P) @ #r
     & not (Ex #j. Request(P, a, tid) @ #j)"

lemma kc_witness_as_reveal_breaks_TASK_static:
  exists-trace
  "Ex R P a tid #i #j #r.
     Accept(R, P, a, tid) @ #i & TaskStatic(tid) @ #j & Reveal('AS') @ #r
     & not (Ex H #k. Intends(H, tid, <'fixed', a>) @ #k)"
"""
    return kc + f"""
lemma witness_splice_chain_names_undelegated_hop:
  exists-trace
  "Ex R H A1 A2 A3 tid #i #d.
     Chain(R, H, A1, A2, tid) @ #i & Delegated(A1, <'agent', A3>, tid) @ #d
     & not (A2 = A3)
     & not (Ex #e. Delegated(A1, <'agent', A2>, tid) @ #e){none_revealed(f, "'AS'", "A1", "A2")}"

lemma witness_act_stripping_logs_human:
  exists-trace
  "Ex R H A1 a tid #i #q.
     Accept(R, H, a, tid) @ #i & NoActor(R, a, tid) @ #i & Request(A1, a, tid) @ #q & not (A1 = H){none_revealed(f, "'AS'", "A1")}"

lemma AUTH_nested_act_chain_was_delegated:
  "All R H A1 A2 tid #i.
     Chain(R, H, A1, A2, tid) @ #i
     ==> ((Ex c #j. RootDelegated(H, A1, c, tid) @ #j & #j < #i)
       & (Ex #k. Delegated(A1, <'agent', A2>, tid) @ #k & #k < #i)){unless(f, "'AS'", "A1", "A2")}"

lemma NOESC_action_within_human_consent:
  "All R P a tid #i.
     Accept(R, P, a, tid) @ #i
     ==> (Ex H A1 c #j. RootDelegated(H, A1, c, tid) @ #j
         & (c = a | (Ex op x. a = <op, x> & c = <op, 'any'>))){unless(f, "'AS'")}"

lemma ATTR_logged_current_actor_sent_request:
  "All R P a tid #i.
     Accept(R, P, a, tid) @ #i
     ==> (Ex #j. Request(P, a, tid) @ #j & #j < #i){unless(f, "'AS'", "P")}"

lemma TASK_static_task:
  "All R P a tid #i #j.
     Accept(R, P, a, tid) @ #i & TaskStatic(tid) @ #j
     ==> (Ex H #k. Intends(H, tid, <'fixed', a>) @ #k){unless(f, "'AS'")}"

lemma TASK_dynamic_task:
  "All R P op v tid #i #j.
     Accept(R, P, <op, v>, tid) @ #i & TaskDynamic(tid) @ #j
     ==> (Ex H S #k #l. Intends(H, tid, <'hole', op, S>) @ #k & Produced(S, tid, v) @ #l){unless(f, "'AS'")}"

end
"""


def render(name, f):
    return (HEADER.format(name=name) + (REVEAL if "KEYCOMP" in f else "")
            + human_rule("static", f) + human_rule("dynamic", f)
            + COMMON_AGENTS + as_rule(f) + rs_rules(f) + invariants(f) + executability(f)
            + (mayact_invariants(f) if "MAYACT" in f else "") + lemmas(f))


def main():
    outdir = Path(sys.argv[1])
    chosen = KC_VARIANTS if len(sys.argv) > 2 and sys.argv[2] == "kc" else VARIANTS
    outdir.mkdir(parents=True, exist_ok=True)
    for name, f in chosen.items():
        (outdir / f"RFC8693_{name}.spthy").write_text(render(name, f))
    (outdir / "variants.txt").write_text("\n".join(chosen) + "\n")


if __name__ == "__main__":
    main()
