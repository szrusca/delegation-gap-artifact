import sys
from pathlib import Path

VARIANTS = {
    "spec_min": {"POLICY"},
    "subpop": {"POLICY", "SUBPOP"},
    "didpreauth": {"POLICY", "DIDPREAUTH"},
    "subpop_didpreauth": {"POLICY", "SUBPOP", "DIDPREAUTH"},
    "exact_consent": {"SUBPOP", "DIDPREAUTH", "EXACT"},
}

W3PRUNE_VARIANTS = {f"w3p_{name}": f | {"W3PRUNE"} for name, f in VARIANTS.items() if "POLICY" in f}

CAPSULE_VARIANTS = {
    "r012_base": {"POLICY", "SUBPOP", "DIDPREAUTH", "OPENSRC"},
    "r012_capsule": {"POLICY", "SUBPOP", "DIDPREAUTH", "OPENSRC", "CAPSULE"},
    "r012_prov": {"POLICY", "SUBPOP", "DIDPREAUTH", "OPENSRC", "PROV"},
    "r012_capsule_prov": {"POLICY", "SUBPOP", "DIDPREAUTH", "OPENSRC", "CAPSULE", "PROV"},
}

FIX_VARIANTS = {
    "fix_rfwd": {"POLICY", "SUBPOP", "DIDPREAUTH", "RFWD"},
    "fix_rfwd_nopreauth": {"POLICY", "SUBPOP", "RFWD"},
    "wimse_allfix": {"POLICY", "SUBPOP", "DIDPREAUTH", "RFWD", "OPENSRC", "CAPSULE", "PROV"},
}

KC_VARIANTS = {f"kc_{name}": f | {"KEYCOMP"} for name, f in VARIANTS.items()}

MODES = {"steered": VARIANTS, "w3prune": W3PRUNE_VARIANTS, "capsule": CAPSULE_VARIANTS,
         "fix": FIX_VARIANTS, "kc": KC_VARIANTS}

EXTENDED_KNOBS = {"OPENSRC", "CAPSULE", "PROV", "RFWD", "KEYCOMP"}

REVEAL = """
rule Reveal_ltk:
  [ !Ltk($X, k) ]
  --[ Reveal($X) ]->
  [ Out(k) ]
"""

OPEN_SOURCE = """rule Source_produces:
  let p = <'prov', $Src, tid, $v>
  in
  [ In(tid), !Ltk($Src, ks) ]
  --[ Produced($Src, tid, $v) ]->
  [ Out(<p, sign(p, ks)>) ]
"""

CLOSED_SOURCE = """rule Source_produces:
  [ !TaskOpen(tid, $Src), !Ltk($Src, ks) ]
  --[ Produced($Src, tid, $v) ]->
  [ Out(<'prov', $Src, tid, $v>) ]
"""

W3PRUNE = """
restriction W3SearchNoDynamicTasks:
  "All t #i. TaskDynamic(t) @ #i ==> F"

restriction W3SearchNoChildDts:
  "All d1 d2 t #i. ChildIssued(d1, d2, t) @ #i ==> F"

restriction W3SearchConcreteRootCapability:
  "All H d op t #i. RootIssued(H, d, <op, 'any'>, t) @ #i ==> F"

restriction W3SearchRegisteredRootDid:
  "All H d c t #i. RootIssued(H, d, c, t) @ #i ==> Ex D #k. Key(D, d) @ #k"
"""

HEADER = """theory WIMSE_{name}
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
  --[ Register($X), Key($X, pk(~k)) ]->
  [ !Ltk($X, ~k), !Pk($X, pk(~k)), Out(pk(~k)) ]

rule Human_links_vault_credential:
  [ !Ltk($H, kH) ]
  --[ VaultLinked($H, $R) ]->
  [ !Vault($H, $R) ]

rule Human_starts_static_task:
  [ Fr(~tid), !Ltk($H, kH) ]
  --[ Intends($H, ~tid, <'fixed', 'push', $repo>), TaskStatic(~tid) ]->
  [ Out(<~tid, $H>), !TaskOf(~tid, $H), !TaskFixed(~tid, $H, <'push', $repo>) ]

rule Human_starts_dynamic_task:
  [ Fr(~tid), !Ltk($H, kH) ]
  --[ Intends($H, ~tid, <'hole', 'push', $Src>), TaskDynamic(~tid) ]->
  [ Out(<~tid, $H>), !TaskOf(~tid, $H), !TaskHole(~tid, $H), !TaskOpen(~tid, $Src) ]

rule Source_produces:
  [ !TaskOpen(tid, $Src), !Ltk($Src, ks) ]
  --[ Produced($Src, tid, $v) ]->
  [ Out(<'prov', $Src, tid, $v>) ]
"""

POLICY = """
rule Human_sets_preauthorized_policy:
  [ !Ltk($H, kH) ]
  --[ PolicySet($H, <'push', 'any'>) ]->
  [ !Policy($H, <'push', 'any'>) ]
"""

DIDPREAUTH = """
rule Human_preauthorizes_agent_did:
  [ !Ltk($H, kH), !Pk($D, pkD) ]
  --[ DidPreAuthorized($H, pkD) ]->
  [ !PreAuth($H, pkD) ]
"""

EXACT = """
rule Human_approves_exact_operand:
  [ !TaskFixed(tid, H, c), !PreAuth(H, did) ]
  --[ CibaApproved(H, did, c, tid) ]->
  [ !Approved(H, did, c, tid) ]

rule Human_approves_proposed_operand:
  [ !TaskHole(tid, H), !PreAuth(H, did), In(v) ]
  --[ CibaApproved(H, did, <'push', v>, tid) ]->
  [ !Approved(H, did, <'push', v>, tid) ]
"""

AGENTS = """
rule Agent_requests_root_dt:
  let m = <'rreq', H, pk(kD), c, tid>
  in
  [ In(<H, c, tid>), !Ltk($D, kD) ]
  --[ RootRequested(pk(kD), H, c, tid) ]->
  [ Out(<m, sign(m, kD)>) ]

rule Agent_requests_subdelegation:
  let dt = <'dt', H, pk(k1), c1, tid, 'root'>
      m  = <'sreq', h(dt), did2, c2>
  in
  [ In(<dt, ds>), In(<did2, c2>), !Ltk($D, k1) ]
  --[ SubDelegated(pk(k1), did2, tid) ]->
  [ Out(<'sreq', dt, ds, did2, c2, sign(m, k1)>) ]

rule Agent_exercises:
  let dt = <'dt', H, pk(kD), c, tid, par>
  in
  [ In(<dt, ds>), In(<$R, a>), !Ltk($D, kD) ]
  --[ Request(pk(kD), a, tid) ]->
  [ Out(<'ex', dt, ds, $R, a, sign(<'dpop', a, $R, h(dt)>, kD)>) ]
"""


def ds_root(f):
    prem = ["In(<m, sg>)", "!TaskOf(tid, H)", "!Ltk('DS', kDS)"]
    checks = ["Eq(verify(sg, m, did), true)"]
    if "POLICY" in f:
        prem.append("!Policy(H, pol)")
        checks.append("Check(pol, c)")
    if "DIDPREAUTH" in f:
        prem.append("!PreAuth(H, did)")
    if "EXACT" in f:
        prem.append("!Approved(H, did, c, tid)")
    checks.append("RootIssued(H, did, c, tid)")
    return f"""
rule DS_issues_root_dt:
  let m  = <'rreq', H, did, c, tid>
      dt = <'dt', H, did, c, tid, 'root'>
  in
  [ {", ".join(prem)} ]
  --[ {", ".join(checks)} ]->
  [ Out(<dt, sign(dt, kDS)>) ]
"""


def ds_sub(f):
    prem = ["In(<'sreq', dt, ds, did2, c2, ps>)", "!Ltk('DS', kDS)"]
    checks = ["Eq(verify(ds, dt, pk(kDS)), true)"]
    if "SUBPOP" in f:
        checks.append("Eq(verify(ps, m, did1), true)")
    if "DIDPREAUTH" in f:
        prem.append("!PreAuth(H, did2)")
    checks += ["Check(c1, c2)", "ChildIssued(did1, did2, tid)"]
    return f"""
rule DS_issues_child_dt:
  let dt    = <'dt', H, did1, c1, tid, 'root'>
      m     = <'sreq', h(dt), did2, c2>
      child = <'dt', H, did2, c2, tid, <'parent', did1>>
  in
  [ {", ".join(prem)} ]
  --[ {", ".join(checks)} ]->
  [ Out(<child, sign(child, kDS)>) ]
"""


DS_EXERCISE = """
rule DS_exercises_with_vault_credential:
  let dt = <'dt', H, did, c, tid, par>
  in
  [ In(<'ex', dt, ds, $R, a, pr>), !Ltk('DS', kDS), !Vault(H, $R) ]
  --[ Eq(verify(ds, dt, pk(kDS)), true), Eq(verify(pr, <'dpop', a, $R, h(dt)>, did), true)
    , Check(c, a), Act(a), DSExec(H, did, a, tid) ]->
  [ UpCall($R, H, a, tid) ]

rule Resource_accepts_vault_call:
  [ UpCall(R, H, a, tid) ]
  --[ Accept(R, H, 'DS', a, tid) ]->
  [ ]
"""

LEMMAS = """
lemma executable_static_task_conformant_two_hops:
  exists-trace
  "Ex R H a tid D1 D2 d1 d2 #i #e #c #j #k #k1 #k2.
     Accept(R, H, 'DS', a, tid) @ #i & DSExec(H, d2, a, tid) @ #e & ChildIssued(d1, d2, tid) @ #c
     & TaskStatic(tid) @ #j & Intends(H, tid, <'fixed', a>) @ #k
     & Key(D1, d1) @ #k1 & Key(D2, d2) @ #k2 & not (D1 = D2)"

lemma executable_dynamic_task_conformant_two_hops:
  exists-trace
  "Ex R H op v S tid D1 D2 d1 d2 #i #e #c #k #l #k1 #k2.
     Accept(R, H, 'DS', <op, v>, tid) @ #i & DSExec(H, d2, <op, v>, tid) @ #e & ChildIssued(d1, d2, tid) @ #c
     & Intends(H, tid, <'hole', op, S>) @ #k & Produced(S, tid, v) @ #l
     & Key(D1, d1) @ #k1 & Key(D2, d2) @ #k2 & not (D1 = D2)"

lemma witness_splice_child_without_parent_request:
  exists-trace
  "Ex D1 d1 d2 tid #c #k.
     ChildIssued(d1, d2, tid) @ #c & Key(D1, d1) @ #k
     & not (Ex #j. SubDelegated(d1, d2, tid) @ #j)"

lemma witness_exercise_by_unregistered_did:
  exists-trace
  "Ex H did a tid #e.
     DSExec(H, did, a, tid) @ #e & not (Ex D #k. Key(D, did) @ #k)"

lemma witness_identity_collapse_at_resource:
  exists-trace
  "Ex R H a b t1 t2 d1 d2 #i #j #e1 #e2.
     Accept(R, H, 'DS', a, t1) @ #i & Accept(R, H, 'DS', b, t2) @ #j
     & DSExec(H, d1, a, t1) @ #e1 & DSExec(H, d2, b, t2) @ #e2 & not (d1 = d2)"

lemma witness_identity_collapse_guided:
  exists-trace
  "Ex R H a b t1 t2 c1 c2 D1 D2 d1 d2 #i #j #e1 #e2 #r1 #r2 #s1 #s2 #k1 #k2.
     Accept(R, H, 'DS', a, t1) @ #i & Accept(R, H, 'DS', b, t2) @ #j
     & DSExec(H, d1, a, t1) @ #e1 & DSExec(H, d2, b, t2) @ #e2
     & RootIssued(H, d1, c1, t1) @ #r1 & RootIssued(H, d2, c2, t2) @ #r2
     & TaskStatic(t1) @ #s1 & TaskStatic(t2) @ #s2
     & Key(D1, d1) @ #k1 & Key(D2, d2) @ #k2 & not (D1 = D2)"

lemma witness_identity_collapse_parent_and_child:
  exists-trace
  "Ex R H a tid D1 D2 d1 d2 #i #j #e1 #e2 #c #s #k1 #k2.
     Accept(R, H, 'DS', a, tid) @ #i & Accept(R, H, 'DS', a, tid) @ #j & not (#i = #j)
     & DSExec(H, d1, a, tid) @ #e1 & DSExec(H, d2, a, tid) @ #e2
     & ChildIssued(d1, d2, tid) @ #c & TaskStatic(tid) @ #s
     & Key(D1, d1) @ #k1 & Key(D2, d2) @ #k2 & not (D1 = D2)"

lemma CHAINAUTH_registered_parent_requested_subdelegation:
  "All D1 d1 d2 tid #c #k.
     ChildIssued(d1, d2, tid) @ #c & Key(D1, d1) @ #k
     ==> Ex #j. SubDelegated(d1, d2, tid) @ #j"

lemma NOESC_exercise_within_human_authorization:
  "All H did a tid #e.
     DSExec(H, did, a, tid) @ #e
     ==> (Ex c #j. PolicySet(H, c) @ #j & (c = a | (Ex op x. a = <op, x> & c = <op, 'any'>)))
       | (Ex d c #j. CibaApproved(H, d, c, tid) @ #j & (c = a | (Ex op x. a = <op, x> & c = <op, 'any'>)))"

lemma ATTR_DS_logged_did_decided_operation:
  "All H did a tid #e.
     DSExec(H, did, a, tid) @ #e
     ==> Ex #j. Request(did, a, tid) @ #j & #j < #e"

lemma ATTR_R_logged_principal_decided_request:
  "All R H L a tid #i.
     Accept(R, H, L, a, tid) @ #i
     ==> Ex #j. Request(L, a, tid) @ #j & #j < #i"

lemma TASK_static_task:
  "All R H L a tid #i #j.
     Accept(R, H, L, a, tid) @ #i & TaskStatic(tid) @ #j
     ==> Ex #k. Intends(H, tid, <'fixed', a>) @ #k"

lemma TASK_dynamic_task:
  "All R H L op v tid #i #j.
     Accept(R, H, L, <op, v>, tid) @ #i & TaskDynamic(tid) @ #j
     ==> Ex S #k #l. Intends(H, tid, <'hole', op, S>) @ #k & Produced(S, tid, v) @ #l"

end
"""


def extended_header(name, f):
    text = HEADER.format(name=name)
    if "CAPSULE" in f:
        for tmpl, fixed_out in (("<'fixed', 'push', $repo>", "!TaskFixed(~tid, $H, <'push', $repo>) ]"),
                                ("<'hole', 'push', $Src>", "!TaskOpen(~tid, $Src) ]")):
            cap = f"<'cap', $H, ~tid, {tmpl}>"
            assert fixed_out in text
            text = text.replace(fixed_out, fixed_out[:-2] + f", Out(<{cap}, sign({cap}, kH)>) ]")
    if "OPENSRC" in f:
        assert CLOSED_SOURCE in text
        text = text.replace(CLOSED_SOURCE, OPEN_SOURCE)
    return text


def ds_exercise_rules(f):
    head = "In(<'ex', dt, ds, $R, a, pr>), !Ltk('DS', kDS), !Vault(H, $R)"
    base = ["Eq(verify(ds, dt, pk(kDS)), true)", "Eq(verify(pr, <'dpop', a, $R, h(dt)>, did), true)",
            "Check(c, a)", "Act(a)"]
    tail = "DSExec(H, did, a, tid)"
    cases = []
    if "CAPSULE" not in f and "PROV" not in f:
        cases.append(("DS_exercises_with_vault_credential", [], [], []))
    if "CAPSULE" not in f and "PROV" in f:
        cases.append(("DS_exercises_with_any_provenance", ["a = <op, v>", "p = <'prov', S, tid, v>"],
                      ["In(<p, sp>)", "!Pk(S, pkS)"], ["Eq(verify(sp, p, pkS), true)", "ProvFrom(S, tid, v)"]))
    if "CAPSULE" in f:
        cases.append(("DS_exercises_capsule_fixed", ["cap = <'cap', H, tid, <'fixed', a>>"],
                      ["In(<cap, sc>)", "!Pk(H, pkH)"], ["Eq(verify(sc, cap, pkH), true)"]))
        if "PROV" in f:
            cases.append(("DS_exercises_capsule_hole_provenance",
                          ["a = <op, v>", "cap = <'cap', H, tid, <'hole', op, S>>", "p = <'prov', S, tid, v>"],
                          ["In(<cap, sc>)", "!Pk(H, pkH)", "In(<p, sp>)", "!Pk(S, pkS)"],
                          ["Eq(verify(sc, cap, pkH), true)", "Eq(verify(sp, p, pkS), true)", "ProvFrom(S, tid, v)"]))
        else:
            cases.append(("DS_exercises_capsule_hole_unchecked",
                          ["a = <op, v>", "cap = <'cap', H, tid, <'hole', op, S>>"],
                          ["In(<cap, sc>)", "!Pk(H, pkH)"], ["Eq(verify(sc, cap, pkH), true)"]))
    out = []
    for rname, lets, prems, checks in cases:
        letlines = "".join(f"\n      {x}" for x in lets)
        out.append(f"""
rule {rname}:
  let dt = <'dt', H, did, c, tid, par>{letlines}
  in
  [ {", ".join([head] + prems)} ]
  --[ {", ".join(base + checks + [tail])} ]->
  [ UpCall($R, H, did, a, tid) ]
""")
    logged = "did" if "RFWD" in f else "'DS'"
    out.append(f"""
rule Resource_accepts_vault_call:
  [ UpCall(R, H, did, a, tid) ]
  --[ Accept(R, H, {logged}, a, tid), Served(R, did, a, tid) ]->
  [ ]
""")
    return "".join(out)


def extended_lemmas(f):
    kc = "KEYCOMP" in f
    nr = "\n     & not (Ex X #r. Reveal(X) @ #r)" if kc else ""
    def g(*alts):
        return "".join(f"\n       | {x}" for x in alts) if kc else ""
    ds = "(Ex #r. Reveal('DS') @ #r)"
    owner = lambda v: f"(Ex D #k #r. Key(D, {v}) @ #k & Reveal(D) @ #r)"
    le = "d2" if "RFWD" in f else "'DS'"
    permits = "(c = a | (Ex op x. a = <op, x> & c = <op, 'any'>))"
    text = f"""
lemma executable_static_task_conformant_two_hops:
  exists-trace
  "Ex R H a tid D1 D2 d1 d2 #i #e #c #j #k #k1 #k2.
     Accept(R, H, {le}, a, tid) @ #i & DSExec(H, d2, a, tid) @ #e & ChildIssued(d1, d2, tid) @ #c
     & TaskStatic(tid) @ #j & Intends(H, tid, <'fixed', a>) @ #k
     & Key(D1, d1) @ #k1 & Key(D2, d2) @ #k2 & not (D1 = D2){nr}"

lemma executable_dynamic_task_conformant_two_hops:
  exists-trace
  "Ex R H op v S tid D1 D2 d1 d2 #i #e #c #k #l #k1 #k2.
     Accept(R, H, {le}, <op, v>, tid) @ #i & DSExec(H, d2, <op, v>, tid) @ #e & ChildIssued(d1, d2, tid) @ #c
     & Intends(H, tid, <'hole', op, S>) @ #k & Produced(S, tid, v) @ #l
     & Key(D1, d1) @ #k1 & Key(D2, d2) @ #k2 & not (D1 = D2){nr}"

lemma witness_splice_child_without_parent_request:
  exists-trace
  "Ex D1 d1 d2 tid #c #k.
     ChildIssued(d1, d2, tid) @ #c & Key(D1, d1) @ #k
     & not (Ex #j. SubDelegated(d1, d2, tid) @ #j){nr}"

lemma witness_exercise_by_unregistered_did:
  exists-trace
  "Ex H did a tid #e.
     DSExec(H, did, a, tid) @ #e & not (Ex D #k. Key(D, did) @ #k){nr}"
"""
    if not kc:
        text += """
lemma witness_identity_collapse_at_resource:
  exists-trace
  "Ex R H L a b t1 t2 d1 d2 #i #j.
     Accept(R, H, L, a, t1) @ #i & Served(R, d1, a, t1) @ #i
     & Accept(R, H, L, b, t2) @ #j & Served(R, d2, b, t2) @ #j & not (d1 = d2)"
"""
    else:
        text += f"""
lemma kc_witness_ds_reveal_breaks_NOESC:
  exists-trace
  "Ex H did a tid #e #r.
     DSExec(H, did, a, tid) @ #e & Reveal('DS') @ #r
     & not (Ex c #j. PolicySet(H, c) @ #j & {permits})
     & not (Ex d c #j. CibaApproved(H, d, c, tid) @ #j & {permits})"

lemma kc_witness_agent_reveal_breaks_ATTR_DS:
  exists-trace
  "Ex H D did a tid #e #k #r.
     DSExec(H, did, a, tid) @ #e & Key(D, did) @ #k & Reveal(D) @ #r
     & not (Ex #j. Request(did, a, tid) @ #j)"
"""
    text += f"""
lemma CHAINAUTH_registered_parent_requested_subdelegation:
  "All D1 d1 d2 tid #c #k.
     ChildIssued(d1, d2, tid) @ #c & Key(D1, d1) @ #k
     ==> (Ex #j. SubDelegated(d1, d2, tid) @ #j){g(ds, "(Ex #r. Reveal(D1) @ #r)")}"

lemma NOESC_exercise_within_human_authorization:
  "All H did a tid #e.
     DSExec(H, did, a, tid) @ #e
     ==> (Ex c #j. PolicySet(H, c) @ #j & {permits})
       | (Ex d c #j. CibaApproved(H, d, c, tid) @ #j & {permits}){g(ds)}"

lemma ATTR_DS_logged_did_decided_operation:
  "All H did a tid #e.
     DSExec(H, did, a, tid) @ #e
     ==> (Ex #j. Request(did, a, tid) @ #j & #j < #e){g(ds, owner("did"))}"

lemma ATTR_R_logged_principal_decided_request:
  "All R H L a tid #i.
     Accept(R, H, L, a, tid) @ #i
     ==> (Ex #j. Request(L, a, tid) @ #j & #j < #i){g(ds, owner("L"))}"

lemma TASK_static_task:
  "All R H L a tid #i #j.
     Accept(R, H, L, a, tid) @ #i & TaskStatic(tid) @ #j
     ==> (Ex #k. Intends(H, tid, <'fixed', a>) @ #k){g(ds)}"

lemma TASK_dynamic_task:
  "All R H L op v tid #i #j.
     Accept(R, H, L, <op, v>, tid) @ #i & TaskDynamic(tid) @ #j
     ==> (Ex S #k #l. Intends(H, tid, <'hole', op, S>) @ #k & Produced(S, tid, v) @ #l){g(ds)}"

end
"""
    return text


def render(name, f):
    if f & EXTENDED_KNOBS:
        return (extended_header(name, f) + (REVEAL if "KEYCOMP" in f else "")
                + (POLICY if "POLICY" in f else "") + (DIDPREAUTH if "DIDPREAUTH" in f else "")
                + (EXACT if "EXACT" in f else "") + AGENTS + ds_root(f) + ds_sub(f)
                + ds_exercise_rules(f) + extended_lemmas(f))
    return (HEADER.format(name=name) + (W3PRUNE if "W3PRUNE" in f else "")
            + (POLICY if "POLICY" in f else "") + (DIDPREAUTH if "DIDPREAUTH" in f else "")
            + (EXACT if "EXACT" in f else "") + AGENTS + ds_root(f) + ds_sub(f) + DS_EXERCISE + LEMMAS)


def main():
    outdir = Path(sys.argv[1])
    chosen = MODES[sys.argv[2] if len(sys.argv) > 2 else "steered"]
    outdir.mkdir(parents=True, exist_ok=True)
    for name, f in chosen.items():
        (outdir / f"WIMSE_{name}.spthy").write_text(render(name, f))
    (outdir / "variants.txt").write_text("\n".join(chosen) + "\n")


if __name__ == "__main__":
    main()
