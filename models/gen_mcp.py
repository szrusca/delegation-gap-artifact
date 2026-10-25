import sys
from pathlib import Path

VARIANTS = {
    "spec": {"AUDM", "SCOPECHK"},
    "spec_must": {"AUDM"},
    "noaud": {"SCOPECHK"},
    "noaud_noscope": set(),
    "opscope": {"AUDM", "SCOPECHK", "OPSCOPE"},
    "xchg": {"AUDM", "SCOPECHK", "XCHG"},
    "xchg_dpop": {"AUDM", "SCOPECHK", "XCHG", "DPOP"},
}

DPOP_ONLY_VARIANTS = {"spec_dpop": {"AUDM", "SCOPECHK", "DPOP"}}

NOLEAK_VARIANTS = {
    "spec_noleak": {"AUDM", "SCOPECHK", "NOLEAK"},
    "xchg_noleak": {"AUDM", "SCOPECHK", "XCHG", "NOLEAK"},
}

KC_VARIANTS = {f"kc_{name}": f | {"KEYCOMP"} for name, f in VARIANTS.items()}

FIX_VARIANTS = {"allfix": {"AUDM", "SCOPECHK", "OPSCOPE", "XCHG", "DPOP"}}

CAPSULE_VARIANTS = {
    "r016_base": {"AUDM", "SCOPECHK", "OPENSRC"},
    "r016_capsule": {"AUDM", "SCOPECHK", "OPENSRC", "CAPSULE"},
    "r016_prov": {"AUDM", "SCOPECHK", "OPENSRC", "PROV"},
    "r016_capsule_prov": {"AUDM", "SCOPECHK", "OPENSRC", "CAPSULE", "PROV"},
    "mcp_allfix_cp": {"AUDM", "SCOPECHK", "OPSCOPE", "XCHG", "DPOP", "OPENSRC", "CAPSULE", "PROV"},
}

MODES = {"steered": VARIANTS, "noleak": NOLEAK_VARIANTS, "kc": KC_VARIANTS, "fix": FIX_VARIANTS,
         "capsule": CAPSULE_VARIANTS, "dpoponly": DPOP_ONLY_VARIANTS}

HEADER = """theory MCP_{name}
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

restriction OneUpstreamGrantPerUserServerResource:
  "All H M R #i #j. UpConsent(H, M, R) @ #i & UpConsent(H, M, R) @ #j ==> #i = #j"

rule Register:
  [ Fr(~k) ]
  --[ Register($X) ]->
  [ !Ltk($X, ~k), !Pk($X, pk(~k)), Out(pk(~k)) ]

rule Human_authorizes_server_upstream:
  [ !Ltk($H, kH) ]
  --[ UpConsent($H, $M, $R) ]->
  [ !UpTok($M, $H, $R) ]
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


def consent_rule(kind, f):
    cnf = "pkC" if "DPOP" in f else "'none'"
    pkprem = ", !Pk($C, pkC)" if "DPOP" in f else ""
    extra_in = ""
    if kind == "static":
        scope = "<'push', $repo>" if "OPSCOPE" in f else "<'push', 'any'>"
        acts = "Intends($H, ~tid, <'fixed', 'push', $repo>), TaskStatic(~tid)"
        out_extra = ""
    elif kind == "dynamic":
        if "OPSCOPE" in f:
            scope = "<'push', v>"
            extra_in = ", In(v)"
        else:
            scope = "<'push', 'any'>"
        acts = "Intends($H, ~tid, <'hole', 'push', $Src>), TaskDynamic(~tid)"
        out_extra = ", !TaskOpen(~tid, $Src)"
    else:
        scope = "<$op, $x>" if "OPSCOPE" in f else "<$op, 'any'>"
        acts = "OtherGrant(~tid)"
        out_extra = ""
    if "CAPSULE" in f and kind != "other":
        tmpl = "<'fixed', 'push', $repo>" if kind == "static" else "<'hole', 'push', $Src>"
        cap = f"<'cap', $H, ~tid, {tmpl}>"
        out_extra += f", Out(<{cap}, sign({cap}, kH)>)"
    return f"""
rule Human_consents_{kind}:
  let t1 = <'at', $H, $C, $M, {scope}, {cnf}, ~tid>
  in
  [ Fr(~tid), !Ltk($H, kH), !Ltk('AS', kAS){pkprem}{extra_in} ]
  --[ Consent($H, $C, $M, {scope}, ~tid), {acts} ]->
  [ {"!HeldBy($C, t1, sign(t1, kAS))" if "NOLEAK" in f else "Out(<t1, sign(t1, kAS)>)"}{out_extra} ]
"""


OPEN_SOURCE = """
rule Source_produces:
  let p = <'prov', $Src, tid, $v>
  in
  [ In(tid), !Ltk($Src, ks) ]
  --[ Produced($Src, tid, $v) ]->
  [ Out(<p, sign(p, ks)>) ]
"""

SOURCE = """
rule Source_produces:
  [ !TaskOpen(tid, $Src), !Ltk($Src, ks) ]
  --[ Produced($Src, tid, $v) ]->
  [ Out(<'prov', $Src, tid, $v>) ]
"""


def agent_rule(f):
    if "NOLEAK" in f:
        held, out = "!HeldBy($C, tok, ts)", "CallTLS(a, $M, $R, tok, ts, sign(pr, kC))"
    else:
        held, out = "In(<tok, ts>)", "Out(<'call', a, $M, $R, tok, ts, sign(pr, kC)>)"
    return f"""
rule Agent_calls_tool:
  let tok = <'at', H, $C, aud, s, cnf, tid>
      pr  = <'dpop', a, $M, h(<tok, ts>)>
  in
  [ {held}, In(<$M, $R, a>), !Ltk($C, kC) ]
  --[ Request($C, a, tid) ]->
  [ {out} ]
"""


def evidence_cases(f):
    if "CAPSULE" not in f and "PROV" not in f:
        return [("Server_executes_tool_call", [], [], [])]
    cases = []
    if "CAPSULE" not in f:
        cases.append(("Server_executes_with_any_provenance", ["a = <op, v>", "p = <'prov', Src, tid, v>"],
                      ["In(<p, sp>)", "!Pk(Src, pkSrc)"], ["Eq(verify(sp, p, pkSrc), true)", "ProvFrom(Src, tid, v)"]))
        return cases
    cases.append(("Server_executes_capsule_fixed", ["cap = <'cap', H, tid, <'fixed', a>>"],
                  ["In(<cap, sc>)", "!Pk(H, pkH)"], ["Eq(verify(sc, cap, pkH), true)"]))
    if "PROV" in f:
        cases.append(("Server_executes_capsule_hole_provenance",
                      ["a = <op, v>", "cap = <'cap', H, tid, <'hole', op, Src>>", "p = <'prov', Src, tid, v>"],
                      ["In(<cap, sc>)", "!Pk(H, pkH)", "In(<p, sp>)", "!Pk(Src, pkSrc)"],
                      ["Eq(verify(sc, cap, pkH), true)", "Eq(verify(sp, p, pkSrc), true)", "ProvFrom(Src, tid, v)"]))
    else:
        cases.append(("Server_executes_capsule_hole_unchecked",
                      ["a = <op, v>", "cap = <'cap', H, tid, <'hole', op, Src>>"],
                      ["In(<cap, sc>)", "!Pk(H, pkH)"], ["Eq(verify(sc, cap, pkH), true)"]))
    return cases


def server_rule(f):
    checks = ["Eq(verify(ts, tok, pkAS), true)", "Act(a)"]
    if "AUDM" in f:
        checks.append("Eq(aud, $M)")
    if "SCOPECHK" in f:
        checks.append("Check(s, a)")
    if "DPOP" in f:
        checks.append("Eq(verify(pr, <'dpop', a, $M, h(<tok, ts>)>, cnf), true)")
    head = ["CallTLS(a, $M, $R, tok, ts, pr)" if "NOLEAK" in f else "In(<'call', a, $M, $R, tok, ts, pr>)",
            "!Pk('AS', pkAS)", "!UpTok($M, H, $R)"]
    out = []
    for rname, lets, prems, extra in evidence_cases(f):
        letlines = "".join(f"\n      {x}" for x in lets)
        out.append(f"""
rule {rname}:
  let tok = <'at', H, C, aud, s, cnf, tid>{letlines}
  in
  [ {", ".join(head + prems)} ]
  --[ {", ".join(checks + extra + ["ToolExec($M, H, C, a, tid)"])} ]->
  [ UpReq($M, $R, H, C, a, tid) ]
""")
    return "".join(out)


def resource_rule(f):
    logged = "C" if "XCHG" in f else "M"
    return f"""
rule Resource_accepts_upstream_call:
  [ UpReq(M, R, H, C, a, tid) ]
  --[ Accept(R, H, {logged}, a, tid), ViaServer(R, M, a, tid) ]->
  [ ]
"""


KC_LEMMAS = """
lemma kc_witness_as_reveal_breaks_CONSENT_M:
  exists-trace
  "Ex M H C a tid #i #r.
     ToolExec(M, H, C, a, tid) @ #i & Reveal('AS') @ #r
     & not (Ex s #j. Consent(H, C, M, s, tid) @ #j)"

lemma kc_witness_client_reveal_breaks_ATTR:
  exists-trace
  "Ex R H L a tid #i #r.
     Accept(R, H, L, a, tid) @ #i & Reveal(L) @ #r
     & not (Ex #j. Request(L, a, tid) @ #j)"
"""


def lemmas(f):
    return (KC_LEMMAS if "KEYCOMP" in f else "") + f"""
lemma executable_static_task_conformant:
  exists-trace
  "Ex R H L a tid #i #j #k.
     Accept(R, H, L, a, tid) @ #i & TaskStatic(tid) @ #j & Intends(H, tid, <'fixed', a>) @ #k{no_reveal(f)}"

lemma executable_dynamic_task_conformant:
  exists-trace
  "Ex R H L op v S tid #i #k #l.
     Accept(R, H, L, <op, v>, tid) @ #i
     & Intends(H, tid, <'hole', op, S>) @ #k & Produced(S, tid, v) @ #l{no_reveal(f)}"

lemma witness_cross_server_token_replay:
  exists-trace
  "Ex M M2 H C a s tid #i #j.
     ToolExec(M, H, C, a, tid) @ #i & Consent(H, C, M2, s, tid) @ #j & not (M = M2){none_revealed(f, "'AS'")}"

lemma witness_scope_escalation_via_upstream_token:
  exists-trace
  "Ex R M H L C a s tid #i #k #j.
     Accept(R, H, L, a, tid) @ #i & ViaServer(R, M, a, tid) @ #i
     & ToolExec(M, H, C, a, tid) @ #k & Consent(H, C, M, s, tid) @ #j
     & not (s = a) & not (Ex op x. a = <op, x> & s = <op, 'any'>){none_revealed(f, "'AS'")}"

lemma witness_identity_collapse:
  exists-trace
  "Ex R H L M a b t1 t2 C1 C2 #i #j #k #l.
     Accept(R, H, L, a, t1) @ #i & Accept(R, H, L, b, t2) @ #j
     & ToolExec(M, H, C1, a, t1) @ #k & ToolExec(M, H, C2, b, t2) @ #l
     & not (C1 = C2){none_revealed(f, "'AS'")}"

lemma CONSENT_M_server_acts_only_on_its_own_grant:
  "All M H C a tid #i.
     ToolExec(M, H, C, a, tid) @ #i
     ==> (Ex s #j. Consent(H, C, M, s, tid) @ #j){unless(f, "'AS'")}"

lemma NOESC_upstream_action_within_consent_at_server:
  "All R M H L a tid #i.
     Accept(R, H, L, a, tid) @ #i & ViaServer(R, M, a, tid) @ #i
     ==> (Ex C s #j. Consent(H, C, M, s, tid) @ #j
         & (s = a | (Ex op x. a = <op, x> & s = <op, 'any'>))){unless(f, "'AS'")}"

lemma ATTR_agent_logged_client_decided_call:
  "All R H L a tid #i.
     Accept(R, H, L, a, tid) @ #i
     ==> (Ex #j. Request(L, a, tid) @ #j & #j < #i){unless(f, "'AS'", "L")}"

lemma TASK_static_task:
  "All R H L a tid #i #j.
     Accept(R, H, L, a, tid) @ #i & TaskStatic(tid) @ #j
     ==> (Ex #k. Intends(H, tid, <'fixed', a>) @ #k){unless(f, "'AS'")}"

lemma TASK_dynamic_task:
  "All R H L op v tid #i #j.
     Accept(R, H, L, <op, v>, tid) @ #i & TaskDynamic(tid) @ #j
     ==> (Ex S #k #l. Intends(H, tid, <'hole', op, S>) @ #k & Produced(S, tid, v) @ #l){unless(f, "'AS'")}"

end
"""


OPSCOPE_RESTRICTION = """
restriction OperandScopesAreConcrete:
  "All H C M op t #i. Consent(H, C, M, <op, 'any'>, t) @ #i ==> F"
"""


def render(name, f):
    return (HEADER.format(name=name) + (REVEAL if "KEYCOMP" in f else "")
            + (OPSCOPE_RESTRICTION if "OPSCOPE" in f else "") + consent_rule("static", f) + consent_rule("dynamic", f)
            + consent_rule("other", f) + (OPEN_SOURCE if "OPENSRC" in f else SOURCE) + agent_rule(f) + server_rule(f) + resource_rule(f) + lemmas(f))


def main():
    outdir = Path(sys.argv[1])
    chosen = MODES[sys.argv[2] if len(sys.argv) > 2 else "steered"]
    outdir.mkdir(parents=True, exist_ok=True)
    for name, f in chosen.items():
        (outdir / f"MCP_{name}.spthy").write_text(render(name, f))
    (outdir / "variants.txt").write_text("\n".join(chosen) + "\n")


if __name__ == "__main__":
    main()
