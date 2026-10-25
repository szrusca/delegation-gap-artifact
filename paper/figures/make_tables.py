import json
import re
import sys
from collections import defaultdict
from pathlib import Path

YES, NO = r"\cmark", r"\xmark"

EVIDENCE = ["chain", "chain+reqbind", "chain+capsule", "chain+prov", "chain+reqbind+capsule",
            "chain+reqbind+prov", "chain+capsule+prov", "chain+reqbind+capsule+prov"]
EVIDENCE_LABEL = {
    "chain": "Chain", "chain+reqbind": "+ReqBind", "chain+capsule": "+Capsule", "chain+prov": "+Prov",
    "chain+reqbind+capsule": "+ReqBind+Capsule", "chain+reqbind+prov": "+ReqBind+Prov",
    "chain+capsule+prov": "+Capsule+Prov", "chain+reqbind+capsule+prov": "+all three"}
ABS_LEMMAS = ["AUTH_every_hop_was_delegated", "NOESC_action_within_root_caveat",
              "ATTR_logged_principal_sent_request", "TASK_static_task", "TASK_dynamic_task"]

PROTOCOL_LEMMAS = {
    "rfc8693": ["AUTH_nested_act_chain_was_delegated", "NOESC_action_within_human_consent",
                "ATTR_logged_current_actor_sent_request", "TASK_static_task", "TASK_dynamic_task"],
    "mcp": ["CONSENT_M_server_acts_only_on_its_own_grant", "NOESC_upstream_action_within_consent_at_server",
            "ATTR_agent_logged_client_decided_call", "TASK_static_task", "TASK_dynamic_task"],
    "obo": ["AUTH_consent_names_client_and_actor", "NOESC_action_within_consent",
            "ATTR_actor_logged_actor_decided_request", "TASK_static_task", "TASK_dynamic_task"],
    "wimse": ["CHAINAUTH_registered_parent_requested_subdelegation", "NOESC_exercise_within_human_authorization",
              "ATTR_R_logged_principal_decided_request", "TASK_static_task", "TASK_dynamic_task"],
    "aip": ["AUTH_every_hop_was_delegated", "NOESC_action_within_root_caveat",
            "ATTR_logged_principal_sent_request", "TASK_static_task", "TASK_dynamic_task"],
}

PLACEMENT = [
    ("RFC 8693, base", "rfc8693", [("R006", "base")]),
    ("RFC 8693, all four fixes", "rfc8693", [("R006", "all")]),
    ("MCP 2026-07-28, spec", "mcp", [("R007", "spec")]),
    ("MCP, all native fixes", "mcp", [("R011_mcp", "allfix")]),
    ("MCP, all fixes + Capsule + Prov", "mcp", [("R016", "mcp_allfix_cp")]),
    ("OBO draft-02, as written", "obo", [("R008", "base")]),
    ("OBO, all fixes", "obo", [("R011_obo", "obo_allfix")]),
    ("WIMSE -00, minimal (policy)", "wimse", [("R009_perlemma", "spec_min")]),
    ("WIMSE, all fixes + Capsule + Prov", "wimse", [("R011_wimse", "wimse_allfix")]),
    ("AIP (chained mode)", "aip", [("R010", "AIP")]),
    ("AIP + Capsule + Prov", "aip", [("R017", "aip_capsule_prov")]),
]

PRECONDITIONS = {'F1': 'leak', 'F2': 'aud', 'M1': 'conf.', 'M2': 'opt.', 'M3': 'leak', 'O1': 'conf.', 'O2': 'conf.', 'W-a': 'leak', 'W-b': 'conf.', 'W-c': 'conf.', 'A2': 'conf.'}

ATTACKS = [
    ("F1", "RFC 8693", "nested-act splice", "R006", "witness_splice_chain_names_undelegated_hop", None, "+MAYACT"),
    ("F2", "RFC 8693", "act-stripping", "R006", "witness_act_stripping_logs_human", None, "+DPOP+AUD"),
    ("M1", "MCP 2026-07-28", "identity collapse", "R007", "witness_identity_collapse", None, "xchg"),
    ("M2", "MCP 2026-07-28", "scope escalation", "R007", "witness_scope_escalation_via_upstream_token", None, "spec (scope check)"),
    ("M3", "MCP 2026-07-28", "misattribution", "R007", "ATTR_agent_logged_client_decided_call", {"xchg"}, "xchg\\_dpop"),
    ("O1", "OBO -02", "actor framing", "R008", "witness_client_acts_logged_as_actor", None, "dpop\\_actor"),
    ("O2", "OBO -02", "non-participation", "R008", "witness_actor_named_without_participation", None, "actbind"),
    ("W-a", "WIMSE -00", "unauthenticated sub-delegation", "R009_perlemma", "witness_splice_child_without_parent_request", None, "subpop"),
    ("W-b", "WIMSE -00", "key-not-agent attribution", "R009_perlemma", "witness_exercise_by_unregistered_did", None, "didpreauth"),
    ("W-c", "WIMSE -00", "identity collapse at R", ("R009_w3prune", "R009"), "witness_identity_collapse_at_resource", None, "fix\\_rfwd (R011)"),
    ("A2", "AIP v1", "context laundering", "R010", "witness_context_laundering", None, "Capsule (R017)"),
]


def load(path):
    data = json.loads(Path(path).read_text())
    idx = {}
    for r in data["rows"]:
        idx[(r["run"], r["variant"], r["lemma"])] = r
    return data, idx


def mark(idx, run, variant, lemma):
    r = idx.get((run, variant, lemma))
    if r is None:
        raise KeyError(f"missing verdict {run} {variant} {lemma}")
    return YES if r["verdict"] == "proved" else NO


def seconds(times, rel):
    return times.get(rel)


def lattice_table(idx, times):
    rows = []
    for e in EVIDENCE:
        c2 = [mark(idx, "R003_n2", e, l) for l in ABS_LEMMAS]
        c3 = [mark(idx, "R004", e, l) for l in ABS_LEMMAS]
        if c2 != c3:
            raise ValueError(f"n=2 and n=3 differ for {e}")
        t2, t3 = seconds(times, f"R003_n2/{e}.time"), seconds(times, f"R004/{e}.time")
        rows.append(f"{EVIDENCE_LABEL[e]} & " + " & ".join(c2) + f" & {t2:.0f} & {t3:.0f} \\\\")
    return "\n".join([
        r"\begin{table}[t]", r"\centering",
        r"\caption{The evidence lattice under steered agents. Verdicts are identical at chain length $n=2$ (R003) and $n=3$ (R004): 80/80 cells match the predictions written before the runs and all 32 executability lemmas verify. \cmark: proved for all traces; \xmark: counterexample trace found. Times in seconds per variant.}",
        r"\label{tab:lattice}", r"\footnotesize", r"\setlength{\tabcolsep}{2.2pt}",
        r"\begin{tabular}{lccccc rr}", r"\toprule",
        r"Evidence & AUTH & NOESC & ATTR & TASK$_s$ & TASK$_d$ & $t_{n=2}$ & $t_{n=3}$ \\", r"\midrule",
        *rows, r"\bottomrule", r"\end{tabular}", r"\end{table}"])


def adversary_table(idx):
    rows = []
    for e in EVIDENCE:
        cells = []
        for adv in ["honest", "steered", "keycomp"]:
            cells.append("\\,".join(mark(idx, "R005", f"{adv}/{e}", l) for l in ABS_LEMMAS))
        rows.append(f"{EVIDENCE_LABEL[e]} & " + " & ".join(cells) + r" \\")
    return "\n".join([
        r"\begin{table}[t]", r"\centering",
        r"\caption{Adversary baselines on the abstract chain (R005, 120/120 cells match). Each cell lists AUTH, NOESC, ATTR, TASK$_s$, TASK$_d$ in order. Only the steered adversary makes Capsule and Prov necessary beyond ReqBind while AUTH and ATTR stay attainable.}",
        r"\label{tab:adversaries}", r"\footnotesize", r"\setlength{\tabcolsep}{2.5pt}",
        r"\begin{tabular}{l ccc}", r"\toprule",
        r"Evidence & HONEST & STEERED & KEYCOMP (agents) \\", r"\midrule",
        *rows, r"\bottomrule", r"\end{tabular}", r"\end{table}"])


def placement_table(idx):
    rows = []
    for label, proto, refs in PLACEMENT:
        run, variant = refs[0]
        cells = [mark(idx, run, variant, l) for l in PROTOCOL_LEMMAS[proto]]
        rows.append(f"{label} & " + " & ".join(cells) + f" & {run.split('_')[0]} \\\\")
    return "\n".join([
        r"\begin{table*}[t]", r"\centering",
        r"\caption{Placement of the analyzed schemes in the lattice, as specified and with all fixes. AUTH is the protocol's chain or consent authentication property; ATTR is attribution at the resource that executes the action.}",
        r"\label{tab:placement}", r"\small", r"\setlength{\tabcolsep}{2.5pt}",
        r"\begin{tabular}{l ccccc l}", r"\toprule",
        r"Scheme / configuration & AUTH & NOESC & ATTR & TASK$_s$ & TASK$_d$ & Run \\", r"\midrule",
        *rows, r"\bottomrule", r"\end{tabular}", r"\end{table*}"])


def step_range(data, run, lemma, variants):
    steps, vs = [], []
    for r in data["rows"]:
        runs = run if isinstance(run, tuple) else (run,)
        if r["run"] not in runs or r["lemma"] != lemma or r["verdict"] not in ("witness_found", "attack_trace"):
            continue
        if variants and r["variant"] not in variants:
            continue
        steps.append(r["steps"])
        vs.append(r["variant"].split("/")[-1].replace("w3p_", ""))
    if not steps:
        raise KeyError(f"no trace for {run} {lemma}")
    lo, hi = min(steps), max(steps)
    return (f"{lo}" if lo == hi else f"{lo}--{hi}"), len(set(vs))


def attack_table(data):
    rows = []
    for fid, proto, name, run, lemma, variants, fix in ATTACKS:
        pre = PRECONDITIONS[fid]
        rng, nvar = step_range(data, run, lemma, variants)
        first = run[0] if isinstance(run, tuple) else run
        rows.append(f"{fid} & {proto} & {name} & {pre} & {first.split('_')[0]} & {nvar} & {rng} & {fix} \\\\")
    rows.append(r"\midrule")
    rows.append(r"TASK$_s$ & all & operand not human-anchored & conf. & R006--R010 & -- & -- & operand-level human consent \\")
    rows.append(r"TASK$_d$ & all & hole not source-anchored & conf. & R006--R010 & -- & -- & Capsule + Prov (R012, R016) \\")
    return "\n".join([
        r"\begin{table*}[t]", r"\centering",
        r"\caption{The 11 attacks, the number of variants in which each trace exists, the trace length in Tamarin steps (min--max across those variants), and the fix that removes the attack's witness trace (verified in the attack's run unless stated); for F2, M3 and W-c the listed pair also restores ATTR (Section~\ref{sec:fixes}). Every fix variant also passes its executability lemmas. For M3 the count covers only the variants that carry the client upstream (XCHG); in the other R007 variants ATTR already fails through M1. Pre.\ is what the trace needs beyond the specified configuration: conf.\ nothing (a conformant configuration); leak, a token held by a steered agent reaches another party; opt., a recommended (SHOULD) check is omitted; aud, $R$ skips its audience check. The last two rows are the generic TASK failures and are not counted among the 11.}",
        r"\label{tab:attacks}", r"\small", r"\setlength{\tabcolsep}{4pt}",
        r"\begin{tabular}{l l l l l c c l}", r"\toprule",
        r"ID & Scheme & Attack & Pre. & Run & \#variants & Steps & Fix (verified in) \\", r"\midrule",
        *rows, r"\bottomrule", r"\end{tabular}", r"\end{table*}"])


def ablation_table(idx):
    spec = [
        ("R012", ["r012_base", "r012_capsule", "r012_prov", "r012_capsule_prov"], "wimse", ("R011_wimse", "wimse_allfix")),
        ("R016", ["r016_base", "r016_capsule", "r016_prov", "r016_capsule_prov"], "mcp", ("R016", "mcp_allfix_cp")),
    ]
    labels = ["base", "+Capsule", "+Prov", "+Capsule+Prov", "all fixes + C + P"]
    cols = []
    for run, variants, key, allfix in spec:
        col = [[mark(idx, run, v, l) for l in PROTOCOL_LEMMAS[key][3:]] for v in variants]
        col.append([mark(idx, allfix[0], allfix[1], l) for l in PROTOCOL_LEMMAS[key][3:]])
        cols.append(col)
    rows = [f"{lab} & " + " & ".join(cols[0][k]) + " & " + " & ".join(cols[1][k]) + " \\\\" for k, lab in enumerate(labels)]
    return "\n".join([
        r"\begin{table}[t]", r"\centering",
        r"\caption{Capsule and provenance ablation on WIMSE (R012; all fixes: R011) and MCP (R016) under the broad \texttt{push:any} grant and steered agents. Removing either piece reopens TASK$_d$ on both. The last row adds every fix; all properties then hold (Table~\ref{tab:placement}).}",
        r"\label{tab:ablation}", r"\small", r"\setlength{\tabcolsep}{4pt}",
        r"\begin{tabular}{l cc cc}", r"\toprule",
        r" & \multicolumn{2}{c}{WIMSE} & \multicolumn{2}{c}{MCP} \\", r"Evidence & TASK$_s$ & TASK$_d$ & TASK$_s$ & TASK$_d$ \\", r"\midrule",
        *rows, r"\bottomrule", r"\end{tabular}", r"\end{table}"])


def counts_table(data):
    prop = re.compile(r"^(AUTH|NOESC|ATTR|TASK|CONSENT|PARTICIPATION|CHAINAUTH)")
    cells, wit, ex, var = defaultdict(set), defaultdict(set), defaultdict(set), defaultdict(set)
    for r in data["rows"]:
        k = (r["variant"].split("/")[-1] if r["run"] != "R005" else r["variant"], r["lemma"])
        group = {"R009_perlemma": "R009", "R009_w3prune": "R009"}.get(r["run"], r["run"])
        if prop.match(r["lemma"]):
            cells[group].add(k)
            var[group].add(k[0])
        elif r["lemma"].startswith("executable"):
            ex[group].add(k)
        elif "witness" in r["lemma"] and r["run"] != "R009_w3prune":
            wit[group].add(k)
    for r in data["rows"]:
        if r["run"] == "R009_w3prune":
            wit["R009"].add((r["variant"].replace("w3p_", ""), r["lemma"]))
    order = ["R003_n2", "R004", "R005", "R006", "R007", "R007_noleak", "R008", "R009", "R010", "R011_mcp",
             "R011_obo", "R011_wimse", "R012", "R016", "R017", "R018", "R006_kc", "R007_kc", "R008_kc", "R009_kc"]
    rows, tot_main, tot_kc = [], 0, 0
    for g in order:
        n = len(cells[g])
        if g.endswith("_kc"):
            tot_kc += n
        else:
            tot_main += n
        rows.append(f"{g.replace('_', chr(92) + '_')} & {len(var[g])} & {n} & {len(wit[g])} & {len(ex[g])} \\\\")
    rows.append(r"\midrule")
    rows.append(f"Total steered/honest & & {tot_main} & & \\\\")
    rows.append(f"Total KEYCOMP & & {tot_kc} & & \\\\")
    rows.append(f"Total & & {tot_main + tot_kc} & & \\\\")
    return "\n".join([
        r"\begin{table}[t]", r"\centering",
        r"\caption{Per-run counts of property-cell verdicts, witness-lemma verdicts (trace found or not) and executability lemmas, extracted from the Tamarin logs. Every verdict matches the prediction written before its run (Section~\ref{sec:validation}).}",
        r"\label{tab:counts}", r"\footnotesize", r"\setlength{\tabcolsep}{3pt}",
        r"\begin{tabular}{l rrrr}", r"\toprule",
        r"Run & Var. & Cells & Witn. & Exec. \\", r"\midrule",
        *rows, r"\bottomrule", r"\end{tabular}", r"\end{table}"]), tot_main, tot_kc


def main():
    data, idx = load(sys.argv[1])
    out = Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    times = data["times_seconds"]
    (out / "tab_lattice.tex").write_text(lattice_table(idx, times) + "\n")
    (out / "tab_adversaries.tex").write_text(adversary_table(idx) + "\n")
    (out / "tab_placement.tex").write_text(placement_table(idx) + "\n")
    (out / "tab_attacks.tex").write_text(attack_table(data) + "\n")
    (out / "tab_ablation.tex").write_text(ablation_table(idx) + "\n")
    counts, main_n, kc_n = counts_table(data)
    (out / "tab_counts.tex").write_text(counts + "\n")
    print("tables written; property cells:", main_n, "+", kc_n, "=", main_n + kc_n)


if __name__ == "__main__":
    main()
