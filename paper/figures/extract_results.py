import json
import re
import sys
from pathlib import Path

LINE = re.compile(r"^\s+(\S+) \((all-traces|exists-trace)\): (verified|falsified - found trace|falsified - no trace found) \((\d+) steps\)")
EXCLUDED_PARTS = {"void_wellformedness", "failed_no_toolchain", "keycomp_void_restriction", "honest_pre_provfrom",
                  "steered_pre_provfrom", "exists_exec_superseded"}
EXCLUDED_RUNS = {"R006_kc_void_invariant", "R006_prev_pass", "R006_diag", "R008_misnamed_witness",
                 "R009_w3", "R009_w3guided", "R009_w3pc", "R015", "R015_proverif", "R017_void_unbound"}


def verdict_of(kind, word):
    if word == "verified":
        return "witness_found" if kind == "exists-trace" else "proved"
    if word == "falsified - found trace":
        return "attack_trace"
    return "no_witness"


def variant_of(run_dir, log):
    rel = log.relative_to(run_dir)
    prefix = "/".join(rel.parts[:-1])
    stem = rel.name[:-4]
    stem = stem.split(".")[0]
    return f"{prefix}/{stem}" if prefix else stem


def main():
    root = Path(sys.argv[1])
    out = Path(sys.argv[2])
    rows = {}
    conflicts = []
    for run_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        if run_dir.name in EXCLUDED_RUNS:
            continue
        for log in sorted(run_dir.rglob("*.log")):
            if EXCLUDED_PARTS & set(log.relative_to(run_dir).parts):
                continue
            variant = variant_of(run_dir, log)
            for line in log.read_text(errors="replace").splitlines():
                m = LINE.match(line)
                if not m:
                    continue
                lemma, kind, word, steps = m.groups()
                key = (run_dir.name, variant, lemma)
                row = {"run": run_dir.name, "variant": variant, "lemma": lemma, "kind": kind,
                       "verdict": verdict_of(kind, word), "steps": int(steps), "log": str(log.relative_to(root))}
                if key in rows and rows[key]["verdict"] != row["verdict"]:
                    conflicts.append([rows[key], row])
                rows[key] = row
    times = {}
    for t in sorted(root.rglob("*.time")):
        if EXCLUDED_PARTS & set(t.relative_to(root).parts) or t.relative_to(root).parts[0] in EXCLUDED_RUNS:
            continue
        parts = t.read_text().split()
        try:
            times[str(t.relative_to(root))] = float(parts[-1])
        except (ValueError, IndexError):
            pass
    out.write_text(json.dumps({"rows": sorted(rows.values(), key=lambda r: (r["run"], r["variant"], r["lemma"])),
                               "conflicts": conflicts, "times_seconds": times}, indent=1))
    print(len(rows), "verdicts;", len(conflicts), "conflicts;", len(times), "time files")


if __name__ == "__main__":
    main()
