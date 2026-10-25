import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text()
outdir = pathlib.Path(sys.argv[2])
outdir.mkdir(parents=True, exist_ok=True)

private_answer = "out(agentview, (tid, {ans}))."
public_provenance = (
    "let p = (prov, tracker, tid, {ans}) in\n"
    "  out(c, (p, sign(p, skT)));\n"
    "  out(agentview, (tid, {ans}))."
)
provenance_check = (
    "in(c, (p: bitstring, sp: bitstring));\n"
    "  if checksign(sp, pkT) = p then\n"
    "  let (=prov, =src, =tid, =v) = p in\n"
    "  if src = tracker then\n"
)
nonconformant_query = "query t: bitstring; event(Accept((push, repoY), t)).\n\n"

variants = {
    "equiv_chainview": (private_answer, "", "choice[repoY, repoX]", ""),
    "equiv_provenance": (public_provenance, provenance_check, "choice[repoY, repoX]", ""),
    "reach_chainview_tracker_said_repoX": (private_answer, "", "repoX", nonconformant_query),
    "reach_provenance_tracker_said_repoX": (public_provenance, provenance_check, "repoX", nonconformant_query),
}

for name, (answer, check, ans, query) in variants.items():
    body = source.replace("TRACKER_ANSWER.", answer.format(ans=ans))
    body = body.replace("RESOURCE_PROVENANCE_CHECK\n", check)
    body = body.replace("\nprocess\n", "\n" + query + "process\n")
    (outdir / f"{name}.pv").write_text(body)
