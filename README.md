# Artifact: The Delegation–Authorization Gap in Multi-Hop AI-Agent Chains

Artifact for the paper *The Delegation–Authorization Gap in Multi-Hop AI-Agent Chains: A Formal Foundation and Protocol Analysis* (Zhouran Song, independent researcher, songzhouran@gmail.com).

It contains every model, generator, prediction file, raw prover log and replay script behind the paper's tables. Every table in the paper is generated from these files.

## Contents

| Path | What it is |
|---|---|
| `models/AbsChain.spthy`, `models/AbsChain3.spthy` | Abstract chain at n = 2 and n = 3. Compile-time flags select the evidence set (`REQBIND`, `CAPSULE`, `PROV`) and the adversary (`HONEST`, `KEYCOMP`). |
| `models/Separation.spthy`, `models/Separation.pvm4`, `models/gen_separation.py` | The chain-view separation (Lemma 2): the Tamarin version, and the ProVerif template plus its expander. |
| `models/gen_rfc8693.py`, `gen_mcp.py`, `gen_obo.py`, `gen_wimse.py` | Generators for every protocol variant (RFC 8693, MCP 2026-07-28, OBO draft-02, WIMSE draft-00). |
| `models/AIP.spthy` | AIP chained mode. With no flags this is R010; `-D=CAPSULE` and `-D=CAPSULE -D=PROV` give R017. |
| `models/generated/` | Every generated variant that was run. |
| `models/results/R0xx/` | Raw Tamarin/ProVerif logs (`*.log`) and wall-clock times (`*.time`) per run. |
| `models/r013/`, `models/results/R013/` | Keycloak 26.7.5 replay of F1/F2. |
| `models/r014/`, `models/results/R014/` | MCP TypeScript SDK 1.32.1 replay of M1–M3. |
| `artifact/predictions/` | Predictions written before each run, and the R003 research plan. |
| `artifact/MANIFEST.md` | SHA-256 digests of the prediction files and of the ProVerif files. |
| `paper/figures/extract_results.py`, `make_tables.py`, `data/` | Verdict extractor, the extracted index, and the table generator. |
| `refine-logs/EXPERIMENT_RESULTS.md`, `EXPERIMENT_TRACKER.md` | Per-run narrative: setup, verdicts, model corrections, void passes. |

Void and superseded passes stay in clearly named subdirectories, for example `R017_void_unbound/` and `R014/void_port_race/`. They are excluded from every count; `extract_results.py` lists the exclusions.

## Requirements

- Tamarin prover 1.12.0 (official Linux binary) and Maude 3.5.1
- ProVerif 2.05
- Python 3.10 or later (standard library only)
- Node.js 20 or later, for R014
- Docker, for R013 (Keycloak 26.7.5)

## Reproducing

**Tables from the shipped logs** (no prover needed):

```
python3 paper/figures/extract_results.py models/results paper/figures/data/results_index.json
python3 paper/figures/make_tables.py paper/figures/data/results_index.json out_tables
```

The output equals the paper's tables byte for byte. It reports 1096 verdicts, and 601 property cells (460 + 141).

**Re-running a model**, for example the lattice at n = 2 (8 variants):

```
bash models/run_lattice.sh models/AbsChain.spthy out/R003
```

Protocol variants:

```
python3 models/gen_mcp.py out/mcp steered
bash models/run_mcp.sh out/mcp out/R007
```

Generator modes are listed in each generator's `MODES` table.

R017 (AIP with a capsule):

```
tamarin-prover models/AIP.spthy --prove -D=CAPSULE
```

**MCP SDK replay (R014):**

```
cd models/r014 && npm ci && node replay.mjs run.json
```

**Prediction digests:**

```
sha256sum artifact/predictions/*
```

Compare the output with `artifact/MANIFEST.md`.

## Notes

- Timestamps in the prediction files are self-recorded; they are not externally attested.
- Some prediction files mention internal review threads by id; those review notes are not part of the artifact.
- The absolute path prefix of the original working directory was removed from 14 raw logs (the `analyzed:` lines of R009_w3prune, R009_w3guided and R016). No verdict line changed.
- `models/r014/node_modules` is not shipped; `npm ci` restores the pinned versions from `package-lock.json`.

## License

Code (models, generators, scripts) is released under the MIT License. Logs, prediction files and documentation are released under CC BY 4.0. See `LICENSE`.

## Citation

See `CITATION.cff`.
