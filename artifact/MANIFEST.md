# Artifact Manifest

Paper: The Delegation–Authorization Gap in Multi-Hop AI-Agent Chains (Z. Song).

## Contents
- `models/`: Tamarin and ProVerif models and generators. These are AbsChain (n = 2, 3, with HONEST/KEYCOMP switches), Separation, AIP, and gen_rfc8693/gen_mcp/gen_obo/gen_wimse.
- `models/generated/`: every generated protocol variant.
- `models/results/`: raw prover logs and timings per run (R003–R018). The implementation replays are `models/r013/` (Keycloak) and `models/r014/` (MCP TypeScript SDK; `npm ci` installs the pinned versions). Void and superseded passes are kept in clearly named subdirectories.
- `paper/figures/extract_results.py`: extracts every lemma verdict into `paper/figures/data/results_index.json` (TSV views alongside).
- `paper/figures/make_tables.py`: generates every table in the paper from that index.
- `artifact/predictions/`: prediction files, listed below.

## Prediction files
Timestamps are self-recorded by the authors; they are not externally attested. R004–R014 and R016–R018 have per-run files. R003's prediction is the lattice stated as target theorems in the research plan, dated by its file name. R015 was exploratory and had no prediction. Several files carry addenda (e.g. KEYCOMP) with their own timestamps inside.

| File | Recorded timestamp (first in file) | SHA-256 |
|---|---|---|
| R003_RESEARCH_PLAN_20261008_163502.md | 2026-10-08T16:35:02Z (file name) | `3be59b7df94dc9d151335ab0ab26ac963a835579e2fa6039babc3a63b3040ef5` |
| R004_PREDICTIONS.md | 2026-10-10T02:22:24Z | `906dd91c94a6c86bd53775c666b9ecfcde119b4321e2ce9b6658213a31282531` |
| R005_PREDICTIONS.md | 2026-10-09T21:25:30Z | `5b4d3e38af300faea021a00a5b012dc2e3b7688ca79f6868de6b8615adaeac99` |
| R006_PREDICTIONS.md | main part 2026-10-09T02:17Z, recorded only in refine-logs/EXPERIMENT_RESULTS.md (the file states "written before any R006 model existed"); KEYCOMP addendum 2026-10-09T18:07:36Z | `843b32808e832c7cf721bb199a8f242f0e39c6f2c2306ef8a6313317861f4801` |
| R007_PREDICTIONS.md | 2026-10-09T21:28:55Z | `aa418a3be0c546264290ac207c52b1576afecf5e0c4c179365a01fa3ccf3ef5f` |
| R008_PREDICTIONS.md | 2026-10-09T21:41:45Z | `0eae951cb802ab5b60c0cb8f6e91e9ba69658f362127271ee3f8a986b2c74876` |
| R009_PREDICTIONS.md | 2026-10-09T22:01:23Z | `3bdfdd17550417bc407c9329383823f777c16c7f919cabb28082161319f11b99` |
| R010_PREDICTIONS.md | 2026-10-10T02:28:05Z | `80fd184a782754b97149bb70be91f4eedb4ae3b5bc6bbe227765e9b5b6080663` |
| R011_PREDICTIONS.md | 2026-10-10T02:24:29Z | `47a27756539881af3ec29fcb74f0fd3fbd582bf53eecf69a8a2bf0fca1509c20` |
| R012_PREDICTIONS.md | 2026-10-10T02:24:29Z | `c90d9475a5c6868b2ff5c1cb292a8d67f8e28cc748458eb1aa7983c02e2524f4` |
| R013_PREDICTIONS.md (Keycloak replay) | 2026-10-12T03:39:34Z | `cee16b3862bea8f3b2faf1176b4672a9d067450668a1b0d99f76607a0cc9ef3e` |
| R014_PREDICTIONS.md (MCP SDK replay) | 2026-10-23T22:44:26Z | `83508ec50be32f1793a457c507c89afa4d2ed2f98110e7dbf072bed1004b757e` |
| R016_PREDICTIONS.md | 2026-10-10T22:04:15Z | `205d03a9ccda3d7450672702a6c7a6bbc0b686b5bda26312c651b079eb9a5981` |
| R017_PREDICTIONS.md | 2026-10-23T17:34:21Z | `e41f8f805b31687c45a9360ba6176f900f78ec8a022d9e50aa73c6ef6a1faa72` |
| R018_PREDICTIONS.md | 2026-10-23T17:34:21Z | `d2636b59ccbe3c422703f585c05affc7ae4b76e205f6c63f099fd082eb87ab4d` |

## Reproduce
1. Install Tamarin 1.12.0 (official linux64 binary), Maude 3.5.1, and ProVerif 2.05; R017 and R018 ran on a 2026-10-23 reinstall of the same Tamarin and Maude versions. Tamarin logs record their version (1.12.0). ProVerif does not print its version in the R015 logs; version 2.05 is from the build record (compiled from the proverif2.05 source distribution, OCaml 4.14).
2. Run each model per the run scripts in `models/` (`run_lattice.sh`, `run_mcp.sh`, `run_perlemma.sh`, `run_exists.sh`).
3. Run `python3 paper/figures/extract_results.py models/results paper/figures/data/results_index.json`.
4. Run `python3 paper/figures/make_tables.py paper/figures/data/results_index.json paper/tables`.

## ProVerif separation model (R015)
`models/Separation.pvm4` is a template. `models/gen_separation.py` expands it into four concrete files: the two-world equivalence (`choice[repoY, repoX]`) and the reachability queries, each with and without provenance. The logs are in `models/results/R015_proverif/`; each log echoes the expanded process. The files were regenerated on 2026-10-22 from the unchanged template.

| File | SHA-256 |
|---|---|
| models/generated/separation/equiv_chainview.pv | `06d788af0793476c9b9b556b3d11c68fadc51eb9373337a8fb2ea402b6533969` |
| models/generated/separation/equiv_provenance.pv | `cffe7e72636e28cf4955d2d6c07e5b2ea0098c2b20ac13e70512970225a2f315` |
| models/generated/separation/reach_chainview_tracker_said_repoX.pv | `b9591bf0c13b63e67bcecdfcb173e5c8afd8becdc5dde4c4fd22fd8acc2bdd03` |
| models/generated/separation/reach_provenance_tracker_said_repoX.pv | `c5fbf0528a1cfb4d8cd29cf8ccaa591722b4e288e2015f5764957a5f9c6dfb09` |
