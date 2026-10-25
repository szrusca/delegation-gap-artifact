#!/usr/bin/env bash
set -u
srcdir="$1"
outdir="$2"
jobs="${3:-4}"
bound="${4:-20}"
mkdir -p "$outdir"
run_one() {
  local name="$1" start
  start=$(date +%s.%N)
  timeout 3600 tamarin-prover "$srcdir/RFC8693_$name.spthy" --derivcheck-timeout=0 \
    --prove=issued_* --prove=first_actor* --prove=later_actor* --prove=AUTH_* --prove=NOESC_* --prove=ATTR_* --prove=TASK_* \
    +RTS -N2 -M6G -RTS > "$outdir/$name.safety.log" 2>&1
  echo "$name safety exit=$? $(echo "$(date +%s.%N) - $start" | bc)" > "$outdir/$name.safety.time"
}
export -f run_one
export srcdir outdir bound
xargs -P "$jobs" -I{} bash -c 'run_one {}' < "$srcdir/variants.txt"
