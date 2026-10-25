#!/usr/bin/env bash
set -u
srcdir="$1"
outdir="$2"
jobs="${3:-4}"
prefix="${4:-MCP}"
mkdir -p "$outdir"
one() {
  local name="$1" start
  start=$(date +%s.%N)
  timeout 1800 tamarin-prover "$srcdir/${prefix}_$name.spthy" --derivcheck-timeout=0 --prove +RTS -N2 -M6G -RTS > "$outdir/$name.log" 2>&1
  echo "$name exit=$? $(echo "$(date +%s.%N) - $start" | bc)" > "$outdir/$name.time"
}
export -f one
export srcdir outdir prefix
xargs -P "$jobs" -I{} bash -c 'one {}' < "$srcdir/variants.txt"
