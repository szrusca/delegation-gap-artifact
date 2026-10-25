#!/usr/bin/env bash
set -u
srcdir="$1"
outdir="$2"
jobs="${3:-6}"
prefix="${4:-WIMSE}"
tmo="${5:-600}"
shift 5
mkdir -p "$outdir"
one() {
  local name="${1%%:*}" lem="${1#*:}" start
  start=$(date +%s)
  timeout "$tmo" tamarin-prover "$srcdir/${prefix}_$name.spthy" --derivcheck-timeout=0 --prove="$lem" +RTS -N1 -M4G -RTS > "$outdir/$name.$lem.log" 2>&1
  local rc=$?
  local v
  v=$(/usr/bin/grep -E "^\s+$lem \((all-traces|exists-trace)\):" "$outdir/$name.$lem.log" | sed 's/^ *//')
  echo "$name $lem rc=$rc $(( $(date +%s) - start ))s ${v:-NONE}" >> "$outdir/summary.txt"
}
export -f one
export srcdir outdir prefix tmo
for v in "$@"; do
  /usr/bin/grep -oE "^lemma [A-Za-z0-9_]+" "$srcdir/${prefix}_$v.spthy" | awk -v n="$v" '{print n":"$2}'
done | xargs -P "$jobs" -I{} bash -c 'one {}'
touch "$outdir/ALL_DONE"
