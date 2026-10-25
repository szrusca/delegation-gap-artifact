#!/usr/bin/env bash
set -u
srcdir="$1"
outdir="$2"
jobs="$3"
boundarg="$4"
mkdir -p "$outdir"
one() {
  local v="$1" l="$2" s
  s=$(date +%s)
  timeout 1200 tamarin-prover "$srcdir/RFC8693_$v.spthy" --derivcheck-timeout=0 $boundarg --prove="$l" +RTS -N1 -M5G -RTS > "$outdir/$v.$l.log" 2>&1
  echo "$v $l exit=$? $(( $(date +%s)-s ))s $(/usr/bin/grep -E "^\s+$l \(" "$outdir/$v.$l.log" | sed -E 's/.*\): //')" > "$outdir/$v.$l.res"
}
export -f one
export srcdir outdir boundarg
while read -r v; do
  for l in ${EXIST_LEMMAS:-executable_static_task_conformant_two_hops executable_dynamic_task_conformant_two_hops witness_splice_chain_names_undelegated_hop witness_act_stripping_logs_human}; do
    echo "$v $l"
  done
done < "$srcdir/variants.txt" | xargs -P "$jobs" -L1 bash -c 'one "$0" "$1"'
