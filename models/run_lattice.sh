#!/usr/bin/env bash
set -u
model="$1"
outdir="$2"
extra="${3:-}"
mkdir -p "$outdir"
run_variant() {
  local name="$1"; shift
  local start end
  start=$(date +%s.%N)
  timeout 1800 tamarin-prover "$model" --prove --derivcheck-timeout=0 "$@" +RTS -N2 -RTS > "$outdir/$name.log" 2>&1
  end=$(date +%s.%N)
  echo "$name $(echo "$end - $start" | bc)" > "$outdir/$name.time"
}
export -f run_variant
export model outdir extra
printf '%s\n' \
  "chain|" \
  "chain+reqbind|-D=REQBIND" \
  "chain+capsule|-D=CAPSULE" \
  "chain+prov|-D=PROV" \
  "chain+reqbind+capsule|-D=REQBIND -D=CAPSULE" \
  "chain+reqbind+prov|-D=REQBIND -D=PROV" \
  "chain+capsule+prov|-D=CAPSULE -D=PROV" \
  "chain+reqbind+capsule+prov|-D=REQBIND -D=CAPSULE -D=PROV" \
> "$outdir/variants.txt"
while IFS='|' read -r name flags; do
  run_variant "$name" $flags $extra &
done < "$outdir/variants.txt"
wait
