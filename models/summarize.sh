#!/usr/bin/env bash
for f in "$1"/*.log; do
  echo "== $(basename "$f" .log) ($(cut -d' ' -f2 "${f%.log}.time" | cut -c1-5)s, wf-fail=$(/usr/bin/grep -c 'wellformedness checks failed' "$f"))"
  /usr/bin/grep -E "^\s+\S+ \((all-traces|exists-trace)\):" "$f" | sed -E 's/ \((all-traces|exists-trace)\)//; s/ - found trace//; s/ - no trace found//'
done
