#!/usr/bin/env bash
# parca5.sh — çift kanal üretim parçası (tek tool çağrısı). Otomatik devam eder.
set -u
SURE="${1:-540}"
cd /home/z/my-project/work/corpus5
C=/home/z/my-project/scripts/kanal5.sh
W=/home/z/my-project/work/tools
(bash $C :98 $W/wine_prefix "$SURE" \
  "VMProtect_Ultimate_3.9.4/builds.json" \
  "VMProtect_Professional_3.8.1/builds.json" \
  "VMProtect_Lite_3.10.4/builds.json" \
  "VMProtect_Ultimate_3.6.0/builds.json" \
  "VMProtect_Ultimate_3.2.0/builds.json" > /tmp/kanalA.log 2>&1 &)
(bash $C :99 $W/wine_prefix_b "$SURE" \
  "VMProtect_Ultimate_3.8.4/builds.json" \
  "VMProtect_Professional_3.9.6/builds.json" \
  "VMProtect_Lite_3.8.7/builds.json" \
  "VMProtect_Ultimate_3.4.0/builds.json" \
  "VMProtect_Ultimate_3.0.9/builds.json" > /tmp/kanalB.log 2>&1 &)
BEKLE=$((SURE + 15))
sleep "$BEKLE"
echo "=== A (son 5):"; tail -5 /tmp/kanalA.log
echo "=== B (son 5):"; tail -5 /tmp/kanalB.log
echo "=== İLERLEME:"
python3 - << 'PYEOF'
import os, json
KOK = "/home/z/my-project/work/corpus5"
toplam = ok = 0
for sv in sorted(os.listdir(KOK)):
    bj = f"{KOK}/{sv}/builds.json"
    if not os.path.exists(bj): continue
    d = json.load(open(bj))
    for b in d["builds"]:
        toplam += 1
        if os.path.exists(b["cikti"]) and os.path.getsize(b["cikti"]) > 0:
            ok += 1
print(f"corpus5: {ok}/{toplam} build tamam")
PYEOF
