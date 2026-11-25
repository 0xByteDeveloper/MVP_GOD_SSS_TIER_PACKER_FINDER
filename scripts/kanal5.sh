#!/usr/bin/env bash
# kanal5.sh <display> <prefix> <sure_sn> <builds1.json> [builds2.json ...]
# Sürücü zinciri: her builds.json için vmp_batch2.py çalıştır (kalan bütçeyle),
# bütçe dolunca çık. Tek tool çağrısında çok sürüm işler.
set -u
DISP="$1"; PREFIX="$2"; BUTCE="$3"; shift 3
T0=$(date +%s)
source /home/z/my-project/scripts/ortam.sh
NUM=$(echo "$DISP" | tr -d ':')
if ! pgrep -f "Xvfb $DISP " > /dev/null 2>&1; then
  Xvfb "$DISP" -screen 0 1600x1000x24 > "/tmp/xvfb_$NUM.log" 2>&1 &
  sleep 2
fi
if [ ! -f "/tmp/openbox_$NUM.pid" ] || ! kill -0 "$(cat "/tmp/openbox_$NUM.pid" 2>/dev/null)" 2>/dev/null; then
  env DISPLAY="$DISP" LD_LIBRARY_PATH="$XLIB" \
      XDG_CONFIG_DIRS="$TOOLS/wm_root/etc/xdg" \
      XDG_DATA_DIRS="$TOOLS/wm_root/usr/share" \
      "$TOOLS/wm_root/usr/bin/openbox" > "/tmp/ob_$NUM.log" 2>&1 &
  echo $! > "/tmp/openbox_$NUM.pid"
  sleep 2
fi
for B in "$@"; do
  KALAN=$(( BUTCE - ($(date +%s) - T0) ))
  if [ "$KALAN" -lt 90 ]; then echo "[kanal5] bütçe doldu (kalan=$KALAN)"; exit 0; fi
  echo "[kanal5] $B — kalan $KALAN sn"
  python3 /home/z/my-project/scripts/vmp_batch2.py "$B" --display "$DISP" --sure "$KALAN" --prefix "$PREFIX" || true
  # kanal arası wineserver temizliği (aynı prefix'i kullanan yoksa gereksiz ama güvenli)
done
echo "[kanal5] zincir bitti: $*"
