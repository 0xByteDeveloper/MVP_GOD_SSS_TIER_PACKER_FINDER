#!/usr/bin/env bash
# wine_run.sh <exe> [args...] — mimari farkındalıklı wine sarmalayıcı
# 32-bit PE → wine32 (qemu-user kit), 64-bit PE → wine64 (fakeroot ağacı)
EXE="$1"
# Z:\ windows yolunu unix'e cevir (koklama için)
SNIFF="${EXE#Z:}"; SNIFF="${SNIFF//\\//}"
MACHINE=""
if [ -f "$SNIFF" ]; then
  # PE makine tipini oku (e_lfanew + 4)
  OFF=$(od -An -tu4 -j60 -N4 --endian=little "$SNIFF" 2>/dev/null | tr -d ' ')
  if [ -n "$OFF" ] && [ "$OFF" -lt 1000000 ] 2>/dev/null; then
    M=$(od -An -tx2 -j$((OFF+4)) -N2 --endian=little "$SNIFF" 2>/dev/null | tr -d ' ')
    MACHINE="$M"
  fi
fi
if [ "$MACHINE" = "014c" ]; then
  # 32-bit PE → wine32 kit'i
  export PATH="$HOME/.local/bin:$PATH"
  export WINEPREFIX="${WINEPREFIX32:-$HOME/.wine32}"
  exec wine32 "$@"
fi
# 64-bit (varsayılan): fakeroot wine64
TOOLS=/home/z/my-project/work/tools
R="$TOOLS/wine_root"
export WINEPREFIX="${WINEPREFIX:-$TOOLS/wine_prefix}"
export WINEDEBUG="${WINEDEBUG:--all}"
export WINEDLLOVERRIDES="${WINEDLLOVERRIDES:-mscoree,mshtml=}"
export LD_LIBRARY_PATH="$R/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export WINEDLLDIR="$R/usr/lib/x86_64-linux-gnu/wine/x86_64-unix"
export WINEDLLPATH="$R/usr/lib/x86_64-linux-gnu/wine/x86_64-windows"
export LD_PRELOAD="$TOOLS/wine_fakeroot.so"
mkdir -p "$WINEPREFIX"
if [ ! -f "$WINEPREFIX/drive_c/windows/system32/zlib1.dll" ] && [ -d "$WINEPREFIX/drive_c/windows/system32" ]; then
  cp "$R/usr/x86_64-w64-mingw32/lib/zlib1.dll" "$WINEPREFIX/drive_c/windows/system32/" 2>/dev/null
fi
exec "$R/usr/lib/wine/wine64" "$@"
