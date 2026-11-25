#!/usr/bin/env bash
# Rootless Debian wine 10.0 sarmalayıcı (LD_PRELOAD fakeroot ile)
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
# Debian wine user32.dll -> zlib1.dll bağımlılığı: prefix system32'ye yerleştir
if [ ! -f "$WINEPREFIX/drive_c/windows/system32/zlib1.dll" ] && [ -d "$WINEPREFIX/drive_c/windows/system32" ]; then
  cp "$R/usr/x86_64-w64-mingw32/lib/zlib1.dll" "$WINEPREFIX/drive_c/windows/system32/" 2>/dev/null
fi
exec "$R/usr/lib/wine/wine64" "$@"
