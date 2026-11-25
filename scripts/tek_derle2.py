#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tek_derle2.py — kanıtlanmış desen: girdi+proje sürüm dizininde, GÖRELİ InputFileName.
Her iş: girdiyi sürüm dizinine kopyala → proje yaz → derle (F9) → çıktıyı hedefe taşı.
TÜM oturum TEK tool çağrısında.
"""
import argparse, json, os, subprocess, time, shutil

KOK = "/home/z/my-project"
TOOLS = f"{KOK}/work/tools"
XDTOOL = f"{TOOLS}/userland/usr/bin/xdotool"
XLIB = f"{TOOLS}/userland/usr/lib/x86_64-linux-gnu:{TOOLS}/wm_root/usr/lib/x86_64-linux-gnu"
WINE_RUN = f"{KOK}/scripts/wine_run.sh"
WINE_SERVER = "/tmp/my-project/work/tools/wine_root/usr/lib/wine/wineserver64"
WINE_SERVER = "/tmp/winedl/root/usr/lib/wine/wineserver64"

class X:
    def __init__(self):
        self.env = dict(os.environ)
        self.env["DISPLAY"] = ":99"
        self.env["LD_LIBRARY_PATH"] = XLIB + ":" + self.env.get("LD_LIBRARY_PATH", "")
    def __call__(self, *a, t=12):
        try:
            r = subprocess.run([XDTOOL, *a], env=self.env, capture_output=True, text=True, timeout=t)
            return r.stdout.strip(), r.stderr.strip(), r.returncode
        except Exception as e:
            return "", str(e), -99

def ana_pencere(x):
    out, _, _ = x("search", "--name", "VMProtect")
    for w in out.splitlines():
        if w.strip().isdigit():
            b, _, _ = x("getwindowname", w)
            if b and ".vmp" in b:
                return int(w)
    return None

def cpu_yuzde(pid, aralik=2.0):
    def oku():
        try:
            d = open(f"/proc/{pid}/stat").read()
            f = d[d.rindex(")") + 2:].split()
            return int(f[11]) + int(f[12])
        except Exception:
            return None
    a = oku()
    if a is None: return None
    time.sleep(aralik)
    b = oku()
    if b is None: return None
    return (b - a) / aralik / os.sysconf("SC_CLK_TCK") * 100

def log(m):
    print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)

def dialog_temizle(x, azami=20):
    t0 = time.time()
    while time.time() - t0 < azami:
        out, _, _ = x("search", "--name", ".")
        stray = []
        for w in out.splitlines():
            if w.strip().isdigit():
                b, _, _ = x("getwindowname", w)
                if b and "IME" not in b and ".vmp" not in b:
                    stray.append(w)
        if not stray:
            return True
        for w in stray:
            x("key", "--clearmodifiers", "Escape")
            time.sleep(0.8)
            x("windowclose", w)
            time.sleep(0.8)
    return False

def derle(x, cikti, azami):
    if os.path.exists(cikti): os.remove(cikti)
    x("key", "--clearmodifiers", "F9")
    t0 = time.time()
    while time.time() - t0 < azami:
        if os.path.exists(cikti) and time.time() - t0 > 15:
            try: s1 = os.path.getsize(cikti)
            except OSError: s1 = None
            time.sleep(4)
            try: s2 = os.path.getsize(cikti)
            except OSError: s2 = None
            time.sleep(3)
            try: s3 = os.path.getsize(cikti)
            except OSError: s3 = None
            if s1 is not None and s1 == s2 == s3 and s3 and s3 > 0:
                time.sleep(4)
                x("key", "--clearmodifiers", "Escape")
                time.sleep(2)
                dialog_temizle(x, 20)
                return s3
        time.sleep(3)
    x("key", "--clearmodifiers", "Escape")
    return -1

def settle(x, wpid, azami=240):
    t0 = time.time()
    while time.time() - t0 < azami:
        wid = ana_pencere(x)
        if wid:
            c = cpu_yuzde(wpid)
            if c is not None and c < 45:
                log(f"settle {time.time()-t0:.0f} sn (cpu={c:.0f}%)")
                return True
        time.sleep(4)
    log("settle ZAMAN AŞIMI")
    return False

def wine_oldur(prefix):
    try:
        subprocess.run([WINE_SERVER, "-k"], env={**os.environ, "WINEPREFIX": prefix},
                       capture_output=True, timeout=30)
    except Exception:
        pass

def proje_uret(girdi_ad, proje_yolu, options):
    icerik = f'''<?xml version="1.0" encoding="UTF-8" ?>
<Document>
    <Protection InputFileName="{girdi_ad}" Options="{options}" RunParameters="">
        <Folders />
        <Procedures />
        <Messages />
    </Protection>
    <DLLBox />
</Document>
'''
    open(proje_yolu, "w", encoding="utf-8").write(icerik)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("isler")
    ap.add_argument("--sure", type=int, default=540)
    ap.add_argument("--prefix", default=f"{TOOLS}/wine_prefix")
    a = ap.parse_args()

    d = json.load(open(a.isler, encoding="utf-8"))
    isler = [i for i in d["isler"] if not (os.path.exists(i["cikti"]) and os.path.getsize(i["cikti"]) > 0)]
    log(f"{len(d['isler'])} iş, {len(isler)} kalan, bütçe {a.sure}s")
    if not isler:
        log("tümü tamam"); return

    xv = subprocess.Popen(["/usr/bin/Xvfb", ":99", "-screen", "0", "1280x900x24"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    ob_env = dict(os.environ); ob_env["DISPLAY"] = ":99"
    ob_env["LD_LIBRARY_PATH"] = XLIB + ":" + ob_env.get("LD_LIBRARY_PATH", "")
    ob = subprocess.Popen([f"{TOOLS}/wm_root/usr/bin/openbox"], env=ob_env,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    x = X()
    t0 = time.time()

    try:
        for no, is_ in enumerate(isler):
            if time.time() - t0 > a.sure:
                log("bütçe doldu"); break
            etiket = is_["etiket"]
            dzn = is_["surum_dizin"]
            proje_yerel = is_["proje"]
            beklenen_cikti = is_["cikti"]
            log(f"İŞ {no+1}/{len(isler)} [{etiket}] proje={os.path.basename(proje_yerel)}")

            wine_env = dict(os.environ)
            wine_env["DISPLAY"] = ":99"
            wine_env["WINEPREFIX"] = a.prefix
            cmd = f'exec {WINE_RUN} ./VMProtect.exe "Z:{proje_yerel}"'
            p = subprocess.Popen(["bash", "-c", cmd],
                                 stdout=open("/tmp/tek_derle2_wine.log","ab"),
                                 stderr=subprocess.STDOUT, env=wine_env, cwd=dzn)
            if not settle(x, p.pid):
                log("  settle edilemedi — sonraki iş")
                wine_oldur(a.prefix); time.sleep(3)
                continue
            s = derle(x, beklenen_cikti, is_.get("azami", 300))
            if s == -1:
                log(f"  ZAMAN AŞIMI: {beklenen_cikti}")
            elif os.path.exists(beklenen_cikti):
                log(f"  OK: {os.path.basename(is_['cikti'])} ({s} bayt)")
            else:
                log(f"  SORUN: boyut={s} ama çıktı yok")
            wine_oldur(a.prefix)
            time.sleep(3)
    finally:
        wine_oldur(a.prefix)
        subprocess.run(["pkill", "-f", "openbox"], capture_output=True)
        subprocess.run(["pkill", "-f", "Xvfb :99"], capture_output=True)
    log("oturum bitti")

if __name__ == "__main__":
    main()
