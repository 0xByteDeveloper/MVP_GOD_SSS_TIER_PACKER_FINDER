#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vmp_batch2.py — zincir_teshis.py'de KANITLANMIŞ akış üzerine kurulu sürücü.
(bash-exec başlatma + settle + F9 + Confirmation Escape + dialog temizliği +
activate--sync + XSendEvent ctrl+o + dialog'a type + Return + başlık bekle)
Kullanım: vmp_batch2.py <builds.json> --display :99 --sure 490 --prefix <p> [--sadece a,b]
"""
import argparse, json, os, subprocess, time

XDTOOL = "/home/z/my-project/work/tools/userland/usr/bin/xdotool"
KOK = "/home/z/my-project"
TOOLS = f"{KOK}/work/tools"
XLIB = f"{TOOLS}/userland/usr/lib/x86_64-linux-gnu:{TOOLS}/wm_root/usr/lib/x86_64-linux-gnu"


class X:
    def __init__(self, display):
        self.env = dict(os.environ)
        self.env["DISPLAY"] = display
        self.env["LD_LIBRARY_PATH"] = XLIB + ":" + self.env.get("LD_LIBRARY_PATH", "")

    def __call__(self, *a, t=10):
        try:
            r = subprocess.run([XDTOOL, *a], env=self.env, capture_output=True, text=True, timeout=t)
            return r.stdout.strip(), r.stderr.strip(), r.returncode
        except Exception as e:
            return "", str(e), -99


def pencereler(x, etiket, log):
    out, _, _ = x("search", "--name", ".")
    l = []
    for w in out.splitlines():
        if w.strip().isdigit():
            b, _, _ = x("getwindowname", w)
            if b and "IME" not in b:
                l.append(f"{w}:{b[:26]}")
    log(f"  pencereler[{etiket}] {' | '.join(l)}")


def ana_pencere(x):
    out, _, _ = x("search", "--name", "VMProtect")
    for w in out.splitlines():
        if w.strip().isdigit():
            b, _, _ = x("getwindowname", w)
            if ".vmp" in b:
                return int(w)
    return None


def genislik(x, w):
    g, _, _ = x("getwindowgeometry", "--shell", str(w))
    for l in g.splitlines():
        if l.startswith("WIDTH="):
            try:
                return int(l.split("=")[1])
            except ValueError:
                return 0
    return 0


def cpu_yuzde(pid, aralik=2.0):
    def oku():
        try:
            d = open(f"/proc/{pid}/stat").read()
            f = d[d.rindex(")") + 2:].split()
            return int(f[11]) + int(f[12])
        except Exception:
            return None
    a = oku()
    if a is None:
        return None
    time.sleep(aralik)
    b = oku()
    if b is None:
        return None
    return (b - a) / aralik / os.sysconf("SC_CLK_TCK") * 100


class Surucu:
    def __init__(self, a):
        self.a = a
        self.x = X(a.display)
        self.d = json.load(open(a.builds, encoding="utf-8"))
        self.surum = self.d["surum"]
        self.prefix = a.prefix
        self.kok = os.path.dirname(a.builds)
        self.log_yolu = f"{self.kok}/surucu.log"
        self.sonuc_yolu = f"{self.kok}/results.json"
        self.sonuclar = json.load(open(self.sonuc_yolu, encoding="utf-8")) if os.path.exists(self.sonuc_yolu) else {}
        self.wpid = None
        self.t0 = time.time()
        self.wine_env = dict(os.environ)
        self.wine_env["DISPLAY"] = a.display
        self.wine_env["WINEPREFIX"] = a.prefix

    def log(self, m):
        s = f"[{time.strftime('%H:%M:%S')}] {m}"
        print(s, flush=True)
        with open(self.log_yolu, "a", encoding="utf-8") as f:
            f.write(s + "\n")

    def kaydet(self):
        json.dump(self.sonuclar, open(self.sonuc_yolu, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    def bitti_mi(self):
        return time.time() - self.t0 > self.a.sure

    def bash_baslat(self, proje):
        """zincir_teshis'te KANITLANMIŞ: bash -c exec + ./VMProtect.exe göreceli."""
        d = self.d["dizin"]
        cmd = f'exec {KOK}/scripts/wine_run.sh ./VMProtect.exe "Z:{proje}"'
        p = subprocess.Popen(["bash", "-c", cmd],
                             stdout=open(f"/tmp/wine_{self.surum}.log", "ab"),
                             stderr=subprocess.STDOUT, env=self.wine_env, cwd=d)
        self.wpid = p.pid
        return p.pid

    def kapat(self):
        try:
            subprocess.run([f"{TOOLS}/wine_root/usr/lib/wine/wineserver64", "-k"],
                           env={**os.environ, "WINEPREFIX": self.prefix}, capture_output=True, timeout=30)
        except Exception:
            pass
        self.wpid = None

    def settle(self, azami=600):
        t0 = time.time()
        while time.time() - t0 < azami:
            if self.bitti_mi():
                return False
            wid = ana_pencere(self.x)
            if wid:
                c = cpu_yuzde(self.wpid)
                if c is not None and c < 45:
                    self.log(f"settle {time.time()-t0:.0f} sn (cpu={c:.0f}%)")
                    return True
            time.sleep(4)
        self.log(f"settle ZAMAN AŞIMI ({azami} sn)")
        return False

    def derle(self, cikti, azami):
        """F9 → minimum 15 sn derleme → stabil çıktı (çift doğrulama) → Escape."""
        try:
            if os.path.exists(cikti):
                os.remove(cikti)
        except OSError:
            pass
        self.x("key", "--clearmodifiers", "F9")
        t0 = time.time()
        while time.time() - t0 < azami:
            if self.bitti_mi():
                return None
            # büyük derlemeler başlangıçta orijinal boyutla kopyalanır — erken yakalama YASAK
            if os.path.exists(cikti) and time.time() - t0 > 15:
                try:
                    s1 = os.path.getsize(cikti)
                except OSError:
                    s1 = None
                time.sleep(4)
                try:
                    s2 = os.path.getsize(cikti)
                except OSError:
                    s2 = None
                time.sleep(3)
                try:
                    s3 = os.path.getsize(cikti)
                except OSError:
                    s3 = None
                if s1 is not None and s1 == s2 == s3 and s3 and s3 > 0:
                    time.sleep(4)
                    self.x("key", "--clearmodifiers", "Escape")  # Confirmation
                    time.sleep(2)
                    self.dialog_temizle(20)
                    return s3
            time.sleep(3)
        self.x("key", "--clearmodifiers", "Escape")
        return -1

    def dialog_temizle(self, azami):
        """Ana pencere (.vmp'li) dışındakileri Escape/close/kill ile kapat."""
        t0 = time.time()
        while time.time() - t0 < azami:
            out, _, _ = self.x("search", "--name", ".")
            stray = []
            for w in out.splitlines():
                if w.strip().isdigit():
                    b, _, _ = self.x("getwindowname", w)
                    if b and "IME" not in b and ".vmp" not in b:
                        stray.append(w)
            if not stray:
                return True
            for w in stray:
                self.x("key", "--clearmodifiers", "Escape")
                time.sleep(0.8)
                self.x("windowclose", w)   # WM_DELETE — güvenli
                time.sleep(0.8)
                # windowkill YOK — X UnmapWindow BadWindow → VMProtect crash (kanıtlandı)
        return False

    def proje_ac(self, proje):
        """KANITLANMIŞ zincir_teshis akışı: activate--sync + XSendEvent ctrl+o
        → yeni dialog (set-farkı, genişlik>300) → activate + type + Return → başlık."""
        ad = os.path.basename(proje)
        for deneme in (1, 2, 3):
            if self.bitti_mi():
                return False
            self.dialog_temizle(12)
            wid = ana_pencere(self.x)
            if not wid:
                self.log("ana pencere yok!")
                return False
            once_out, _, _ = self.x("search", "--name", ".")
            once = set(w for w in once_out.splitlines() if w.strip().isdigit())
            self.x("windowactivate", "--sync", str(wid), t=5)
            time.sleep(1.0)
            self.x("key", "--window", str(wid), "--clearmodifiers", "ctrl+o")
            # yeni dialog bekle
            acik = None
            t0 = time.time()
            while time.time() - t0 < 15:
                if self.bitti_mi():
                    return False
                time.sleep(1.2)
                out, _, _ = self.x("search", "--name", ".")
                for w in out.splitlines():
                    if w.strip().isdigit() and w not in once and w != str(wid):
                        b, _, _ = self.x("getwindowname", w)
                        if not b or "IME" in b:
                            continue
                        if genislik(self.x, w) > 300:
                            acik = int(w)
                            break
                if acik:
                    break
            if acik is None:
                pencereler(self.x, f"open-yok-d{deneme}", self.log)
                self.x("key", "--clearmodifiers", "Escape")
                time.sleep(2)
                continue
            # dialog'a yaz
            self.x("windowactivate", "--sync", str(acik), t=5)
            time.sleep(1.0)
            self.x("type", "--clearmodifiers", "--delay", "25", "Z:" + proje.replace("/", "\\"))
            time.sleep(1.2)
            self.x("key", "--clearmodifiers", "Return")
            # başlık değişimi bekle — ProgressDialog'a SABRET (Escape İPTAL EDER!)
            t0 = time.time()
            while time.time() - t0 < 120:
                if self.bitti_mi():
                    return False
                nw = ana_pencere(self.x)
                if nw and ad in (self.x("getwindowname", str(nw))[0]):
                    time.sleep(5)  # ProgressDialog kapanış payı
                    return True
                time.sleep(3)
            self.log(f"proje yüklenemedi ({ad}) d{deneme}")
            self.dialog_temizle(8)
            self.x("key", "--clearmodifiers", "Escape")
            time.sleep(2)
        return False

    def calistir(self):
        builds = self.d["builds"]
        if self.a.sadece:
            sec = set(self.a.sadece.split(","))
            builds = [b for b in builds if b["ad"] in sec]
        kalan = [b for b in builds if not (self.sonuclar.get(b["ad"], {}).get("durum") == "OK" and
                 os.path.exists(b["cikti"]) and os.path.getsize(b["cikti"]) > 0)]
        self.log(f"{self.surum}: {len(builds)} build, {len(kalan)} kalan")
        if not kalan:
            self.log("tümü tamam")
            return
        ilk = kalan[0]
        self.log(f"başlat: {os.path.basename(ilk['proje'])}")
        self.bash_baslat(ilk["proje"])
        if not self.settle():
            self.log("settle edilemedi — çıkış")
            self.kapat()
            return
        for b in kalan:
            if self.bitti_mi():
                self.log("zaman bütçesi doldu")
                break
            ad = b["ad"]
            if b is not ilk:
                if not self.proje_ac(b["proje"]):
                    # KURTARMA: zincir koptu → VMProtect'i proje ile yeniden başlat
                    self.log(f"{ad}: zincir koptu — yeniden başlatma")
                    self.kapat()
                    time.sleep(3)
                    if self.bitti_mi():
                        self.log("bütçe doldu (restart öncesi)")
                        break
                    self.bash_baslat(b["proje"])
                    if not self.settle():
                        self.log("restart settle edilemedi — çıkış")
                        self.kapat()
                        return
                    self.log(f"{ad}: restart OK")
                    if self.derle_ve_kaydet(b) is None:
                        break
                    continue
            if self.derle_ve_kaydet(b) is None:
                break
        self.kapat()
        self.log("sürücü bitti")

    def derle_ve_kaydet(self, b):
        ad = b["ad"]
        azami = 1000 if "HEPSI" in ad else 300
        t0 = time.time()
        s = self.derle(b["cikti"], azami)
        if s is None:
            self.log(f"{ad}: bütçe doldu (yarım)")
            return None
        if s == -1:
            self.log(f"{ad}: ZAMAN AŞIMI")
            self.sonuclar[ad] = {"durum": "ZAMAN_ASIMI"}
        else:
            self.log(f"{ad}: OK ({s} bayt, {time.time()-t0:.0f} sn)")
            self.sonuclar[ad] = {"durum": "OK", "boyut": s, "sure_sn": round(time.time()-t0)}
        self.kaydet()
        return s


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("builds")
    ap.add_argument("--display", default=":99")
    ap.add_argument("--prefix", required=True)
    ap.add_argument("--sure", type=int, default=490)
    ap.add_argument("--sadece", default="")
    a = ap.parse_args()
    Surucu(a).calistir()
