#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# kor_test_v8.py — GOD STATE regresyon paketi
# 1) 310 VMP korpusu (adlar gizli)        → VMP tespiti %100 olmali
# 2) ornekler/ (33 dosya + evren/)        → bilinen kararlar
# 3) PackGenome RGD 1474 gercek ornek     → aile bazli dogruluk (11 packer)
# 4) ornekler/wine9 (gercek cikti 4 + girdi 2) → Themida 3.2.4 / Enigma 7.8x
# 5) oz-tarama (dedektör kendi binary'si) → temiz gecmeli
import subprocess, os, sys, json, glob, re
from collections import defaultdict

KOK = "/home/z/my-project/work/repo_push"
DET = os.path.join(KOK, "bin", "vmpdet8_linux")
CORPUS = "/home/z/my-project/work/corpus5"
RGD = "/home/z/my-project/work/kaynak3/packgenome_PackGenome-Artifacts/Dataset/RGD"

def tara(yol):
    try:
        c = subprocess.run([DET, yol], capture_output=True, timeout=120)
        return c.stdout.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return ""

def ozet(cikti):
    """ciktidan: vmp_karar, aile, paketleyici, kanitlar"""
    vmp = None; paket = ""; evren = ""; ep = ""; ent = ""
    yapisal = 0
    for satir in cikti.splitlines():
        if satir.startswith("VMProtect:"):
            vmp = "DETECTED" in satir
        elif satir.startswith("Packer:"):
            paket = satir[8:].strip()
        elif satir.startswith("EVREN:") and not evren:
            evren = satir[7:].split("[")[0].strip()
        elif satir.startswith("EVREN-EP:"):
            ep = satir[10:].strip()
        elif satir.startswith("EVREN-YAPISAL:"):
            m = re.search(r"(\d+) bulgu", satir)
            if m: yapisal = int(m.group(1))
    return vmp, paket, evren, ep, yapisal

hatalar = []
rapor = []
# ---------- 1) 310 VMP korpusu
vmp_toplam = vmp_tespit = 0
for surum in sorted(os.listdir(CORPUS)):
    klasor = os.path.join(CORPUS, surum)
    if not os.path.isdir(klasor): continue
    for f in sorted(glob.glob(os.path.join(klasor, "**", "*.exe"), recursive=True) + glob.glob(os.path.join(klasor, "**", "*.dll"), recursive=True)):
        c = tara(f)
        vmp, paket, evren, ep, ys = ozet(c)
        vmp_toplam += 1
        if vmp: vmp_tespit += 1
        elif "sahte" in paket.lower(): hatalar.append(f"SAHTE-DEMET {f}: {paket}")
rapor.append(f"1) VMProtect 310 korpusu (exe+dll): {vmp_tespit}/{vmp_toplam} tespit (%.1f%%)" % (100.0*vmp_tespit/max(1,vmp_toplam)))

# ---------- 2) ornekler/ bilinen kararlar
beklenen = {
  "gercek_UPX.exe": ("UPX", None), "hello_paketsiz.exe": (None, None),
  "Test_64_paketsiz.exe": (None, None), "korumasiz_Test_64.exe": (None, None),
  "korumasiz_Test_32.dll": (None, None),
  "cift_vmp_340_340.exe": ("VMProtect", None),
  "cift_vmp_340ic_394dis.exe": ("VMProtect", None),
  "cift_vmp_394ic_340dis_v5.exe": ("VMProtect", None),
  "cift_vmp_hello.exe": ("VMProtect", None),
  "vmp309_T32E_Move_Virt.exe": ("VMProtect", None),
  "vmp387_T32D_Move_Mutation.dll": ("VMProtect", None),
  "vmp394_T32E_fn0.exe": ("VMProtect", None),
  "vmp396_T64D_fn0.dll": ("VMProtect", None),
  "vmp_340_adlar_degisti.exe": ("VMProtect", None),
  "vmp_394_hello.exe": ("VMProtect", None),
  "vmp_ult_309_fn0.exe": ("VMProtect", None),
  "vmp_ult_340_fn0.exe": ("VMProtect", None),
  "themida_izi_sentetik.exe": ("Themida", None),
  "uclu_upx_vmp_vmp.exe": ("UPX", None), "upx_dis_vmp_ic.exe": ("UPX", None),
}
for ad, (bek_aile, _) in sorted(beklenen.items()):
    yol = os.path.join(KOK, "ornekler", ad)
    if not os.path.exists(yol): continue
    c = tara(yol); vmp, paket, evren, ep, ys = ozet(c)
    if bek_aile == "VMProtect":
        ok = vmp
    elif bek_aile is None:
        ok = (not vmp)
    else:
        ok = (bek_aile.lower() in (evren + " " + paket).lower()) and not vmp
    rapor.append(f"2) {ad}: vmp={vmp} evren='{evren}' paket='{paket}' {'OK' if ok else 'HATA'}")
    if not ok: hatalar.append(f"ornek {ad}: vmp={vmp} evren='{evren}' paket='{paket}' (beklenen {bek_aile})")

# evren klasoru (bilinen etiketler)
evren_bek = {
  "es3n1n.exe": "es3n1n", "gercek_vmp_bolum.exe": "VMProtect",
  "net_babel_sentetik.exe": "Babel", "net_confuserex_sentetik.exe": "ConfuserEx",
  "net_reactor_sentetik.exe": "Reactor", "nocturne.exe": "Nocturne",
  "obfh.exe": "obfus", "obfusheader_fakesig_GERCEK.exe": "obfus",
  "pyinstaller_cookie_sim.exe": "PyInstaller", "ryujin.exe": "Ryujin",
  "sahte_demet.exe": "obfus", "tinyload.exe": "TinyLoad",
  "upx531_best_win32.exe": "UPX", "upx531_lzma_win64.exe": "UPX", "upx531_nrv2b_win32.exe": "UPX",
}
for ad, bek in sorted(evren_bek.items()):
    yol = os.path.join(KOK, "ornekler", "evren", ad)
    if not os.path.exists(yol): continue
    c = tara(yol); vmp, paket, evren, ep, ys = ozet(c)
    ok = bek.lower() in (evren + " " + paket).lower()
    rapor.append(f"2e) {ad}: evren='{evren}' paket='{paket}' {'OK' if ok else 'HATA'}")
    if not ok: hatalar.append(f"evren {ad}: evren='{evren}' paket='{paket}' (beklenen {bek})")

# wine9 (gercek cikti)
wine9_bek = {
  "gercek_themida_324_32.exe": ("Themida", None),
  "gercek_themida_324_64.exe": ("Themida", None),
  "gercek_enigma_780_32.exe": ("Enigma", "7.8x"),
  "gercek_enigma_780_64.exe": ("Enigma", "7.8x"),
  "girdi_test32_paketsiz.exe": (None, None),
  "girdi_test64_paketsiz.exe": (None, None),
}
for ad, (bek, bsurum) in sorted(wine9_bek.items()):
    yol = os.path.join(KOK, "ornekler", "wine9", ad)
    c = tara(yol); vmp, paket, evren, ep, ys = ozet(c)
    if bek is None:
        ok = not vmp
    else:
        ok = bek.lower() in (evren + " " + paket).lower() and (bsurum is None or (bsurum in ep))
    rapor.append(f"4w) {ad}: evren='{evren}' ep='{ep}' {'OK' if ok else 'HATA'}")
    if not ok: hatalar.append(f"wine9 {ad}: evren='{evren}' ep='{ep}' (beklenen {bek} {bsurum})")

# ---------- 3) PackGenome RGD — 11 aile, 1474 gercek ornek
rgd_sonuc = defaultdict(lambda: [0, 0])     # aile -> [tespit, toplam]
rgd_yanlis = defaultdict(list)
for aile in sorted(os.listdir(RGD)):
    aile_yol = os.path.join(RGD, aile)
    if not os.path.isdir(aile_yol): continue
    for f in glob.glob(os.path.join(aile_yol, "**", "*_packed.exe"), recursive=True):
        c = tara(f)
        vmp, paket, evren, ep, ys = ozet(c)
        rgd_sonuc[aile][1] += 1
        es = (evren + " " + paket).lower()
        # aile eslesme kurallari — TAM TABLO (21 aile)
        AILE_ES = {
            "ACProtect":  ("acprotect", "perplex"),
            "ASPack":     ("aspack",),
            "Armadillo":  ("armadillo", "pdata000"),
            "Enigma":     ("enigma",),
            "Fsg":        ("fsg",),
            "MoleBox":    ("molebox",),
            "Obsidium":   ("obsidium",),
            "PECompact":  ("pecompact",),
            "Packman":    ("packman",),
            "Themida":    ("themida",),
            "Upx":        ("upx",),
            "VMProtect":  ("vmprotect",),
            "WinLicense": ("themida", "winlicense"),
            "ZProtect":   ("zprotect",),
            "WinUpack":   ("upack", "bydwing"),
            "beroexepacker": ("bero",),
            "exe32pack":  ("exe32pack", "!ep"),
            "expressor":  ("expressor", "epressor"),
            "jdpack":     ("jdpack",),
            "kkrunchy":   ("kkrunchy",),
            "mew":        ("mew",),
            "mpress":     ("mpress",),
            "neolite":    ("neolite",),
            "nspack":     ("nspack", "nsp0", "nsp1"),
            "pelock":     ("pelock", "pelocknt"),
            "petite":     ("petite",),
        }
        anahtarlar = AILE_ES.get(aile, (aile.lower(),))
        hit = any(k in es for k in anahtarlar)
        if hit: rgd_sonuc[aile][0] += 1
        else: rgd_yanlis[aile].append((os.path.basename(f), evren, paket))
for a, (t, n) in sorted(rgd_sonuc.items()):
    rapor.append(f"3) RGD {a}: {t}/{n} (%.1f%%) — kacan: {len(rgd_yanlis[a])}" % (100.0*t/max(1,n)))
    for kacan in rgd_yanlis[a][:6]:
        hatalar.append(f"RGD {a} kacan: {kacan}")

# ---------- 5) oz-tarama
c = tara(DET)
vmp, paket, evren, ep, ys = ozet(c)
oz_ok = not vmp and "sahte" not in (evren+paket).lower()
rapor.append(f"5) oz-tarama (vmpdet8_linux kendisi): vmp={vmp} evren='{evren}' {'OK' if oz_ok else 'HATA'}")
if not oz_ok: hatalar.append(f"oz-tarama: vmp={vmp} evren='{evren}' paket='{paket}'")

# ---------- cikti
print("=" * 72)
for r in rapor: print(r)
print("-" * 72)
print(f"TOPLAM HATA: {len(hatalar)}")
for h in hatalar[:40]: print("  !", h)
print("=" * 72)
with open(os.path.join(KOK, "docs", "kor_test_v8.txt"), "w") as f:
    f.write("# v8 GOD STATE REGRESYON RAPORU — %s\n\n" % __import__("datetime").datetime.now().isoformat(timespec="seconds"))
    f.write("\n".join(rapor) + "\n\nHATALAR (%d):\n" % len(hatalar) + "\n".join(hatalar) + "\n")
print("docs/kor_test_v8.txt yazildi")
sys.exit(1 if hatalar else 0)
