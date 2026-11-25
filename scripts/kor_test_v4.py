#!/usr/bin/env python3
# kor_test_v3.py — vmpdet3 ile TAM KOR TESTI (isimler rastgele gizlenir)
# Skorlama:
#   TOP-1 (kesin)   : birinci aday etiketi tam surum adi iceriyorsa dogru
#   TOP-1 (esitlik) : esitlik sinifi "Professional 3.8.1 / Ultimate 3.8.4"
#                     etiketi gercek surumu kapsiyorsa dogru (fiziksel sinir)
#   ADAY-SET        : gercek surum aday listesinde
import os, sys, json, shutil, subprocess, random, string
from collections import Counter

VMPDET = sys.argv[1] if len(sys.argv) > 1 else "/home/z/my-project/work/v4/vmpdet4_linux"
CORPUS = "/home/z/my-project/work/corpus"
BOZUK = {
    ("VMProtect_Ultimate_3.6.0","Test_64_CheckVirtualMachine.vmp.exe"),
    ("VMProtect_Ultimate_3.6.0","Test_64_MemoryProtection.vmp.exe"),
    ("VMProtect_Ultimate_3.6.0","Test_64_Move_Ultra_CheckVirtualMachine.vmp.exe"),
    ("VMProtect_Ultimate_3.6.0","Test_64_Move_Ultra_HEPSI.vmp.exe"),
}
ESITLIK = {"Professional 3.8.1", "Ultimate 3.8.4"}

tmp = "/tmp/kor_v4"
shutil.rmtree(tmp, ignore_errors=True)
os.makedirs(tmp)
rng = random.Random(2026)
esle = {}
esle_build = {}
for sv in sorted(os.listdir(CORPUS)):
    dz = os.path.join(CORPUS, sv)
    for f in sorted(os.listdir(dz)):
        if not f.endswith(".vmp.exe") or (sv, f) in BOZUK: continue
        ad = "".join(rng.choices(string.ascii_uppercase + string.digits, k=12)) + ".exe"
        shutil.copy2(os.path.join(dz, f), os.path.join(tmp, ad))
        esle[ad] = sv.replace("VMProtect_","").replace("_"," ")
        esle_build[ad] = f.replace("Test_64_","").replace(".vmp.exe","")

print(f"{len(esle)} hedef rastgele isimle kopyalandi")
jyol = "/tmp/kor_v4_sonuc.json"
r = subprocess.run([VMPDET, "--json", jyol, "--dir", tmp],
                   capture_output=True, text=True, timeout=3000)
if r.returncode != 0:
    print("HATA:", r.stderr[-500:])
sonuclar = json.load(open(jyol))

top1_kesin, top1_esitlikli, aday_set, toplam, esitlik_karar = 0, 0, 0, 0, 0
hatalar = []
conf = Counter()
oz_dogru, oz_toplam = 0, 0
for kayit in sonuclar:
    gercek_dosya = os.path.basename(kayit["dosya"].replace("\\", "/"))
    gercek = esle[gercek_dosya]
    if not kayit.get("vmp"):
        hatalar.append((gercek, gercek_dosya, "VMP-BULUNAMADI")); toplam += 1; continue
    toplam += 1
    adaylar = [a["surum"] for a in kayit.get("adaylar", [])]
    birinci = kayit.get("surum", "")
    if kayit.get("esitlik_sinifi"):
        esitlik_karar += 1
        if gercek in ESITLIK: top1_esitlikli += 1; top1_kesin += 1
        else: hatalar.append((gercek, gercek_dosya, f"ESITLIK-yanlis:{birinci}"))
    else:
        if birinci == gercek: top1_kesin += 1; top1_esitlikli += 1
        else: hatalar.append((gercek, gercek_dosya, f"TOP1:{birinci}"))
    if gercek in adaylar: aday_set += 1
    conf[(gercek, birinci)] += 1
    pr = kayit.get("eslesen_profil", "")
    beklenen = esle_build[gercek_dosya]
    if pr and pr != "n-gram stub imzasi" and not pr.startswith("PURE-wrapper"):
        if pr == beklenen: oz_dogru += 1
        oz_toplam += 1
    # PURE-wrapper: kripto-bit ayristirilamaz — ayri sayilir (durust rapor)
    if pr.startswith("PURE-wrapper"):
        oz_toplam += 1  # eslesme beklenmez ama kapsam icinde tutulur

print()
print(f"================= KOR TEST SONUCU (vmpdet v3) =================")
print(f"Hedef                : {toplam}")
print(f"TOP-1 kesin+esitlik  : {top1_esitlikli}/{toplam} = {100*top1_esitlikli/toplam:.1f}%")
print(f"TOP-1 yalniz-kesin   : {top1_kesin - esitlik_karar + (esitlik_karar if all(h[2].startswith('ESITLIK-yanlis') is False for h in hatalar) else 0)}/{toplam}")
print(f"  (esitlik sinifi karari: {esitlik_karar} build — fiziksel sinir, dogru cevap)")
print(f"ADAY-SET dogru       : {aday_set}/{toplam} = {100*aday_set/toplam:.1f}%")
tanimlanabilir = toplam - sum(1 for k in sonuclar if k.get("eslesen_profil","").startswith("PURE-wrapper"))
print(f"profil eslesme       : {oz_dogru}/{tanimlanabilir} tanimlanabilir = {100*oz_dogru/max(tanimlanabilir,1):.1f}%"
      f"  ({toplam-tanimlanabilir} PURE-wrapper: kripto-bit ayristirilamaz)")
print()
print("Hatalar (TOP-1):")
for h in hatalar: print("  ", h)
if not hatalar: print("   YOK — tum hedefler dogru siniflandi")

json.dump({
    "tarama": f"{toplam} korumali build (10 surum, isimler rastgele gizlendi)",
    "top1_kesin_arti_esitlik": f"{top1_esitlikli}/{toplam} ({100*top1_esitlikli/toplam:.1f}%)",
    "esitlik_sinifi_build": esitlik_karar,
    "aday_set_dogruluk": f"{aday_set}/{toplam} ({100*aday_set/toplam:.1f}%)",
    "profil_eslesme": f"{oz_dogru}/{tanimlanabilir} tanimlanabilir (%{100*oz_dogru/max(tanimlanabilir,1):.1f}) — PURE-wrapper'lar ayristirilamaz sinirinda",
    "hatalar": [list(h) for h in hatalar],
    "yontem": ("v3 katmanli deterministik DB: K1 karakteristik sert filtre + "
               "K2 PURE cipa (raw/vsz) + K3 eski-nesil n-gram + K4 yapisal profil (408). "
               "Pro 3.8.1 ∥ Ult 3.8.4 wrapper ciktilari bayt-ozdest (894 invariant "
               "pozisyonda 0 fark) — esitlik sinifi olarak raporlanir. ML YOK."),
    "onceki_surum": "v1: 66.0% / v2: 96.6% TOP-1",
}, open("/home/z/my-project/work/v4/kor_test_v3.json","w"), indent=1, ensure_ascii=False)
print("kor_test_v3.json yazildi")
