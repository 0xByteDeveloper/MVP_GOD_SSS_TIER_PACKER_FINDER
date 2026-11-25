#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""kor_test_v5.py — vmpdet5 TAM KÖR TEST (isimler rastgele gizlenir).
Skorlama:
  TOP-1 kesin      : birinci aday gerçek sürümse doğru
  TOP-1 eşitlik    : fn0 yapısında 3.8.1/3.8.4 → eşitlik sınıfı doğru sayılır
  ADAY-SET         : gerçek sürüm aday listesinde
Aile bazlı rapor: T32E / T32D / T64E / T64D (kullanıcının 4 ailesi)
"""
import os, sys, json, shutil, subprocess, random, string, re
from collections import defaultdict

VMPDET = sys.argv[1] if len(sys.argv) > 1 else "/home/z/my-project/work/v5/vmpdet5_linux"
CORPUS = "/home/z/my-project/work/corpus5"
ESITLIK = {2, 8}   # Pro 3.8.1 (idx2) ∥ Ult 3.8.4 (idx8) — yalnız fn0
SV2IDX = {"3.10.4":0,"3.8.7":1,"3.8.1":2,"3.9.6":3,"3.0.9":4,"3.2.0":5,
          "3.4.0":6,"3.6.0":7,"3.8.4":8,"3.9.4":9}
AD2IDX = {"Lite 3.10.4":0,"Lite 3.8.7":1,"Professional 3.8.1":2,"Professional 3.9.6":3,
          "Ultimate 3.0.9":4,"Ultimate 3.2.0":5,"Ultimate 3.4.0":6,"Ultimate 3.6.0":7,
          "Ultimate 3.8.4":8,"Ultimate 3.9.4":9}
FN0 = "_fn0"

tmp = "/tmp/kor_v5"
shutil.rmtree(tmp, ignore_errors=True)
os.makedirs(tmp)
rng = random.Random(2027)

hedefler, etiketler = [], []
for sv in sorted(os.listdir(CORPUS)):
    bj = os.path.join(CORPUS, sv, "builds.json")
    if not os.path.exists(bj):
        continue
    d = json.load(open(bj))
    try:
        r = json.load(open(os.path.join(CORPUS, sv, "results.json")))
    except FileNotFoundError:
        r = {}
    for b in d["builds"]:
        if not (os.path.exists(b["cikti"]) and os.path.getsize(b["cikti"]) > 0):
            continue
        if r.get(b["ad"], {}).get("durum") == "ATLANDI":
            continue
        uz = ".exe" if b["aile"] in ("T32E", "T64E") else ".dll"
        rasgele = "h_" + "".join(rng.choice(string.ascii_lowercase) for _ in range(10)) + uz
        shutil.copy(b["cikti"], os.path.join(tmp, rasgele))
        hedefler.append(os.path.join(tmp, rasgele))
        etiketler.append({"ad": b["ad"], "aile": b["aile"], "surum": d["no"],
                          "sv_idx": SV2IDX[d["no"]], "fn0": b["ad"].endswith(FN0)})

json_yol = "/tmp/kor_v5_sonuclar.json"
r = subprocess.run([VMPDET, "--json", json_yol] + hedefler,
                   capture_output=True, text=True, timeout=600)
sonuc = json.load(open(json_yol))

ist = defaultdict(int)
hatalar = []
profil_es = 0
profil_top = 0
for et, sr in zip(etiketler, sonuc):
    aile, gercek, fn0 = et["aile"], et["sv_idx"], et["fn0"]
    ist[(aile, "toplam")] += 1
    adaylar = [AD2IDX[a["surum"]] for a in sr.get("adaylar", []) if a["surum"] in AD2IDX]
    esitlik = sr.get("esitlik_sinifi", False)
    if adaylar:
        if adaylar[0] == gercek:
            ist[(aile, "top1")] += 1
            ist[("TOPLAM", "top1")] += 1
        elif esitlik and gercek in ESITLIK and set(adaylar[:2]) == ESITLIK:
            ist[(aile, "top1_esitlik")] += 1
            ist[("TOPLAM", "top1_esitlik")] += 1
        else:
            hatalar.append((et["ad"], gercek, adaylar, sr.get("guven", "")))
        if gercek in adaylar:
            ist[(aile, "aday_set")] += 1
            ist[("TOPLAM", "aday_set")] += 1
    else:
        hatalar.append((et["ad"], gercek, [], sr.get("guven", "ADAY YOK")))
    ist[("TOPLAM", "toplam")] += 1
    # profil eşleşmesi (yalnız kesin tip eşleşenler)
    pr = sr.get("eslesen_profil", "")
    if pr and "(yakin profil)" not in pr:
        profil_top += 1
        tip_beklenen = et["ad"].split("_", 1)[1]
        if pr in tip_beklenen or tip_beklenen in pr:
            profil_es += 1

print("=" * 72)
print("KÖR TEST v5 — 4 AİLE × 10 SÜRÜM (isimler rastgele gizlendi)")
print("=" * 72)
for aile in ["T32E", "T32D", "T64E", "T64D", "TOPLAM"]:
    t = ist[(aile, "toplam")]
    k = ist[(aile, "top1")]
    e = ist[(aile, "top1_esitlik")]
    a = ist[(aile, "aday_set")]
    print(f"{aile:7s}: {t:3d} build | TOP-1 kesin {k:3d} + eşitlik {e:2d} = "
          f"{(k+e)/t*100:6.2f}% | aday-set {a/t*100:6.2f}%")
print(f"\nProfil (build-tip) eşleşmesi: {profil_es}/{profil_top}")
if hatalar:
    print(f"\nHATALAR ({len(hatalar)}):")
    for ad, gercek, adaylar, guven in hatalar[:20]:
        print(f"  {ad:32s} gerçek={gercek} adaylar={adaylar} ({guven})")
else:
    print("\nHATA YOK — %100")

ozet = {
    "toplam": ist[("TOPLAM", "toplam")],
    "top1_kesin": ist[("TOPLAM", "top1")],
    "top1_esitlik": ist[("TOPLAM", "top1_esitlik")],
    "aday_set": ist[("TOPLAM", "aday_set")],
    "aile_bazli": {a: {k[1]: v for k, v in ist.items() if k[0] == a}
                   for a in ["T32E", "T32D", "T64E", "T64D"]},
    "hata_sayisi": len(hatalar),
}
json.dump(ozet, open("/home/z/my-project/work/v5/kor_test_v5.json", "w"),
          ensure_ascii=False, indent=1)
print("\nrapor: work/v5/kor_test_v5.json")
