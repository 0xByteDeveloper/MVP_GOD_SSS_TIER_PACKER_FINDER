#!/usr/bin/env python3
# kor_test_v6.py — 310-dosyali TAM KOR REGRESYON TESTI (v6 evrensel motor ile)
# corpus5 dizin yapisindan direkt hedef listesi olusturur (builds.json gerekmez)
import os, sys, json, shutil, subprocess, random, string, re
from collections import defaultdict

VMPDET = sys.argv[1] if len(sys.argv) > 1 else "/tmp/vmpdet6_test"
CORPUS = "/home/z/my-project/work/corpus5"
ESITLIK = {2, 8}   # Pro 3.8.1 (idx2) ∥ Ult 3.8.4 (idx8) — yalnız fn0
SV2IDX = {"3.10.4":0,"3.8.7":1,"3.8.1":2,"3.9.6":3,"3.0.9":4,"3.2.0":5,
          "3.4.0":6,"3.6.0":7,"3.8.4":8,"3.9.4":9}
AD2IDX = {"Lite 3.10.4":0,"Lite 3.8.7":1,"Professional 3.8.1":2,"Professional 3.9.6":3,
          "Ultimate 3.0.9":4,"Ultimate 3.2.0":5,"Ultimate 3.4.0":6,"Ultimate 3.6.0":7,
          "Ultimate 3.8.4":8,"Ultimate 3.9.4":9}

tmp = "/tmp/kor_v6"
shutil.rmtree(tmp, ignore_errors=True)
os.makedirs(tmp)
rng = random.Random(2027)

hedefler, etiketler = [], []
for svdir in sorted(os.listdir(CORPUS)):
    tam = os.path.join(CORPUS, svdir)
    if not os.path.isdir(tam): continue
    m = re.search(r"(\d+\.\d+\.\d+)", svdir)
    surum = m.group(1) if m else None
    if surum is None or surum not in SV2IDX:
        continue
    try: r = json.load(open(os.path.join(tam, "results.json")))
    except FileNotFoundError: r = {}
    for fn in sorted(os.listdir(tam)):
        if not (fn.endswith(".exe") or fn.endswith(".dll")): continue
        ad = fn.rsplit(".", 1)[0].replace(".vmp", "")
        if r.get(ad, {}).get("durum") == "ATLANDI": continue
        uz = ".exe" if fn.endswith(".exe") else ".dll"
        rasgele = "h_" + "".join(rng.choice(string.ascii_lowercase) for _ in range(10)) + uz
        shutil.copy(os.path.join(tam, fn), os.path.join(tmp, rasgele))
        hedefler.append(os.path.join(tmp, rasgele))
        etiketler.append({"ad": ad, "aile": ad.split("_")[0], "surum": surum,
                          "sv_idx": SV2IDX[surum], "fn0": ad.endswith("_fn0")})

print(f"hedef: {len(hedefler)} dosya")
json_yol = "/tmp/kor_v6_sonuclar.json"
r = subprocess.run([VMPDET, "--json", json_yol] + hedefler,
                   capture_output=True, text=True, timeout=560)
if r.returncode != 0:
    print("HATA rc:", r.returncode); print(r.stderr[-800:]); sys.exit(1)
sonuclar = json.load(open(json_yol))
assert len(sonuclar) == len(hedefler)

top1, top1_esit, aday_set, vmp_kac = 0, 0, 0, 0
aile_dogru = defaultdict(int); aile_toplam = defaultdict(int)
hatalar = []
for i, (s, et) in enumerate(zip(sonuclar, etiketler)):
    if not s["vmp"]:
        hatalar.append((et["ad"], et["surum"], "VMP tespit EDILEMEDI", s.get("paketleyici","")))
        continue
    vmp_kac += 1
    adaylar = s.get("adaylar", [])
    if not adaylar:
        hatalar.append((et["ad"], et["surum"], "aday yok", "")); continue
    def ady_idx(a):
        ad = a["surum"] if isinstance(a, dict) else str(a)
        return AD2IDX.get(ad, -1)
    if s.get("esitlik_sinifi") and et["fn0"] and et["sv_idx"] in ESITLIK:
        top1_esit += 1; top1 += 1
    elif ady_idx(adaylar[0]) == et["sv_idx"]:
        top1 += 1
    elif any(ady_idx(a) == et["sv_idx"] for a in adaylar):
        aday_set += 1
        hatalar.append((et["ad"], et["surum"], "ADAY-SET (top1 yanlis)", str(adaylar[0])[:60]))
    else:
        hatalar.append((et["ad"], et["surum"], "YANLIS top1", str(adaylar[0])[:60]))
    # aile kontrolu (T32E/T32D/T64E/T64D) — arch alanindan
    aile_toplam[et["aile"]] += 1
    if s.get("aile", "?") != "?" : aile_dogru[et["aile"]] += 1

n = len(hedefler)
print(f"\nSONUC: {n} dosya | VMP tespit: {vmp_kac}/{n}")
print(f"  TOP-1 kesin/esitlik: {top1}/{n} ({100*top1/n:.1f}%)")
print(f"  + ADAY-SET: {(top1+aday_set)}/{n} ({100*(top1+aday_set)/n:.1f}%)")
print(f"  hatalar: {len(hatalar)}")
for h in hatalar[:12]: print("   ", h)
json.dump({"hatalar": hatalar, "top1": top1, "n": n}, open("/tmp/kor_v6_ozet.json","w"), indent=1)
