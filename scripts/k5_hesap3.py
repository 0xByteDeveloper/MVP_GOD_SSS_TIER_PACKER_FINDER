#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""k5_hesap3.py — K5 v3: SIKLIK bazlı motor imza seti (K3 metodolojisinin
tüm sürümlere genellenmesi):
  - gram: 24 bayt (K3 ile aynı), koruyucu bölüm(ler)in ilk 64KB'ı
  - imza seti: sürümün build'lerinin >=%60'ında görünen gram'lar
  - benzersizlik: başka sürümün HİÇBİR build'inde görünmeyen
  - hedef puanı: |hedef ∩ imza| / |imza|
Çıktı: work/v4/k5_db3.json
"""
import os, json, struct
from collections import defaultdict

KOK = "/home/z/my-project"
CORPUS = f"{KOK}/work/corpus"
GR = 24
SINIR = 65536
ESIK = 0.60
MAKS = 512

db = open(f"{KOK}/work/v4/detektor_db.h", encoding="utf-8").read()
import re
SURUMLER = re.findall(r'"([^"]+)"', re.search(r"SURUM\[\]\s*=\s*\{(.*?)\};", db, re.S).group(1))

STANDART = {".text",".rdata",".data",".pdata",".tls",".rsrc",".reloc",".edata",
            ".idata",".bss",".gfids",".qtmetad","_RDATA",".xdata",".CRT",".didat",
            ".xc",".clr",".sdata",".00cfg",".textbss",".eh_fram",".eh_frame",
            ".gcc_except_table",".UPX0",".UPX1",".UPX2"}
ONEK = (".rdata$",".text$",".data$",".CRT$")

def koruyucu_veri(veri):
    """tüm koruyucu bölümlerin verisi (her biri ilk 64KB, toplam 128KB sınırı)"""
    e = struct.unpack_from('<I', veri, 0x3C)[0]
    n = struct.unpack_from('<H', veri, e+6)[0]
    opt = struct.unpack_from('<H', veri, e+20)[0]
    bt = e + 24 + opt
    parca = []
    toplam = 0
    for i in range(n):
        o = bt + 40*i
        ad = veri[o:o+8].rstrip(b'\0').decode('ascii','replace')
        vsz, va, rsz, ro = struct.unpack_from('<IIII', veri, o+8)
        if (ad not in STANDART and not any(ad.startswith(p) for p in ONEK)) and rsz > 512:
            al = min(rsz, SINIR, 131072 - toplam)
            if al > 0:
                parca.append(veri[ro:ro+al]); toplam += al
    return b"".join(parca)

def gramlar(bvol):
    return {bvol[i:i+GR] for i in range(0, len(bvol) - GR + 1)}

surum_build_gramlari = {}   # idx -> [set, ...]
for idx, surum in enumerate(SURUMLER):
    d = os.path.join(CORPUS, "VMProtect_" + surum.replace(" ", "_"))
    if not os.path.isdir(d): continue
    ks = []
    for f in sorted(os.listdir(d)):
        if not f.endswith(".vmp.exe"): continue
        bvol = koruyucu_veri(open(os.path.join(d, f), "rb").read())
        if len(bvol) >= 1024:
            ks.append(gramlar(bvol))
    if ks: surum_build_gramlari[idx] = ks

# sıklık sayımı
imzalar = {}
for idx, ks in surum_build_gramlari.items():
    sayac = defaultdict(int)
    for k in ks:
        for g in k: sayac[g] += 1
    oran = ESIK * len(ks)
    sik = {g for g, c in sayac.items() if c >= oran}
    imzalar[idx] = sik
    print(f"idx={idx} {SURUMLER[idx]}: {len(ks)} build, sık gram={len(sik)}")

# benzersizlik filtresi
tum_diger = {}
for idx, ks in surum_build_gramlari.items():
    tum_diger[idx] = set().union(*ks)

tablo = {}
for idx, sik in imzalar.items():
    diger = set()
    for jdx, bir in tum_diger.items():
        if jdx != idx: diger |= bir
    benzersiz = sorted(sik - diger)[:MAKS]
    tablo[str(idx)] = [g.hex() for g in benzersiz]
    print(f"K5v3[{idx}] {SURUMLER[idx]}: {len(tablo[str(idx)])} benzersiz imza gram")

# öz doğrulama: her build kendi imzasıyla kaç puan alır, diğerlarıyla kaç?
print("\n=== ÖZ DOĞRULAMA (min/orta kendi kapsama, maks diğer sürüm kapsaması) ===")
for idx, ks in surum_build_gramlari.items():
    imza = imzalar.get(idx, set())
    ben = set(bytes.fromhex(h) for h in tablo[str(idx)])
    if not ben:
        print(f"idx={idx}: imza yok — atlandı"); continue
    kap = sorted(len(k & ben)/len(ben) for k in ks)
    diger_maks = 0.0
    for jdx, ks2 in surum_build_gramlari.items():
        if jdx == idx: continue
        m = max(len(k & ben)/len(ben) for k in ks2)
        diger_maks = max(diger_maks, m)
    print(f"idx={idx} {SURUMLER[idx]:22s}: kendi min={kap[0]:.3f} ort={kap[len(kap)//2]:.3f} | diğer maks={diger_maks:.3f}")

json.dump({"sürümler": SURUMLER, "imzalar": tablo},
          open(f"{KOK}/work/v4/k5_db3.json","w"))
print(f"\nYAZILDI ({os.path.getsize(f'{KOK}/work/v4/k5_db3.json')/1024:.0f} KB)")
