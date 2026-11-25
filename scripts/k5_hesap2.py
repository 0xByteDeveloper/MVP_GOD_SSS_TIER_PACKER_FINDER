#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""k5_hesap2.py — K5 v2: İÇERİK parmak izi. Her sürüm için:
  - tüm build'lerinin ilk koruyucu bölümünde (ilk 64KB) ORTAK 8-gram'lar (motor kelime dağarcığı)
  - bunlardan DİĞER sürümlerin HİÇBİR build'inde görünmeyenler = benzersiz motor gram'ları
Çıktı: work/v4/k5_db2.json  (hex 8-gram listeleri)
"""
import os, json, struct

KOK = "/home/z/my-project"
CORPUS = f"{KOK}/work/corpus"
GR = 8           # gram boyutu
SINIR = 65536    # bölüm başından ilk 64KB
MAKS_GRAM = 3000 # sürüm başına saklanacak benzersiz gram üst sınırı

db = open(f"{KOK}/work/v4/detektor_db.h", encoding="utf-8").read()
import re
SURUMLER = re.findall(r'"([^"]+)"', re.search(r"SURUM\[\]\s*=\s*\{(.*?)\};", db, re.S).group(1))

STANDART = {".text",".rdata",".data",".pdata",".tls",".rsrc",".reloc",".edata",
            ".idata",".bss",".gfids",".qtmetad","_RDATA",".xdata",".CRT",".didat",
            ".xc",".clr",".sdata",".00cfg",".textbss",".eh_fram",".eh_frame",
            ".gcc_except_table",".UPX0",".UPX1",".UPX2"}
ONEK = (".rdata$",".text$",".data$",".CRT$")

def ilk_koruyucu(veri):
    e = struct.unpack_from('<I', veri, 0x3C)[0]
    n = struct.unpack_from('<H', veri, e+6)[0]
    opt = struct.unpack_from('<H', veri, e+20)[0]
    bt = e + 24 + opt
    for i in range(n):
        o = bt + 40*i
        ad = veri[o:o+8].rstrip(b'\0').decode('ascii','replace')
        vsz, va, rsz, ro = struct.unpack_from('<IIII', veri, o+8)
        if (ad not in STANDART and not any(ad.startswith(p) for p in ONEK)) and rsz > 512:
            return veri[ro:ro+min(rsz, SINIR)]
    return b""

def gram_kumesi(bvol):
    s = set()
    for i in range(0, len(bvol) - GR + 1):
        s.add(bvol[i:i+GR])
    return s

surum_gramlari = {}   # idx -> [build gram kümeleri]
for idx, surum in enumerate(SURUMLER):
    d = os.path.join(CORPUS, "VMProtect_" + surum.replace(" ", "_"))
    if not os.path.isdir(d):
        print("YOK:", surum); continue
    kumeler = []
    for f in sorted(os.listdir(d)):
        if not f.endswith(".vmp.exe"): continue
        bvol = ilk_koruyucu(open(os.path.join(d, f), "rb").read())
        if len(bvol) >= 1024:
            kumeler.append(gram_kumesi(bvol))
    if kumeler:
        surum_gramlari[idx] = kumeler
        print(f"{surum}: {len(kumeler)} build gram kümesi (ort. {sum(len(k) for k in kumeler)//len(kumeler)} gram)")

# kelime dağarcığı = kesişim
sozlukler = {}
for idx, kumeler in surum_gramlari.items():
    it = set(kumeler[0])
    for k in kumeler[1:]:
        it &= k
    sozlukler[idx] = it
    print(f"idx={idx} {SURUMLER[idx]}: kelime dağarcığı={len(it)}")

# her sürümün build'lerdekilerin TOPLAMI (benzersizlik filtresi için)
tum_gramlar = {}
for idx, kumeler in surum_gramlari.items():
    bir = set()
    for k in kumeler: bir |= k
    tum_gramlar[idx] = bir

# benzersiz motor gram'ları
tablo = {}
for idx, sozluk in sozlukler.items():
    diger = set()
    for jdx, bir in tum_gramlar.items():
        if jdx != idx: diger |= bir
    benzersiz = sorted(sozluk - diger)[:MAKS_GRAM]
    tablo[idx] = [g.hex() for g in benzersiz]
    print(f"K5v2[{idx}] {SURUMLER[idx]}: {len(tablo[idx])} benzersiz gram")

json.dump({"sürümler": SURUMLER, "k5": tablo},
          open(f"{KOK}/work/v4/k5_db2.json","w"))
boyut = os.path.getsize(f"{KOK}/work/v4/k5_db2.json")
print(f"YAZILDI: work/v4/k5_db2.json ({boyut/1024:.0f} KB)")
