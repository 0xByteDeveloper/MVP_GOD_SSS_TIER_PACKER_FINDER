#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""k5_hesap.py — K5 MOTOR PARMAK İZİ: her sürüm için koruyucu bölümdeki
SABİT bayt pozisyonları (tüm build'lerde aynı) + diğer sürümlerden ayrışan
değerler. vmpdet4'ün detektor_db.h'üne gömülecek tabloyu üretir.

Çıktı: work/v4/k5_db.json  {surum_idx: [[ofset, bayt, ayirt_edici_mi], ...]}
"""
import os, json, struct

KOK = "/home/z/my-project"
CORPUS = f"{KOK}/work/corpus"

# sürüm sırası detektor_db.h SURUM[] ile aynı olmalı — v3 DB'den al
db = open(f"{KOK}/work/v4/detektor_db.h", encoding="utf-8").read()
import re
surum_blok = re.search(r"SURUM\[\]\s*=\s*\{(.*?)\};", db, re.S)
SURUMLER = re.findall(r'"([^"]+)"', surum_blok.group(1))
print("DB sürümleri:", SURUMLER)

STANDART = {".text",".rdata",".data",".pdata",".tls",".rsrc",".reloc",".edata",
            ".idata",".bss",".gfids",".qtmetad","_RDATA",".xdata",".CRT",".didat",
            ".xc",".clr",".sdata",".00cfg",".textbss",".eh_fram",".eh_frame",
            ".gcc_except_table",".UPX0",".UPX1",".UPX2"}
for ek in (".rdata$", ".text$", ".data$", ".CRT$"):
    STANDART |= {ek}  # önek kontrolü ayrı yapılacak

def ilk_koruyucu_bolum(veri):
    """ilk standart-dışı bölümün (ad, ham_veri) — K5 referans bölümü"""
    e = struct.unpack_from('<I', veri, 0x3C)[0]
    n = struct.unpack_from('<H', veri, e+6)[0]
    opt = struct.unpack_from('<H', veri, e+20)[0]
    bt = e + 24 + opt
    for i in range(n):
        o = bt + 40*i
        ad = veri[o:o+8].rstrip(b'\0').decode('ascii','replace')
        vsz, va, rsz, ro = struct.unpack_from('<IIII', veri, o+8)
        standart = ad in STANDART or any(ad.startswith(p) for p in (".rdata$",".text$",".data$",".CRT$"))
        if not standart and rsz > 0:
            return ad, veri[ro:ro+rsz]
    return None, b""

# her sürümün build'lerinden bölüm verilerini topla
surum_bolumleri = {}
for idx, surum in enumerate(SURUMLER):
    d = os.path.join(CORPUS, "VMProtect_" + surum.replace(" ", "_"))
    if not os.path.isdir(d):
        print(f"UYARI: {surum} corpus yok"); continue
    bolumler = []
    for f in sorted(os.listdir(d)):
        if not f.endswith(".vmp.exe"): continue
        veri = open(os.path.join(d, f), "rb").read()
        ad, bvol = ilk_koruyucu_bolum(veri)
        if ad and len(bvol) > 512:
            bolumler.append((f, ad, bvol))
    if bolumler:
        surum_bolumleri[idx] = bolumler
        print(f"{surum}: {len(bolumler)} build, bölüm örnekleri: {set(b[1] for b in bolumler)}")
    else:
        print(f"{surum}: build yok!")

# sabit pozisyonlar: min uzunluk içinde tüm build'lerde aynı bayt
k5 = {}
for idx, bolumler in surum_bolumleri.items():
    min_uz = min(len(b[2]) for b in bolumler)
    min_uz = min(min_uz, 8192)  # ilk 8KB yeter
    sabitler = []
    for ofs in range(min_uz):
        degerler = set(b[2][ofs] for b in bolumler)
        if len(degerler) == 1:
            sabitler.append((ofs, degerler.pop()))
    surum_bolumleri[idx] = (bolumler, sabitler)
    print(f"sürüm idx={idx} {SURUMLER[idx]}: sabit pozisyon={len(sabitler)} (min uzunluk {min_uz})")

# ayırt edicilik: pozisyon+değer diğer sürümlerin sabitlerinden farklı mı
tablo = {}
for idx, (bolumler, sabitler) in surum_bolumleri.items():
    diger = {}
    for jdx, (b2, s2) in surum_bolumleri.items():
        if jdx != idx:
            diger[jdx] = dict(s2)
    kayit = []
    for ofs, byt in sabitler:
        ayirt = True
        for jdx, dmap in diger.items():
            if dmap.get(ofs) == byt:
                ayirt = False; break
        kayit.append([ofs, byt, 1 if ayirt else 0])
    # en güçlü 240 pozisyon: önce ayırt edici, sonra ofset sırası
    kayit.sort(key=lambda x: (-x[2], x[0]))
    kayit = kayit[:240]
    # ofset sırasına geri getir
    kayit.sort()
    tablo[idx] = kayit
    ayirt_sayi = sum(k[2] for k in kayit)
    print(f"K5[{idx}] {SURUMLER[idx]}: {len(kayit)} pozisyon ({ayirt_sayi} ayırt edici)")

json.dump({"sürümler": SURUMLER, "k5": tablo},
          open(f"{KOK}/work/v4/k5_db.json","w"), indent=0)
print("\nYAZILDI: work/v4/k5_db.json")
