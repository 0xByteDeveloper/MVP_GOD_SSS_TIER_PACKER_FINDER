#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""db_uret5.py — corpus_analiz.json → detektor_db5.h (v5 gömülü imza DB)
Sürüm indeksleri v4 düzenini korur:
  0=Lite 3.10.4, 1=Lite 3.8.7, 2=Pro 3.8.1, 3=Pro 3.9.6, 4=Ult 3.0.9,
  5=Ult 3.2.0, 6=Ult 3.4.0, 7=Ult 3.6.0, 8=Ult 3.8.4, 9=Ult 3.9.4
Aileler: 0=T32E, 1=T32D, 2=T64E, 3=T64D
Tipler : 0=fn0 1=Pack 2=ImportProtection 3=HEPSI 4=Move_Virt 5=Move_Mutation
         6=Move_Ultra 7=Move_Ultra_HEPSI
"""
import json

KOK = "/home/z/my-project"
kay = json.load(open(f"{KOK}/work/v5/corpus_analiz.json"))

SURUM_NO2IDX = {"3.10.4": 0, "3.8.7": 1, "3.8.1": 2, "3.9.6": 3, "3.0.9": 4,
                "3.2.0": 5, "3.4.0": 6, "3.6.0": 7, "3.8.4": 8, "3.9.4": 9}
SURUM_AD = ["Lite 3.10.4", "Lite 3.8.7", "Professional 3.8.1", "Professional 3.9.6",
            "Ultimate 3.0.9", "Ultimate 3.2.0", "Ultimate 3.4.0", "Ultimate 3.6.0",
            "Ultimate 3.8.4", "Ultimate 3.9.4"]
EDISYON = ["Lite", "Lite", "Professional", "Professional", "Ultimate", "Ultimate",
           "Ultimate", "Ultimate", "Ultimate", "Ultimate"]
AILE_AD = ["T32E", "T32D", "T64E", "T64D"]
AILE_MAK = [0x14C, 0x14C, 0x8664, 0x8664]
AILE_DLL = [0, 1, 0, 1]
TIP_AD = ["fn0", "Pack", "ImportProtection", "HEPSI", "Move_Virt",
          "Move_Mutation", "Move_Ultra", "Move_Ultra_HEPSI"]
TIP2IDX = {ad: i for i, ad in enumerate(TIP_AD)}

# ---- profiller
profiller = []
for k in kay:
    tip_ad = k["ad"].split("_", 1)[1]
    if tip_ad not in TIP2IDX:
        continue
    sv = SURUM_NO2IDX[k["surum"]]
    aile = AILE_AD.index(k["aile"])
    kor = k["kor"][:3]
    profiller.append({
        "aile": aile, "surum": sv, "tip": TIP2IDX[tip_ad],
        "ad": k["ad"], "bolum_sayi": len(k["kor"]),
        "raw": [x[1] for x in kor], "vsz": [x[2] for x in kor], "kar": [x[3] for x in kor],
    })

# ---- çakışma denetimi: aynı ailede aynı imza → sürüm kümesi
imza2sv = {}
for pr in profiller:
    imza = (pr["aile"], pr["bolum_sayi"], tuple(pr["raw"]), tuple(pr["vsz"]))
    imza2sv.setdefault(imza, set()).add(pr["surum"])
cakis = {k: v for k, v in imza2sv.items() if len(v) > 1}
print(f"{len(profiller)} profil; çakışan imza: {len(cakis)}")
for k, v in cakis.items():
    print(f"  AİLE {AILE_AD[k[0]]} böl={k[1]} raw={k[2]} vsz={k[3]} → sürüm {sorted(v)}")
    # fn0 3.8.1/3.8.4 eşitliği dışında çakışma OLMAZ
    assert sorted(v) == [2, 8] and k[1] == 1, "BEKLENMEDİK ÇAKIŞMA!"

# ---- CAPA2 (hello ailesi — runtime demo'ları için korunur)
capa2_hello = json.load(open(f"{KOK}/work/v4/capa2_hello.json"))
HELLO_IDX = {"Lite_3104": 0, "Lite_387": 1, "Pro_381": 2, "Pro_396": 3, "Ult_309": 4,
             "Ult_320": 5, "Ult_340": 6, "Ult_360": 7, "Ult_384": 8, "Ult_394": 9}

sat = []
sat.append("// ============================================================================")
sat.append("// detektor_db5.h — v5 GÖMÜLÜ İMZA VERİTABANI (otomatik üretildi: db_uret5.py)")
sat.append("// DÖRT AİLE korpusu: 32-bit EXE / 32-bit DLL / 64-bit EXE / 64-bit DLL")
sat.append("// (kullanıcının GERÇEK Test_32/64 exe+dll dosyaları, 312 build, 10 sürüm)")
sat.append("// Sürüm atfı: aile-kapısı → tam cipa eşleşmesi → goreli-marjlı profil mesafesi")
sat.append("// EŞİTLİK: yalnız fn0 (seçeneksiz saf wrapper) yapısında Pro 3.8.1 ∥ Ult 3.8.4")
sat.append("//   bayt-özdeştir; Pack/Move/HEPSI yapılarında AYRIŞIRLAR (kanıtlı).")
sat.append("// ============================================================================")
sat.append("#pragma once")
sat.append("#include <cstdint>")
sat.append("")
sat.append("namespace vmpdb {")
sat.append("")
sat.append(f"static const int SURUM_SAYI = {len(SURUM_AD)};")
sat.append("static const char* const SURUM[] = {" + ", ".join(f'"{x}"' for x in SURUM_AD) + "};")
sat.append("static const char* const EDISYON[] = {" + ", ".join(f'"{x}"' for x in EDISYON) + "};")
sat.append("")
sat.append(f"static const int AILE_SAYI = {len(AILE_AD)};")
sat.append("static const char* const AILE_AD[] = {" + ", ".join(f'"{x}"' for x in AILE_AD) + "};")
sat.append("// aile: makine (0x14C/0x8664) + DLL bayrağı")
sat.append("static const uint16_t AILE_MAKINE[] = {" + ", ".join(f"0x{m:X}" for m in AILE_MAK) + "};")
sat.append("static const uint8_t AILE_DLL[] = {" + ", ".join(str(d) for d in AILE_DLL) + "};")
sat.append("static const char* const AILE_TARIF[] = {")
sat.append('    "32-bit EXE (i386)", "32-bit DLL (i386)", "64-bit EXE (AMD64)", "64-bit DLL (AMD64)"};')
sat.append("")
sat.append("// build tipi — özellik çıkarımı ve fn0-eşitliği için")
sat.append("static const int TIP_SAYI = 8;")
sat.append("static const char* const TIP_AD[] = {" + ", ".join(f'"{x}"' for x in TIP_AD) + "};")
sat.append("// tip 0 = fn0 (seçenek YOK, fonksiyon YOK) → eşitlik sınıfı olabilir")
sat.append("")
sat.append("// ---- profiller: (aile, sürüm, tip) → korumalı bölüm boyutları + karakteristikleri")
sat.append("struct Profil5 {")
sat.append("    uint8_t aile; uint8_t surum; uint8_t tip; uint8_t bolum_sayi;")
sat.append("    uint32_t raw[3]; uint32_t vsz[3]; uint32_t kar[3];")
sat.append("};")
sat.append(f"static const int PROFIL5_SAYI = {len(profiller)};")
sat.append("static const Profil5 PROFIL5[] = {")
for pr in profiller:
    r = (pr["raw"] + [0, 0, 0])[:3]
    v = (pr["vsz"] + [0, 0, 0])[:3]
    c = (pr["kar"] + [0, 0, 0])[:3]
    sat.append("    {%d,%d,%d,%d,{%u,%u,%u},{%u,%u,%u},{0x%X,0x%X,0x%X}}," % (
        pr["aile"], pr["surum"], pr["tip"], pr["bolum_sayi"],
        r[0], r[1], r[2], v[0], v[1], v[2], c[0], c[1], c[2]))
sat.append("};")
sat.append("")
sat.append("// ---- eşitlik sınıfı (yalnız fn0 yapıları): Pro 3.8.1 (idx 2) ∥ Ult 3.8.4 (idx 8)")
sat.append("static const int ESDEGER_SAYI = 2;")
sat.append("static const int ESDEGER_UYE[] = {2, 8};")
sat.append("")

# CAPA2 hello
sat.append("// ---- CAPA2: hello girdi-ailesi (runtime demo katmanları için)")
sat.append("struct Capa2Kayit5 { uint32_t raw; uint32_t vsz; int8_t surum; };")
sat.append("struct Capa2Aile5 { const char* ad; uint32_t isaret_raw; uint32_t isaret_vsz;")
sat.append("                     int kayit_sayi; Capa2Kayit5 kayit[10]; };")
isaret = (108, 512)  # hello ailesi işaret bölümü (.vmp0 108/512)
kayitlar = []
for kis, bol in capa2_hello.items():
    for ad, raw, vsz, oz in bol:
        if ad == ".vmp1":
            kayitlar.append((raw, vsz, HELLO_IDX[kis]))
sat.append("static const int CAPA2_SAYI = 1;")
sat.append("static const Capa2Aile5 CAPA2[] = {")
sat.append(f'    {{"hello_mingw", {isaret[0]}, {isaret[1]}, {len(kayitlar)}, {{')
for raw, vsz, sv in kayitlar:
    sat.append(f"        {{{raw}, {vsz}, {sv}}},")
sat.append("    }},")
sat.append("};")
sat.append("")
sat.append("} // namespace vmpdb")
sat.append("")

open(f"{KOK}/work/v5/detektor_db5.h", "w", encoding="utf-8").write("\n".join(sat))
print(f"yazıldı: work/v5/detektor_db5.h ({len(sat)} satır)")
