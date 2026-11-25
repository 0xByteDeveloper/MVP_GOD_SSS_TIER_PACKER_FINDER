#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""yetenek_matrisi.py — vmpdet4 tüm yeni yetenek testleri + JSON rapor."""
import os, json, subprocess

KOK = "/home/z/my-project"
YENI = f"{KOK}/work/yeni"
VMPDET = f"{KOK}/work/v4/vmpdet4_linux"
OUT = f"{KOK}/work/v4/yetenek_matrisi.json"

TESTLER = [
    # (kategori, dosya, beklenen)
    ("negatif", "02_Negatif/Test_64_paketsiz.exe", "PAKETSIZ/VMP-degil"),
    ("negatif", "02_Negatif/hello_mingw.exe", "PAKETSIZ/VMP-degil"),
    ("negatif", "02_Negatif/Test_64_upx_geri_acilmis.exe", "PAKETSIZ/VMP-degil"),
    ("upx_gercek", "01_Gercek_UPX/Test_64_upx.exe", "UPX/VMP-degil"),
    ("upx_gercek", "01_Gercek_UPX/Test_64_upx_best.exe", "UPX/VMP-degil"),
    ("upx_gercek", "01_Gercek_UPX/Test_64_upx_ultra.exe", "UPX/VMP-degil"),
    ("themida_izi", "03_Themida_Izi/Test_64_themida_izi.exe", "Themida/VMP-degil"),
    ("themida_izi", "03_Themida_Izi/Test_64_boom_izi.exe", "Themida/VMP-degil"),
    ("bolum_degisti", "04_Bolum_Yeniden_Ad/Test_64_309_adlar_degisti.exe", "VMP+surum+uyari"),
    ("bolum_degisti", "04_Bolum_Yeniden_Ad/Test_64_34_adlar_degisti.exe", "VMP+surum+uyari"),
    ("bolum_degisti", "04_Bolum_Yeniden_Ad/Test_64_36_adlar_degisti.exe", "VMP+surum+uyari"),
    ("modlanmis_sim", "05_Modlanmis_Motor/Test_64_309_modlanmis.exe", "VMP+surum(yapi)"),
    ("modlanmis_sim", "05_Modlanmis_Motor/Test_64_34_modlanmis.exe", "VMP+surum(yapi)"),
    ("modlanmis_sim", "05_Modlanmis_Motor/Test_64_36_modlanmis.exe", "VMP+surum(yapi)"),
    ("hello_referans", "11_Hello_Referans/hello_Lite_3104.vmp.exe", "Lite 3.10.4"),
    ("hello_referans", "11_Hello_Referans/hello_Lite_387.vmp.exe", "Lite 3.8.7"),
    ("hello_referans", "11_Hello_Referans/hello_Pro_381.vmp.exe", "esitlik 3.8.1|3.8.4"),
    ("hello_referans", "11_Hello_Referans/hello_Pro_396.vmp.exe", "Pro 3.9.6"),
    ("hello_referans", "11_Hello_Referans/hello_Ult_309.vmp.exe", "Ult 3.0.9"),
    ("hello_referans", "11_Hello_Referans/hello_Ult_320.vmp.exe", "Ult 3.2.0"),
    ("hello_referans", "11_Hello_Referans/hello_Ult_340.vmp.exe", "Ult 3.4.0"),
    ("hello_referans", "11_Hello_Referans/hello_Ult_360.vmp.exe", "Ult 3.6.0"),
    ("hello_referans", "11_Hello_Referans/hello_Ult_384.vmp.exe", "esitlik 3.8.1|3.8.4"),
    ("hello_referans", "11_Hello_Referans/hello_Ult_394.vmp.exe", "Ult 3.9.4"),
    ("cift_vmp", "07_Katman_VMP_VMP/Test_64_34.vmp.vmp.exe", "cift+3.4.0(ic)"),
    ("cift_vmp", "07_Katman_VMP_VMP/Test_64_309dis_34ic.vmp.vmp.exe", "cift+3.4.0(ic)"),
    ("cift_vmp", "07_Katman_VMP_VMP/Test_64_34_34.vmp.vmp.exe", "cift+3.4.0+3.4.0"),
    ("cift_vmp", "09_Runtime_Demo/hello_34_394.vmp.vmp.exe", "cift+3.4.0(cap2)"),
    ("upx_dis", "08_Katman_VMP_UPX/Test_64_34_fn0.exe", "UPX-dis+VMP-ic gizli"),
    ("upx_dis", "08_Katman_VMP_UPX/Test_64_3439_fn0.exe", "UPX-dis+çift-VMP gizli"),
    ("upx_dis", "08_Katman_VMP_UPX/Test_64_309_fn0.exe", "UPX-dis+VMP gizli"),
    ("script_rastgele", "09_Runtime_Demo/hello_394_rastgele_bolum.vmp.exe", "koruyucu/renamed"),
    ("runtime_demo", "09_Runtime_Demo/hello_394.vmp.exe", "VMP 3.9.4"),
    ("ozel_bolum", "10_Ozel_Bolum_Adi/Test_64_john.vmp.exe", "VMP (ad etkisiz)"),
]

sonuclar = []
for kategori, rel, beklenen in TESTLER:
    yol = os.path.join(YENI, rel)
    if not os.path.exists(yol):
        sonuclar.append({"kategori": kategori, "dosya": rel, "beklenen": beklenen,
                         "bulunan": "DOSYA-YOK", "durum": "ATLANDI"})
        continue
    r = subprocess.run([VMPDET, "--json", "/tmp/matris_tek.json", yol],
                       capture_output=True, text=True, timeout=60)
    try:
        kayit = json.load(open("/tmp/matris_tek.json"))[0]
    except Exception:
        kayit = {"vmp": None, "kanit": "cozumlenemedi"}
    sonuclar.append({
        "kategori": kategori, "dosya": rel, "beklenen": beklenen,
        "vmp": kayit.get("vmp"),
        "surum": kayit.get("surum", ""),
        "paketleyici": kayit.get("paketleyici", ""),
        "kanit": kayit.get("kanit", ""),
        "katmanli": kayit.get("katmanli", False),
        "bolum_degisti": kayit.get("bolum_adlari_degisti", False),
        "ozel_varyant": kayit.get("ozel_varyant", False),
        "durum": "OK",
    })

json.dump(sonuclar, open(OUT, "w"), ensure_ascii=False, indent=1)
print(f"{len(sonuclar)} test → {OUT}\n")
# ozet tablo
for k in sorted(set(s['kategori'] for s in sonuclar)):
    satirlar = [s for s in sonuclar if s['kategori'] == k]
    print(f"[{k}] {len(satirlar)} test")
    for s in satirlar:
        isaret = "VMP" if s.get('vmp') else ("NEG" if s.get('paketleyici') else "-")
        print(f"   {isaret} {s['dosya'].split('/')[-1][:44]:44s} beklenen={s['beklenen'][:28]:28s} surum={str(s.get('surum',''))[:34]}")
