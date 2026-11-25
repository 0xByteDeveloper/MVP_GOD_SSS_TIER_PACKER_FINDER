#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""katman_isleri3.py — DOĞRU formatta (vmp_proje.py, Document Version=2)
çok katmanlı derleme işleri üretir."""
import os, sys, json, shutil, importlib.util

KOK = "/home/z/my-project"
ALLVER = f"{KOK}/work/allver/Allver_Collection"
YENI = f"{KOK}/work/yeni"

spec = importlib.util.spec_from_file_location("vmp_proje", f"{KOK}/scripts/vmp_proje.py")
vp = importlib.util.module_from_spec(spec); spec.loader.exec_module(vp)

isler = []

# ---- 1) UPX iç + VMP 3.9.4 dış
d = f"{YENI}/06_Katman_UPX_VMP"; os.makedirs(d, exist_ok=True)
ic = os.path.join(d, "Test_64.upx.exe")
shutil.copy(f"{YENI}/01_Gercek_UPX/Test_64_upx.exe", ic)
proje = os.path.join(d, "katman_upx_vmp394.vmp")
open(proje, "w").write(vp.proje_xml(ic, os.path.join(d, "Test_64.upx.vmp.exe")))
isler.append({"surum_dizin": f"{ALLVER}/VMProtect Ultimate 3.9.4", "proje": proje,
              "cikti": os.path.join(d, "Test_64.upx.vmp.exe"), "azami": 300,
              "etiket": "UPX_ic_VMP394_dis"})

# ---- 2) VMP 3.4.0 iç + VMP 3.9.4 dış (çift VMProtect, farklı sürümler)
d = f"{YENI}/07_Katman_VMP_VMP"; os.makedirs(d, exist_ok=True)
ic = os.path.join(d, "Test_64_34.vmp.exe")
shutil.copy(f"{KOK}/work/corpus/VMProtect_Ultimate_3.4.0/Test_64_fn0.vmp.exe", ic)
proje = os.path.join(d, "katman_vmp_vmp.vmp")
open(proje, "w").write(vp.proje_xml(ic, os.path.join(d, "Test_64_34.vmp.vmp.exe")))
isler.append({"surum_dizin": f"{ALLVER}/VMProtect Ultimate 3.9.4", "proje": proje,
              "cikti": os.path.join(d, "Test_64_34.vmp.vmp.exe"), "azami": 300,
              "etiket": "VMP340_ic_VMP394_dis"})

# ---- 3) UPX iç + VMP 3.4.0 dış
d = f"{YENI}/06_Katman_UPX_VMP"
ic = os.path.join(d, "Test_64b.upx.exe")
shutil.copy(f"{YENI}/01_Gercek_UPX/Test_64_upx_best.exe", ic)
proje = os.path.join(d, "katman_upx_vmp34.vmp")
open(proje, "w").write(vp.proje_xml(ic, os.path.join(d, "Test_64b.upx.vmp.exe")))
isler.append({"surum_dizin": f"{ALLVER}/VMProtect Ultimate 3.4.0", "proje": proje,
              "cikti": os.path.join(d, "Test_64b.upx.vmp.exe"), "azami": 300,
              "etiket": "UPX_ic_VMP340_dis"})

# ---- 4) UPX iç + VMP 3.6.0 dış + Pack seçeneği
d = f"{YENI}/06_Katman_UPX_VMP"
ic = os.path.join(d, "Test_64c.upx.exe")
shutil.copy(f"{YENI}/01_Gercek_UPX/Test_64_upx_ultra.exe", ic)
proje = os.path.join(d, "katman_upx_vmp36_pack.vmp")
open(proje, "w").write(vp.proje_xml(ic, os.path.join(d, "Test_64c.upx.vmp.exe"),
                                    secenekler=["Pack"]))
isler.append({"surum_dizin": f"{ALLVER}/VMProtect Ultimate 3.6.0", "proje": proje,
              "cikti": os.path.join(d, "Test_64c.upx.vmp.exe"), "azami": 300,
              "etiket": "UPX_ic_VMP360_dis_Pack"})

json.dump({"isler": isler}, open(f"{YENI}/katman_isler3.json","w"), indent=1)
for i in isler: print(i["etiket"], "->", os.path.basename(i["cikti"]))
print("iş:", len(isler))
