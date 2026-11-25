#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""katman_isleri5.py — üçüncü oturum:
  e1) 3.4.0 wrapper + hello (Sleep)
  e2) 3.9.4 wrapper + (e1) çıktısı → Sleep'li ÇİFT katman (runtime demo)
  e3) 3.9.4 wrapper + Test_64, VMCodeSectionName='.john' (gerçek özel bölüm adı)
"""
import os, json, shutil, importlib.util

KOK = "/home/z/my-project"
ALLVER = f"{KOK}/work/allver/Allver_Collection"
YENI = f"{KOK}/work/yeni"

spec = importlib.util.spec_from_file_location("vmp_proje", f"{KOK}/scripts/vmp_proje.py")
vp = importlib.util.module_from_spec(spec); spec.loader.exec_module(vp)

isler = []
d = f"{YENI}/09_Runtime_Demo"

# e1: 3.4.0 + hello
ic = os.path.join(d, "hello34_girdi.exe")
shutil.copy(os.path.join(d, "hello.exe"), ic)
proje = os.path.join(d, "katman_hello34.vmp")
open(proje,"w").write(vp.proje_xml(ic, os.path.join(d, "hello_34.vmp.exe")))
isler.append({"surum_dizin": f"{ALLVER}/VMProtect Ultimate 3.4.0", "proje": proje,
              "cikti": os.path.join(d, "hello_34.vmp.exe"), "azami": 240,
              "etiket": "VMP340_hello"})

# e2: 3.9.4 + (e1) çıktısı — Sleep'li çift katman (girdi = e1 çıktısı, oturum sırasında oluşur)
ic2 = os.path.join(d, "hello_34.vmp.exe")
proje2 = os.path.join(d, "katman_hello34_394.vmp")
open(proje2,"w").write(vp.proje_xml(ic2, os.path.join(d, "hello_34_394.vmp.vmp.exe")))
isler.append({"surum_dizin": f"{ALLVER}/VMProtect Ultimate 3.9.4", "proje": proje2,
              "cikti": os.path.join(d, "hello_34_394.vmp.vmp.exe"), "azami": 240,
              "etiket": "VMP394_dis_VMP340_ic_hello"})

# e3: özel bölüm adı (.john) — gerçek VMCodeSectionName seçeneği
d3 = f"{YENI}/10_Ozel_Bolum_Adi"; os.makedirs(d3, exist_ok=True)
ic3 = os.path.join(d3, "Test_64_girdi.exe")
shutil.copy(f"{KOK}/upload/Test_64.exe", ic3)
proje3 = os.path.join(d3, "katman_john.vmp")
open(proje3,"w").write(vp.proje_xml(ic3, os.path.join(d3, "Test_64_john.vmp.exe"),
                                    vm={"VMCodeSectionName": ".john"}))
isler.append({"surum_dizin": f"{ALLVER}/VMProtect Ultimate 3.9.4", "proje": proje3,
              "cikti": os.path.join(d3, "Test_64_john.vmp.exe"), "azami": 240,
              "etiket": "VMP394_bolum_john"})

json.dump({"isler": isler}, open(f"{YENI}/katman_isler5.json","w"), indent=1)
for i in isler: print(i["etiket"], "->", os.path.basename(i["cikti"]))
