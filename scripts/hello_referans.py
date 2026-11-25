#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""hello_referans.py — 10 sürümün hello üzerinde saf-wrapper referans derlemeleri.
Runtime demo (hello tabanlı çift katman) sürüm atfı için CAPA2 (hello ailesi) tablosu.
"""
import os, json, shutil, importlib.util

KOK = "/home/z/my-project"
ALLVER = f"{KOK}/work/allver/Allver_Collection"
YENI = f"{KOK}/work/yeni"
D = f"{YENI}/11_Hello_Referans"; os.makedirs(D, exist_ok=True)

spec = importlib.util.spec_from_file_location("vmp_proje", f"{KOK}/scripts/vmp_proje.py")
vp = importlib.util.module_from_spec(spec); spec.loader.exec_module(vp)

SURUMLER = [
    ("VMProtect Lite 3.10.4", "Lite_3104"),
    ("VMProtect Lite 3.8.7", "Lite_387"),
    ("VMProtect Professional 3.8.1", "Pro_381"),
    ("VMProtect Professional 3.9.6", "Pro_396"),
    ("VMProtect Ultimate 3.0.9", "Ult_309"),
    ("VMProtect Ultimate 3.2.0", "Ult_320"),
    ("VMProtect Ultimate 3.3.1", None),   # i386 — atlanır
    ("VMProtect Ultimate 3.4.0", "Ult_340"),
    ("VMProtect Ultimate 3.6.0", "Ult_360"),
    ("VMProtect Ultimate 3.8.4", "Ult_384"),
    ("VMProtect Ultimate 3.9.4", "Ult_394"),
]

def isler_uret(adlar):
    is_ = []
    for surum_dzn, kisa in SURUMLER:
        if kisa is None or kisa not in adlar: continue
        ic = os.path.join(D, f"hello_{kisa}_girdi.exe")
        shutil.copy(f"{YENI}/02_Negatif/hello_mingw.exe", ic)
        proje = os.path.join(D, f"hello_{kisa}.vmp")
        cikti = os.path.join(D, f"hello_{kisa}.vmp.exe")
        if os.path.exists(cikti): continue
        open(proje, "w").write(vp.proje_xml(ic, cikti))
        is_.append({"surum_dizin": f"{ALLVER}/{surum_dzn}", "proje": proje,
                    "cikti": cikti, "azami": 200, "etiket": f"hello_{kisa}"})
    return is_

if __name__ == "__main__":
    import sys
    adlar = sys.argv[1].split(",") if len(sys.argv) > 1 else [k for _, k in SURUMLER if k]
    is_ = isler_uret(adlar)
    json.dump({"isler": is_}, open(f"{YENI}/hello_referans_isler.json", "w"), indent=1)
    for i in is_: print(i["etiket"])
    print("iş:", len(is_))
