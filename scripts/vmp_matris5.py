#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vmp_matris5.py — v5 DÖRT AİLE derleme matrisi (GERÇEK kullanıcı dosyaları).
Aileler: T32E (Test_32.exe), T32D (Test_32.dll), T64E (Test_64.exe), T64D (Test_64.dll)
Build seti (aile başına, sürüm başına 8):
  fn0, HEPSI, Pack, ImportProtection,
  Move_Virt, Move_Mutation, Move_Ultra, Move_Ultra_HEPSI
Çıktı: work/corpus5/<surum>/ altına projeler + builds.json (sürücü: vmp_batch2.py)
"""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vmp_proje import proje_xml

KOK = "/home/z/my-project"
ORJ = f"{KOK}/upload/orijinal"
CORPUS = f"{KOK}/work/corpus5"

# aile → (girdi dosyası, MovePlayer VA, uzantı)
AILELER = {
    "T32E": (f"{ORJ}/Test_32.exe", 0x4014A0,  "exe"),
    "T32D": (f"{ORJ}/Test_32.dll", 0x10001380, "dll"),
    "T64E": (f"{ORJ}/Test_64.exe", 0x1400014C0, "exe"),
    "T64D": (f"{ORJ}/Test_64.dll", 0x1800013D0, "dll"),
}

# (dizin, kısa ad, sürüm_no, edition, x64?)
SURUMLER = [
    ("VMProtect Ultimate 3.9.4",     "VMProtect_Ultimate_3.9.4",     "3.9.4",  "Ultimate",     True),
    ("VMProtect Ultimate 3.8.4",     "VMProtect_Ultimate_3.8.4",     "3.8.4",  "Ultimate",     True),
    ("VMProtect Professional 3.9.6", "VMProtect_Professional_3.9.6", "3.9.6",  "Professional", True),
    ("VMProtect Professional 3.8.1", "VMProtect_Professional_3.8.1", "3.8.1",  "Professional", True),
    ("VMProtect Lite 3.10.4",        "VMProtect_Lite_3.10.4",        "3.10.4", "Lite",         True),
    ("VMProtect Lite 3.8.7",         "VMProtect_Lite_3.8.7",         "3.8.7",  "Lite",         True),
    ("VMProtect Ultimate 3.6.0",     "VMProtect_Ultimate_3.6.0",     "3.6.0",  "Ultimate",     True),
    ("VMProtect Ultimate 3.4.0",     "VMProtect_Ultimate_3.4.0",     "3.4.0",  "Ultimate",     True),
    ("VMProtect Ultimate 3.3.1",     "VMProtect_Ultimate_3.3.1",     "3.3.1",  "Ultimate",     False),
    ("VMProtect Ultimate 3.2.0",     "VMProtect_Ultimate_3.2.0",     "3.2.0",  "Ultimate",     True),
    ("VMProtect Ultimate 3.0.9",     "VMProtect_Ultimate_3.0.9",     "3.0.9",  "Ultimate",     True),
]

TUM_OZELLIKLER = ["MemoryProtection", "ImportProtection", "ResourceProtection", "Pack",
                  "StripDebugInfo", "StripFixups", "CheckDebugger", "CheckKernelDebugger",
                  "CheckVirtualMachine", "RunnerCRC", "LoaderCRC", "EncryptRegs",
                  "CryptValues", "EncryptBytecode", "DebugMode"]
TIP_AD = {0: "Virt", 1: "Mutation", 2: "Ultra"}


def vcmp(v, esik):
    return tuple(int(x) for x in v.split(".")) >= tuple(int(x) for x in esik.split("."))


def matris(aile, move_va, surum_no, edition):
    """[(ad, secenekler, prosedurler), ...]"""
    m = []

    def ekle(ad, sec=None, pros=None):
        m.append({"ad": ad, "secenekler": sec or [], "prosedurler": pros or []})

    # Pure wrapper
    ekle(f"{aile}_fn0")
    # Tekil yapısal özellikler (imza + özellik doğrulama)
    ekle(f"{aile}_Pack", sec=["Pack"])
    ekle(f"{aile}_ImportProtection", sec=["ImportProtection"])
    # Hepsini aç
    ekle(f"{aile}_HEPSI", sec=list(TUM_OZELLIKLER))
    # Fonksiyon koruma tipleri (MovePlayer)
    for tip in (0, 1, 2):
        ekle(f"{aile}_Move_{TIP_AD[tip]}", pros=[(move_va, tip, None)])
    # Ultra + hepsi
    ekle(f"{aile}_Move_Ultra_HEPSI", sec=list(TUM_OZELLIKLER), pros=[(move_va, 2, None)])
    return m


def main():
    os.makedirs(CORPUS, exist_ok=True)
    toplam = 0
    for dizin, kisa, no, edition, x64 in SURUMLER:
        if not x64:
            print(f"{kisa}: i386-ikili — 32-bit kanal için ayrı ele alınacak, atlandı")
            continue
        sur = f"{CORPUS}/{kisa}"
        prj = f"{sur}/projeler"
        os.makedirs(prj, exist_ok=True)
        liste = []
        for aile, (girdi, move_va, uz) in AILELER.items():
            for b in matris(aile, move_va, no, edition):
                ad = b["ad"]
                cikti = f"{sur}/{ad}.vmp.{uz}"
                pyp = f"{prj}/{ad}.vmp"
                open(pyp, "w", encoding="utf-8").write(
                    proje_xml(girdi, cikti, secenekler=b["secenekler"], prosedurler=b["prosedurler"]))
                liste.append({"ad": ad, "proje": pyp, "cikti": cikti, "aile": aile,
                              "secenekler": b["secenekler"], "prosedurler": b["prosedurler"]})
        json.dump({"surum": kisa, "no": no, "edition": edition,
                   "dizin": f"{KOK}/work/Allver_Collection/{dizin}", "builds": liste},
                  open(f"{sur}/builds.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        toplam += len(liste)
        print(f"{kisa}: {len(liste)} build (4 aile × 8)")
    print(f"TOPLAM: {toplam} build")


if __name__ == "__main__":
    main()
