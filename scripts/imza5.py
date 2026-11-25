#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""imza5.py — corpus5 imza analizi: her build'in korumalı bölümlerini + PE özelliklerini çıkarır,
aile bazında sürüm ayrıştırılabilirliğini ölçer. Çıktı: work/v5/corpus_analiz.json
"""
import os, json, struct
from collections import defaultdict

KOK = "/home/z/my-project"
C5 = f"{KOK}/work/corpus5"
STANDART = {".text", ".rdata", ".data", ".pdata", ".reloc", ".rsrc", ".idata", ".tls",
            ".eh_fram", ".bss", ".edata", ".didat", ".debug", ".CRT", ".gfids"}

def pe_ozet(yol):
    d = open(yol, "rb").read()
    e = struct.unpack_from("<I", d, 0x3C)[0]
    if d[e:e+4] != b"PE\0\0":
        return None
    mach, n = struct.unpack_from("<HH", d, e+4)
    chars, = struct.unpack_from("<H", d, e+22)
    osz, = struct.unpack_from("<H", d, e+20)
    opt = e + 24
    magic, = struct.unpack_from("<H", d, opt)
    dd = opt + (112 if magic == 0x20B else 96)
    sec = opt + osz
    bolumler = []
    for i in range(n):
        o = sec + i*40
        ad = d[o:o+8].rstrip(b"\0").decode(errors="replace")
        vsz, va, rsz, ra = struct.unpack_from("<IIII", d, o+8)
        sc, = struct.unpack_from("<I", d, o+36)
        bolumler.append({"ad": ad, "vsz": vsz, "va": va, "rsz": rsz, "ra": ra, "sc": sc})
    return {
        "makine": mach, "dll": bool(chars & 0x2000), "magic": magic,
        "boyut": len(d), "bolumler": bolumler,
        "exp_rva": struct.unpack_from("<I", d, dd)[0],
        "imp_rva": struct.unpack_from("<I", d, dd+8)[0],
        "rel_rva": struct.unpack_from("<I", d, dd+40)[0],
    }

def main():
    kayitlar = []
    for sv in sorted(os.listdir(C5)):
        bj = f"{C5}/{sv}/builds.json"
        if not os.path.exists(bj):
            continue
        d = json.load(open(bj))
        for b in d["builds"]:
            if not (os.path.exists(b["cikti"]) and os.path.getsize(b["cikti"]) > 0):
                continue
            try:
                rr = json.load(open(f"{C5}/{sv}/results.json"))
                if rr.get(b["ad"], {}).get("durum") == "ATLANDI":
                    continue
            except FileNotFoundError:
                pass
            p = pe_ozet(b["cikti"])
            if p is None:
                print("BOZUK PE:", b["cikti"])
                continue
            kor = [x for x in p["bolumler"] if x["ad"] not in STANDART and x["rsz"] > 0]
            kayitlar.append({
                "surum": d["no"], "surum_kisa": sv, "edition": d["edition"],
                "ad": b["ad"], "aile": b["aile"], "yol": b["cikti"],
                "makine": p["makine"], "dll": p["dll"], "boyut": p["boyut"],
                "bolum_sayi": len(p["bolumler"]),
                "kor": [[x["ad"], x["rsz"], x["vsz"], x["sc"]] for x in kor],
                "secenekler": b["secenekler"], "prosedurler": b["prosedurler"],
                "exp_rva": p["exp_rva"], "imp_rva": p["imp_rva"], "rel_rva": p["rel_rva"],
            })
    os.makedirs(f"{KOK}/work/v5", exist_ok=True)
    json.dump(kayitlar, open(f"{KOK}/work/v5/corpus_analiz.json", "w"), ensure_ascii=False, indent=1)
    print(f"{len(kayitlar)} build analiz edildi")

    # ---- aile bazında sürüm ayrımı: (aile, build-tipi) → {sürüm: (raw,vsz) çipi}
    print("\n=== AİLE × BUILD-TİPİ ÇİPA TABLOSU (sürüm ayrıştırılabilirlik) ===")
    for aile in ["T32E", "T32D", "T64E", "T64D"]:
        print(f"\n--- {aile} ---")
        tipler = ["fn0", "Pack", "ImportProtection", "HEPSI", "Move_Virt", "Move_Mutation", "Move_Ultra", "Move_Ultra_HEPSI"]
        for tip in tipler:
            cipler = {}
            for k in kayitlar:
                if k["aile"] != aile or not k["ad"].endswith(tip):
                    continue
                imza = tuple(tuple(x[1:3]) for x in k["kor"])  # (raw,vsz) dizisi
                cipler.setdefault(imza, []).append(k["surum"])
            benzersiz = {}
            for imza, svr in cipler.items():
                benzersiz.setdefault(tuple(svr), imza)
            ayirt = sum(1 for svr in benzersiz if len(set(svr)) == 1)
            top = len(benzersiz)
            print(f"  {tip:18s}: {top} farklı çip, {ayirt} tanesi tek sürüme işaret"
                  + ("  ⚠ ÇAKIŞMA" if ayirt < top else ""))

if __name__ == "__main__":
    main()
