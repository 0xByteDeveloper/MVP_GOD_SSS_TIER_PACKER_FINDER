#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vmp_proje.py - VMProtect .vmp (XML) proje dosyasi uretici (V309 + 3.5.1 kaynak + YAMA raporu). Windows VMProtect altinda (wine) mutlak Z: yollari kullanilir."""
import sys, json

# core.h enum ProjectOption (3.5.1 kaynağı) — XML 'Options' bit maskesi
SECENEK = {
    "DebugMode":         0x00000002,
    "CryptValues":       0x00000008,
    "IncludeWatermark":  0x00000020,
    "RunnerCRC":         0x00000040,
    "EncryptRegs":       0x00000080,
    "StripFixups":       0x00008000,
    "Pack":              0x00000100,
    "ImportProtection":  0x00000200,
    "CheckDebugger":     0x00000400,
    "CheckVirtualMachine": 0x00000800,
    "MemoryProtection":  0x00001000,
    "ResourceProtection": 0x00010000,
    "CheckKernelDebugger": 0x00020000,
    "StripDebugInfo":    0x00040000,
    "LoaderCRC":         0x10000000,
    "EncryptBytecode":   0x80000000,
    "VirtualFiles":      0x08000000,
}
TIP_AD = {0: "Virtualization", 1: "Mutation", 2: "Ultra"}


def z_yol(linux_yolu):
    """Linux yolunu wine Z: sürücü yoluna çevirir."""
    return "Z:" + linux_yolu.replace("/", "\\")


def proje_xml(girdi, cikti, secenekler=None, prosedurler=None, **vm):
    """prosedurler: [(adres_int, tip 0/1/2, complexity|None), ...]
    vm: VMVersion / VMInstances / VMComplexity / VMCodeSectionName / RandomSeed"""
    secenekler = secenekler or []
    prosedurler = prosedurler or []
    bolum = vm.get("VMCodeSectionName", ".vmp")
    attrs = {
        "InputFileName": z_yol(girdi),
        "OutputFileName": z_yol(cikti),
        "Options": str(sum(SECENEK[s] for s in secenekler)),
        "VMCodeSectionName": bolum,
    }
    for k in ("VMVersion", "VMInstances", "VMComplexity", "RandomSeed"):
        if k in vm and vm[k] is not None:
            attrs[k] = vm[k]
    s = ['<?xml version="1.0" encoding="UTF-8" ?>', '<Document Version="2">']
    s.append("    <Protection " + " ".join(f'{k}="{v}"' for k, v in attrs.items()) + ">")
    s += ["        <Folders />", "        <Procedures>"]
    for adres, tip, c in prosedurler:
        a = f'Address="0x{adres:X}" CompilationType="{tip}" IncludedInCompilation="true"'
        if c is not None:
            a += f' Complexity="{c}"'
        s.append(f"            <Procedure {a} />")
    s += ["        </Procedures>", "        <Messages />", "    </Protection>", "    <DLLBox />", "</Document>", ""]
    return "\n".join(s)


if __name__ == "__main__":
    # test: python3 vmp_proje.py out.vmp /home/z/.../Test_64.exe /home/z/.../cikti.exe 0x1400014B0 2
    girdi, cikti = sys.argv[2], sys.argv[3]
    pros = []
    if len(sys.argv) > 4:
        pros = [(int(sys.argv[4], 16), int(sys.argv[5]) if len(sys.argv) > 5 else 0, None)]
    open(sys.argv[1], "w", encoding="utf-8").write(proje_xml(girdi, cikti, prosedurler=pros))
    print("yazıldı:", sys.argv[1])
