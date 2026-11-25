#!/usr/bin/env python3
# sahte_imza_test.py — obfus.h FAKE_SIGNATURES davranisini simule eden PE'ler uret
# ve evrensel motorun SAHTE DEMET kuralini dogrula.
# Ayrica: es3n1n (.s_code+.s_rel), Ryujin (.Ryujin), Nocturne (.vmpm) bolum testleri.
import struct, shutil, os, subprocess

SRC = "/home/z/my-project/upload/orijinal/Test_64.exe"   # 3 bolumlu temiz PE
OUT = "/tmp/evren_test_pe"
os.makedirs(OUT, exist_ok=True)

def bolumleri_yaz(src, yeni_adlar, hedef):
    """PE bolum ADLARINI yeniden adlandir (yapisal her sey ayni kalir)."""
    d = bytearray(open(src, "rb").read())
    e = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, e+6)[0]
    opt = struct.unpack_from("<H", d, e+20)[0]
    so = e + 24 + opt
    for i in range(nsec):
        ad = yeni_adlar[i].encode() if i < len(yeni_adlar) else b""
        ad = ad[:8].ljust(8, b"\x00")
        d[so+i*40:so+i*40+8] = ad
    open(hedef, "wb").write(bytes(d))

def tara(f):
    r = subprocess.run(["/tmp/vmpdet6_test", "--evren", f], capture_output=True, text=True)
    return r.stdout

# 1) obfus.h FAKE_SIGNATURES demeti: .themida + .vmp0/.vmp1/.vmp2 + .enigma1/.enigma2 + UPX0
bolumleri_yaz(SRC, [".themida", ".vmp0", ".vmp1", ".vmp2", ".enigma1", ".enigma2", "UPX0"], f"{OUT}/sahte_demet.exe")
# 2) GERCEK VMProtect: .vmp0 + .vmp1 (ayni uretici — demet olmamali)
bolumleri_yaz(SRC, [".text", ".rdata", ".vmp0", ".vmp1"], f"{OUT}/gercek_vmp_bolum.exe")
# 3) es3n1n: .s_code + .s_rel
bolumleri_yaz(SRC, [".s_code", ".s_rel", ".data", ".idata"], f"{OUT}/es3n1n.exe")
# 4) Ryujin: .Ryujin
bolumleri_yaz(SRC, [".text", ".Ryujin", ".rdata", ".idata"], f"{OUT}/ryujin.exe")
# 5) Nocturne: .vmpm + .nctrn
bolumleri_yaz(SRC, [".text", ".vmpm", ".nctrn", ".idata"], f"{OUT}/nocturne.exe")
# 6) TinyLoad: .pxkey
bolumleri_yaz(SRC, [".text", ".pxkey", ".rdata", ".idata"], f"{OUT}/tinyload.exe")
# 7) obfus.h gercek modu: .obfh
bolumleri_yaz(SRC, [".obfh", ".text", ".rdata", ".idata"], f"{OUT}/obfh.exe")

tests = {
    "sahte_demet.exe": ["SAHTE IMZA MODU", "obfus.h"],
    "gercek_vmp_bolum.exe": ["VMProtect"],
    "es3n1n.exe": ["es3n1n/obfuscator"],
    "ryujin.exe": ["Ryujin"],
    "nocturne.exe": ["Nocturne"],
    "tinyload.exe": ["TinyLoad"],
    "obfh.exe": ["obfus.h"],
}
tam, kismi = 0, 0
for f, beklenen in tests.items():
    cikti = tara(f"{OUT}/{f}")
    satirlar = [l for l in cikti.splitlines() if any(k in l for k in ("EVREN", "Packer", "VMProtect:", "Kanit"))]
    vur = all(any(b in l for l in satirlar) for b in beklenen)
    durum = "PASS" if vur else "FAIL"
    if vur: tam += 1
    print(f"[{durum}] {f:26} beklenen={beklenen}")
    for l in satirlar[:4]: print("      ", l.strip()[:100])
print(f"\n{tam}/{len(tests)} gecti")
