#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""net_ornek_uret.py — .NET motoru icin sentetik (yapisal olarak gecerli) ornekler
URETIR: ornekler/evren/ altina 3 dosya:
  net_confuserex_sentetik.exe  — ConfusedByAttribute + KoiVM + 'ConfuserEx v9.9.9' damgasi
  net_babel_sentetik.exe       — 'Babel' metadata stream'i
  net_reactor_sentetik.exe     — NecroVM.Runtime + UTF-16 'is tampered.'
Yapi: minimal PE32 + CLI header (veri_dizin[14]) + BSJB metadata root + stream'ler.
Motor bunlari parse edip aileyi SOYLEMELI (ConfuserEx / Babel / .NET Reactor).
"""
import struct, os

CIKTI = "/home/z/my-project/work/repo_push/ornekler/evren"

def pe_uret(streamler, dosya_adi):
    """streamler: [(stream_adi, icerik)] — #Strings/#Blob/#US + ozel stream'ler"""
    # ECMA-335 II.24.2.1: surum dizgisi alani 4 bayta yuvarlanir
    surum = b"v4.0.30319\x00\x00"
    while len(surum) % 4:
        surum += b"\x00"
    ver_alan = len(surum)
    # stream icerikleri
    meta_blob = b"".join(i for _, i in streamler)
    # metadata root: sig+maj+min+reserved+len+version+flags+nstreams
    kok = struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(surum)) + surum
    kok += struct.pack("<HH", 0, len(streamler))  # flags, nstreams
    # stream basliklari: offset(meta kokten itibaren) + size + name\0 (4-hiza)
    ofset = len(kok)
    basliklar = b""
    konumlar = []
    for ad, icerik in streamler:
        konumlar.append(ofset + len(basliklar) + len(streamler) * 0)  # asagida duzeltilecek
    # baslik boyutunu once hesapla (iki gecis)
    def baslik_yaz(offsets):
        b = b""
        for (ad, icerik), ofs in zip(streamler, offsets):
            b += struct.pack("<II", ofs, len(icerik)) + ad.encode() + b"\x00"
            while len(b) % 4:
                b += b"\x00"
        return b
    # kok + basliklar sonrasi veri baslangici
    proto = baslik_yaz([0] * len(streamler))
    veri_baslangic = len(kok) + len(proto)
    ofsetler, cur = [], 0
    for ad, icerik in streamler:
        ofsetler.append(veri_baslangic + cur)
        cur += len(icerik)
    basliklar = baslik_yaz(ofsetler)
    assert len(basliklar) == len(proto)
    metadata = kok + basliklar + meta_blob

    # --- CLI header: cb, maj, min, MetaData RVA, MetaData Size, Flags, EntryPointToken
    CLI_RVA = 0x2000           # bolum icinde CLI basliginin RVA'si
    cli = struct.pack("<IHHIIII", 0x48, 2, 5, 0xDEADBEEF, len(metadata), 1, 0)
    cli += struct.pack("<II", 0, 0)          # Resources, StrongName
    cli += struct.pack("<II", 0, 0) * 2      # CodeManager, VTableFixups
    cli += struct.pack("<II", 0, 0) * 2      # ExportAddr, NativeEntry
    cli += struct.pack("<II", 0, 0)          # Cookie ayrimi (72 bayta tamamla)
    assert len(cli) == 72, len(cli)
    META_RVA = CLI_RVA + len(cli)
    cli = bytearray(cli)
    struct.pack_into("<I", cli, 8, META_RVA)   # MetaData RVA'yi gercek degerle yaz
    cli = bytes(cli)

    # --- bolum icerigi: gercege yakin stub kod (0x1000) + CLI + metadata
    # NOT: NOP-kaydirak DEGIL — PEiD dejenerre imzalarinin yanlis pozitifini
    # onlemek icin ayirt edici baytli mini stub
    stub = b"\x31\xC0\x31\xDB\x31\xC9\x31\xD2\x64\xA1\x30\x00\x00\x00\x8B\x40\x0C\xC3"
    stub += b"\xCC" * (0x1000 - len(stub))
    bolum_veri = stub + cli + metadata
    VA = 0x1000
    RAW = 0x400

    # --- PE32 iskeleti (DOGRU optional header — 224 bayt)
    dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x80) + b"\x00" * 0x40
    nt_sig = struct.pack("<I", 0x4550)
    file_hdr = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x2102)
    # standard (28) + windows (68) alanlari:
    opt = struct.pack("<HBB", 0x10B, 14, 0)
    opt += struct.pack("<III", 0x200, 0x200, 0)          # SizeOfCode/Data/Uninit
    opt += struct.pack("<III", 0x1000, 0x1000, 0x1000)   # EP, BaseOfCode, BaseOfData
    opt += struct.pack("<III", 0x400000, 0x1000, 0x200)  # ImageBase, SectAlign, FileAlign
    opt += struct.pack("<HHHHHH", 4, 0, 0, 0, 4, 0)      # OS/Image/Subsys versions
    opt += struct.pack("<I", 0)                            # Win32Version
    opt += struct.pack("<III", 0x3000, 0x400, 0)          # SizeOfImage/Headers/CheckSum
    opt += struct.pack("<HH", 3, 0)                        # Subsystem, DllCharacteristics
    opt += struct.pack("<IIII", 0x100000, 0x1000, 0x100000, 0x1000)  # Stack/Heap
    opt += struct.pack("<II", 0, 16)                       # LoaderFlags, NumberOfRvaAndSizes
    assert len(opt) == 96, len(opt)
    # data dizinleri (16 adet) — 14: CLI header
    dizinler = b"\x00" * 8 * 14
    dizinler += struct.pack("<II", CLI_RVA, len(cli))
    dizinler += b"\x00" * 8
    opt += dizinler
    assert len(opt) == 224

    bolum = b".text\x00\x00\x00" + struct.pack("<IIIIIIHHI",
        len(bolum_veri), VA, len(bolum_veri), RAW, 0, 0, 0, 0, 0x60000020)
    baslik = dos + nt_sig + file_hdr + opt + bolum
    while len(baslik) < RAW:
        baslik += b"\x00"
    pe = baslik + bolum_veri

    yol = os.path.join(CIKTI, dosya_adi)
    with open(yol, "wb") as f:
        f.write(pe)
    print(f"{dosya_adi}: {len(pe)} bayt — CLI@RVA 0x{CLI_RVA:X}, meta@RVA 0x{META_RVA:X}")

os.makedirs(CIKTI, exist_ok=True)

# 1) ConfuserEx: #Strings'te tip adi + metadata bolgesinde surum damgasi
strings = b"\x00" + b"ConfusedByAttribute\x00" + b"KoiVM\x00" + b"VMEntryRun\x00" + b"<Module>\x00"
blob = b"\x00ConfuserEx v9.9.9\x00"
pe_uret([("#Strings", strings), ("#Blob", blob), ("#~", b"\x00" * 64)],
        "net_confuserex_sentetik.exe")

# 2) Babel: 'Babel' metadata stream
strings2 = b"\x00" + b"<Module>\x00"
pe_uret([("#Strings", strings2), ("Babel", b"\x01\x02\x03\x04"), ("#~", b"\x00" * 64)],
        "net_babel_sentetik.exe")

# 3) .NET Reactor: NecroVM.Runtime tip adi + UTF-16 'is tampered.'
strings3 = b"\x00" + b"NecroVM.Runtime\x00" + b"$method0x6000123-1\x00" + b"<Module>\x00"
us3 = b"\x00" + "is tampered.".encode("utf-16-le") + b"\x00\x00"
pe_uret([("#Strings", strings3), ("#US", us3), ("#~", b"\x00" * 64)],
        "net_reactor_sentetik.exe")

print("OK — .NET sentetik ornekleri uretildi")
