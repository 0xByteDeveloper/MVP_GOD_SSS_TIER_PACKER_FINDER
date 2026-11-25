#!/usr/bin/env python3
# upx_iznik_cikar.py — UPX orneklerinden GERCEK imzalarini cikarir (bolumler, UPX! basligi, identstr, stub)
import struct, os, json

D = "/home/z/my-project/work/kaynak/upx_ornek"
res = {}

def pe_info(path):
    d = open(path, "rb").read()
    e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
    assert d[e_lfanew:e_lfanew+4] == b"PE\x00\x00"
    machine, nsec = struct.unpack_from("<HH", d, e_lfanew+4)[0], struct.unpack_from("<H", d, e_lfanew+6)[0]
    opt_size = struct.unpack_from("<H", d, e_lfanew+20)[0]
    ep = struct.unpack_from("<I", d, e_lfanew+40)[0]
    sec_off = e_lfanew + 24 + opt_size
    secs = []
    for i in range(nsec):
        off = sec_off + i*40
        name = d[off:off+8].rstrip(b"\x00").decode("latin1")
        vsz, vaddr, rsz, rptr = struct.unpack_from("<IIII", d, off+8)
        chars = struct.unpack_from("<I", d, off+36)[0]
        secs.append({"name": name, "vsz": vsz, "vaddr": vaddr, "rsz": rsz, "rptr": rptr, "chars": hex(chars)})
    return d, {"machine": hex(machine), "ep_rva": hex(ep), "sections": secs}

for fn in sorted(os.listdir(D)):
    if not fn.startswith(("t32_", "t64_")):
        continue
    p = os.path.join(D, fn)
    d, info = pe_info(p)
    # UPX! packheader ara (son bolumde, sondan 32 byte'dan geriye dogru en fazla 512)
    hits = []
    start = max(0, len(d) - 8192)
    idx = d.find(b"UPX!", start)
    while idx != -1 and idx < len(d):
        hits.append(idx)
        idx = d.find(b"UPX!", idx+1)
    # identstr banner
    banner = b"$Info: This file is packed with the UPX executable packer"
    bidx = d.find(banner)
    bstr = None
    if bidx >= 0:
        end = d.find(b"\x00", bidx)
        bstr = d[bidx:end].decode("latin1", "replace")
    # UPX! baslik alanini cozumle (32 byte EXE formati)
    ph = None
    for h in hits:
        if h + 32 <= len(d):
            ver, fmt, method, level = d[h+4], d[h+5], d[h+6], d[h+7]
            uadler, cadler = struct.unpack_from("<II", d, h+8)
            ulen = int.from_bytes(d[h+16:h+19], "little")
            clen = int.from_bytes(d[h+19:h+22], "little")
            osize = int.from_bytes(d[h+22:h+25], "little")
            filt, cto = d[h+25], d[h+26]
            ph = {"offset": h, "version": ver, "format": fmt, "method": method,
                  "level": level, "uadler32": hex(uadler), "cadler32": hex(cadler),
                  "ulen": ulen, "clen": clen, "orig_size": osize, "filter": filt, "cto": cto}
            break
    res[fn] = {"pe": info, "upx_header": ph, "banner": bstr,
               "upx_magic_hits": hits[:6], "filesize": len(d)}

print(json.dumps(res["t32_nrv2b.exe"], indent=1)[:1200])
print("\n=== TUM ORNEKLER ===")
for fn, r in res.items():
    ph = r["upx_header"]
    print(f"{fn:20} EP={r['pe']['ep_rva']:>8} secs={[s['name'] for s in r['pe']['sections']]} "
          f"UPX!@{[hex(x) for x in r['upx_magic_hits']]} v{ph['version'] if ph else '?'} m={ph['method'] if ph else '?'}")
json.dump(res, open("/home/z/my-project/work/kaynak/tarama/upx_gercek_ciktilar.json", "w"), indent=1)
print("\nOK -> work/kaynak/tarama/upx_gercek_ciktilar.json")
