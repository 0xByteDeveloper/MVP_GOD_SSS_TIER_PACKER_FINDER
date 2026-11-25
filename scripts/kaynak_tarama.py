#!/usr/bin/env python3
"""
kaynak_tarama.py — Otomatik kaynak-kodu tarayici:
Her open-source packer'in KAYNAGINDAN deterministik PE izlerini cikarir.
Cikti: work/kaynak/tarama/<packer>.json + ozet tablo.

Taranan iz siniflari:
  S1 bolum isimleri (section names) — 8 byte PE section name literals
  S2 sihirli baytlar / marker stringler (magic, banner, version)
  S3 stub G/CDATA byte dizileri (entry-point stub pattern)
  S4 sifreleme/sikistirma sabitleri (LZMA props, RC4, ChaCha, AES SBOX, CRC tablo...)
  S5 stub import karakteri (VirtualAlloc/LoadLibrary zinciri)
"""
import os, re, json, hashlib

BASE = "/home/z/my-project/work/kaynak/packers"
VMP  = "/home/z/my-project/work/kaynak/vmp351/Allver_Collection/VMProtect 3.5.1 [Source Code]"
OUT  = "/home/z/my-project/work/kaynak/tarama"
os.makedirs(OUT, exist_ok=True)

SRC_EXT = (".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".hh", ".asm", ".s",
           ".py", ".rs", ".nim", ".cs", ".java", ".kt", ".go", ".inc", ".inl",
           ".vb", ".ts", ".dpr", ".pas", ".js", ".nimble")

# --- S1: bolum adi adaylari — bilinen packer bolum sozlugu + jenerik desen
KNOWN_SECTIONS = [
    "UPX0", "UPX1", "UPX2", "UPX!", ".vmp0", ".vmp1", ".vmp2", "vmp0", "vmp1", "vmp2",
    ".themida", "Themida", ".taggant", ".aspack", ".aspack1", "ASPack",
    ".adata", ".asdata", ".enigma1", ".enigma2", ".enigmap", ".MPRESS1", ".MPRESS2",
    ".nsp0", ".nsp1", ".nsp2", "nsp0", "nsp1", "MEW", ".mew", ".fsg", "FSG!",
    ".petite", ".pencrypt", ".pebundle", ".peres", ".pesect", ".Upack", "UPX3",
    ".taz", ".ccg", ".tsuarch", ".tsustub", ".sparse", ".petite",
    ".RLPack", ".rmnet", "rnp", ".sforce", ".sfx", ".svkp", ".tlock",
    ".UPX0", ".UPX1", ".UPX2", ".textb", ".themidac", "WinLic", ".mnbvcx",
    ".perplex", ".seau", ".spack", ".seau", "aspack", "PEBundle",
    ".bss", ".ndata", ".itext", ".idata2", ".pelock", ".psvkp",
    ".vmp", ".cvp", ".cvirt", ".reactor", ".netreactor", "React",
    ".asprotect", ".aspr", ".aspr1", ".aspr2", "ASPR", ".safengine",
    ".sedata", ".sense", "SEnsE", ".dyamar", ".dycrypt", ".eskf",
    ".mta1", ".mta2", "MTa", ".pklst", ".sforce",
    "kagura", ".kagura", ".obf", ".obf1", ".binprotect", ".binb",
    ".ryujin", "Ryujin", ".es3n1n", ".chum", ".nocturne", ".pep", ".yap",
    ".tinyl", ".tinyl1", ".tl0", ".tl1", ".x0rro", ".grey", ".krypto",
    ".ncrypt", ".nova", ".obsid", ".alush", ".hxor", ".PELOCK", "PELock",
    "CODE", "DATA", "BSS", "idata", "edata", "rsrc", "reloc", ".tls",
    ".text", ".data", ".rdata", ".bss", "DGROUP", ".CRT", ".tls",
]
SECTION_HINT_RE = re.compile(
    r'(?:section|Section|SECTION|Name|name|seg|Seg)[^\n]{0,40}?["\'](\.[A-Za-z0-9_]{1,7}|UPX[0-9!]|[A-Za-z]{2,7}[0-9])["\']')

# --- S2: sihirli stringler
MAGIC_STRINGS = [
    "UPX!", "UPX0", "UPX1", "UPX2", "UPX 3.", "$Info: This file is packed with the UPX",
    "MEI\x0c", "PyInstaller", "pyi-", "_MEIPASS", "python3", "PYZ-00.pyz",
    "VMProtect begin", "VMProtect end", "vmprotect", "VMProtect",
    "This file is packed with the UPX executable packer",
    "Themida", "WinLicense", "SecureEngine",
    "Enigma Protector", "Enigma protector", "The Enigma Protector",
    "ConfuserEx", "confuserex", "ConfusedByAttribute",
    "KoiVM", "koivm",
    "ProGuard", "proguard", "Kotlin.Metadata",
    "pyarmor", "PyArmor", "__pyarmor__",
    "Nuitka", "__compiled__",
    "NSIS", "Nullsoft", "Inno Setup", "7-Zip", "RAR!", "PK\x03\x04",
    "LZMA", "lzma", "lzma_alone", "7zXZ", "XZ_",
    "aPLib", "aplib", "aPL32",
    "MPRESS", "MPress",
    "MoleBox", "molebox", "MOLEBOX",
    "Obsidium", "ASProtect", "ASProtect32",
    "Execryptor", "EXECryptor",
    "StarForce", "SFCL", "SecuROM", "SafeDisc",
    "Denuvo",
    "Steam", "SteamAPI", "CEG",
    "batchtoapp", "BatchToApp", "DosX", "obfus.h", "obfusheader",
    "es3n1n", "Astral-PE", "ASM-Guard", "TinyLoad", "BinProtect",
    "KiteShield", "kiteshield", "maya", "x0rro", "chum", "GreyM", "nimcrypt",
    "NullCrypt", "Ryujin", "Kryptonite", "PE-Crypter", "hXOR",
    "Zhao", "zhidun", "NovaProtect", "Xop", "Kagura", "Nocturne",
    "movfuscator", "tigress", "Tigress",
]

# --- S4: kripto sabitleri
CRYPTO_CONSTS = {
    "chacha20": [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, "expand 32-byte k"],
    "blake2s": [0x6A09E667, 0xBB67AE85],
    "sha256": [0x6a09e667, 0x428a2f98, 0x71374491],
    "sha1":   [0x67452301, 0xEFCDAB89],
    "md5":    [0x67452301, 0xefcdab89, 0x98badcfe],
    "crc32":  [0xEDB88320, 0x04C11DB7],
    "lzma_props": [0x5d, 0x00, 0x00],  # lc/lp/pb + dictsize 0x0000...
    "lzma_alone_magic": [0x5D, 0x00, 0x00, 0x80, 0x00],
    "zstd_magic": [0x28, 0xB5, 0x2F, 0xFD],
    "lz4_magic": [0x04, 0x22, 0x4D, 0x18],
    "rc4_hint": ["rc4", "RC4", "arc4", "ARC4"],
    "aes_sbox": [0x63, 0x7c, 0x77, 0x7b],
    "xor_keys_generic": None,
}

def repo_files(root, limit=900):
    files = []
    for dp, dns, fns in os.walk(root):
        if "/.git" in dp or "/.vs" in dp or "/node_modules" in dp:
            continue
        for fn in fns:
            if fn.endswith(SRC_EXT):
                files.append(os.path.join(dp, fn))
    return files[:limit]

def read(p, maxb=2_000_000):
    try:
        with open(p, "rb") as f:
            return f.read(maxb)
    except Exception:
        return b""

def scan_repo(name, root):
    res = {"packer": name, "root": root, "sections": {}, "magics": {}, "crypto": {},
           "stub_hints": {}, "ep_markers": [], "file_count": 0, "notable_files": []}
    files = repo_files(root)
    res["file_count"] = len(files)
    for p in files:
        data = read(p)
        if not data:
            continue
        try:
            text = data.decode("utf-8", "ignore")
        except Exception:
            continue
        rel = os.path.relpath(p, root)
        low = text.lower()
        # S1: sections
        for sec in KNOWN_SECTIONS:
            if len(sec) >= 4 and sec in text:
                # kaba kontekst filtresi: bolum set eden satirlar
                for m in re.finditer(re.escape(sec), text):
                    line_start = text.rfind("\n", 0, m.start()) + 1
                    line = text[line_start:text.find("\n", m.start())]
                    if re.search(r'(name|section|memcpy|strcpy|set|push|db|mov|"[^"]*")', line, re.I):
                        key = sec
                        res["sections"].setdefault(key, [])
                        if len(res["sections"][key]) < 8:
                            res["sections"][key].append(f"{rel}:{line.strip()[:110]}")
                        break
        # S1b: dinamik bolum adi literals
        for m in SECTION_HINT_RE.finditer(text):
            cand = m.group(1)
            if 3 <= len(cand) <= 8 and not cand.lower() in ("section", "segment"):
                res["sections"].setdefault(cand, [])
                if len(res["sections"][cand]) < 5:
                    line_start = text.rfind("\n", 0, m.start()) + 1
                    line = text[line_start:text.find("\n", m.start())]
                    res["sections"][cand].append(f"{rel}:{line.strip()[:110]}")
        # S2: magic strings
        for mg in MAGIC_STRINGS:
            if mg in text:
                res["magics"].setdefault(mg, [])
                if len(res["magics"][mg]) < 4:
                    idx = low.find(mg.lower())
                    line_start = text.rfind("\n", 0, idx) + 1
                    line = text[line_start:text.find("\n", idx)]
                    res["magics"][mg].append(f"{rel}:{line.strip()[:110]}")
        # S4: crypto constants
        for cname, consts in CRYPTO_CONSTS.items():
            if consts is None:
                continue
            for c in consts:
                hit = None
                if isinstance(c, str):
                    if c in text:
                        hit = c
                else:
                    for hexfmt in (hex(c), "0x%08X" % c, "0x%08x" % c, "0x%X" % c, str(c)):
                        if hexfmt in text:
                            hit = hexfmt
                            break
                if hit:
                    res["crypto"].setdefault(cname, [])
                    if len(res["crypto"][cname]) < 4:
                        res["crypto"][cname].append(f"{rel}:{hit}")
        # S3/S5: stub ipuclari — byte dizileri ve loader API zinciri
        if re.search(r'(VirtualAlloc\s*\(|LoadLibraryA\s*\(|GetProcAddress\s*\()', text) and \
           re.search(r'(decrypt|decompress|unpack|stub|loader|loader)', low):
            apis = sorted(set(re.findall(r'(VirtualAlloc\w*|VirtualProtect\w*|LoadLibrary\w*|GetProcAddress|CreateProcess\w*|NtUnmapViewOfSections|IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess)', text)))
            if apis:
                res["stub_hints"][rel] = apis[:10]
        # EP pattern: entry point secen kod
        if re.search(r'(AddressOfEntryPoint|e_lfanew|IMAGE_FIRST_SECTION)', text):
            res["ep_markers"].append(rel)
            if len(res["ep_markers"]) < 12:
                pass
    return res

TARGETS = {}
for d in sorted(os.listdir(BASE)):
    full = os.path.join(BASE, d)
    if os.path.isdir(full):
        TARGETS[d] = full
TARGETS["vmp-3.5.1-src"] = VMP

summary = []
for name, root in TARGETS.items():
    try:
        r = scan_repo(name, root)
        with open(os.path.join(OUT, f"{name}.json"), "w") as f:
            json.dump(r, f, indent=1, ensure_ascii=False)
        summary.append((name, r["file_count"], len(r["sections"]), len(r["magics"]),
                        len(r["crypto"]), len(r["stub_hints"])))
    except Exception as e:
        summary.append((name, f"ERR {e}", 0, 0, 0, 0))

print(f"{'PACKER':28} {'FILES':>5} {'SEC':>4} {'MAG':>4} {'CRP':>4} {'STUB':>4}")
for row in summary:
    print(f"{row[0]:28} {row[1]:>5} {row[2]:>4} {row[3]:>4} {row[4]:>4} {row[5]:>4}")
