#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# v7_uret.py — PEiD userDB + DIE .sg imzalarindan C++ v7 tablolari uretir
# KAYNAKLAR:
#   1. Detect-It-Easy peid_rules/PE/*.userdb.txt  (klasik packer/protector EP imzalari)
#   2. Detect-It-Easy db/PE/*.sg                   (modern EP + bolum-adi + bolum-icerik imzalari)
# CIKTI:
#   src/peid_db.h  — PEiD EP imza tablosu (uretilmis)
#   src/die_db.h   — DIE EP + bolum-icerik + bolum-adi tablolari (uretilmis)
# FORMAT:
#   desen: kucuk-harf hex; '.' = wildcard NIBBLE (yarim bayt); '??' PEiD'de bayt -> '..'
#   DIE '$$' bayt wildcard -> '..'  (DIE: 2 karakter = 1 bayt)
#   DIE '...' dizgi literali 'metin' -> hex'e cevrilir
import os, re, sys, glob

KOK = "/home/z/my-project/work/kaynak2"
DIE = os.path.join(KOK, "horsicq_Detect-It-Easy")
CIKTI = "/home/z/my-project/work/repo_push/src"

HEX = set("0123456789abcdefABCDEF")

# ---------------------------------------------------------------- PEiD ayristirma
def peid_ayristir(yol, kategori):
    """userdb.txt -> [(ad, desen_hex_nibble_wildcard, ep_only)]"""
    girdiler = []
    ad = None
    with open(yol, "r", encoding="utf-8", errors="replace") as f:
        for satir in f:
            s = satir.strip()
            if s.startswith("[") and s.endswith("]"):
                ad = s[1:-1].strip()
            elif s.lower().startswith("signature") and "=" in s and ad:
                hexkismi = s.split("=", 1)[1].strip()
                baytlar = []
                gecerli = True
                for tok in hexkismi.split():
                    if tok == "??":
                        baytlar.append("..")
                    elif tok == "?":
                        baytlar.append(".")   # PEiD yarim-bayt jokeri (nadir)
                    elif len(tok) == 2 and all(c in "0123456789ABCDEFabcdef" for c in tok):
                        baytlar.append(tok.lower())
                    else:
                        gecerli = False
                        break
                if gecerli and baytlar:
                    girdiler.append([ad, "".join(baytlar), None, kategori])
            elif s.lower().startswith("ep_only") and "=" in s and ad:
                val = s.split("=", 1)[1].strip().lower()
                if girdiler and girdiler[-1][0] == ad:
                    girdiler[-1][2] = (val == "true")
    return girdiler

# ---------------------------------------------------------------- DIE .sg ayristirma
SG_META = re.compile(r'meta\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)')
SG_EP = re.compile(r'PE\.compareEP\(\s*"([^"]+)"\s*\)')
SG_SECIN = re.compile(r'PE\.isSignatureInSectionPresent\(\s*(-?\d+)\s*,\s*"([^"]+)"\s*\)')
SG_SECNAME = re.compile(r'PE\.isSectionNamePresent\(\s*"([^"]+)"\s*\)')
SG_STRSEC = re.compile(r'PE\.findString\(')

def die_desen_cevir(p):
    """DIE desen -> bizim nibble-format. 'ab..' 'a$' 'metin' destekli."""
    out = []
    i = 0
    n = len(p)
    while i < n:
        c = p[i]
        if c == "'":                       # dizgi literali
            j = p.find("'", i + 1)
            if j < 0:
                return None
            for ch in p[i + 1:j]:
                out.append("%02x" % ord(ch)) if 32 <= ord(ch) < 127 else None
            i = j + 1
            continue
        if c in ".$":
            out.append(".")                # yarim bayt joker (nibble)
            i += 1
            continue
        if c in "0123456789abcdefABCDEF":
            out.append(c.lower())
            i += 1
            continue
        return None                        # bilinmeyen karakter
    return "".join(out)

def die_ayristir(yol, dosya_adi):
    try:
        metin = open(yol, "r", encoding="utf-8", errors="replace").read()
    except OSError:
        return None
    if "compareEP" not in metin and "isSectionNamePresent" not in metin and \
       "isSignatureInSectionPresent" not in metin:
        return None
    metalar = SG_META.findall(metin)
    if not metalar:
        return None
    kategori, aile = metalar[0][0], metalar[0][1]
    girdi = {"dosya": dosya_adi, "kategori": kategori, "aile": aile,
             "ep": [], "secicerik": [], "secadi": []}
    for m in SG_EP.finditer(metin):
        d = die_desen_cevir(m.group(1))
        if d:
            girdi["ep"].append(d)
    for m in SG_SECIN.finditer(metin):
        d = die_desen_cevir(m.group(2))
        if d:
            girdi["secicerik"].append((int(m.group(1)), d))
    for m in SG_SECNAME.finditer(metin):
        girdi["secadi"].append(m.group(1))
    if not girdi["ep"] and not girdi["secadi"] and not girdi["secicerik"]:
        return None
    return girdi

# ---------------------------------------------------------------- kalite olcutleri
def desen_istatistik(d):
    toplam_nibble = len(d)
    kesin_nibble = sum(1 for c in d if c != ".")
    return toplam_nibble, kesin_nibble   # 2 nibble = 1 bayt

# Heuristik / sahte / derleyici girdileri — GERCEK imza degil, atlanir
YASAKLI_AD = re.compile(r"PseudoSigner|Heuristic|\bfake\b|Fake|detected by|nothing detected|-> nothing", re.I)

def desen_cesitlilik(desen):
    """Somut (joker olmayan) baytlarin FARKLI deger sayisi — 90 90 90... gibi
    dejenerre NOP-kaydirak imzalarini elemek icin (gercek stub >= 3 farkli opcode kullanir)"""
    somut = set()
    for i in range(0, len(desen) - 1, 2):
        h, l = desen[i], desen[i+1]
        if h != "." and l != ".":
            somut.add(h + l)
    return len(somut)

def pei_gecerli_mi(ad, desen, ep_only):
    if YASAKLI_AD.search(ad):
        return False
    tn, kn = desen_istatistik(desen)
    if desen_cesitlilik(desen) < 3:      # dejenerre imza (tek bayt tekrari)
        return False
    # ep imzalari: >= 12 bayt desen VE >= 5 bayt kesin
    if ep_only:
        return tn >= 24 and kn >= 10
    # tam-tarama imzalari: cok daha katı (>= 20 bayt kesin) — yanlis pozitif riski
    return tn >= 40 and kn >= 24

def die_ep_gecerli_mi(desen):
    tn, kn = desen_istatistik(desen)
    if desen_cesitlilik(desen) < 3:
        return False
    return tn >= 16 and kn >= 8

# ---------------------------------------------------------------- ad temizleme
def ad_temizle(ad):
    """PEiD adi -> (aile, surum) 'ASPack 2.12 -> www.aspack.com' seklinde"""
    ad = ad.replace("->", "|")
    parcalar = [p.strip() for p in ad.split("|")]
    ana = parcalar[0]
    # surum: ilk sayi grubu
    m = re.search(r"(\d+\.\d[\w.+*-]*)", ana)
    surum = m.group(1).rstrip(".-") if m else ""
    # aile: surumden onceki kisim
    aile = ana[:m.start()].strip() if m else ana
    aile = re.sub(r"[\[\(].*?[\]\)]", "", aile).strip()
    aile = aile.rstrip(" vV.-_")
    if not aile:
        aile = ana.strip()
    return aile, surum

# ---------------------------------------------------------------- ana akis
def main():
    # 1) PEiD
    peid = []
    for kat in ("packer", "protector", "protection", "joiner"):
        yol = os.path.join(DIE, "peid_rules", "PE", kat + ".userdb.txt")
        peid += peid_ayristir(yol, kat)
    # kalite filtresi + tekil (desen bazli)
    gecen, gorulen_desen = [], set()
    for ad, desen, ep, kat in peid:
        if ep is None:
            ep = False
        if not pei_gecerli_mi(ad, desen, ep):
            continue
        if desen in gorulen_desen:
            continue
        gorulen_desen.add(desen)
        gecen.append((ad, desen, ep, kat))
    ep_kayitlar = [g for g in gecen if g[2]]
    tum_kayitlar = [g for g in gecen if not g[2]]
    print(f"PEiD: {len(peid)} girdi -> {len(ep_kayitlar)} EP + {len(tum_kayitlar)} tam-tarama (kalite filtresi sonrasi)")

    # 2) DIE .sg
    die_girdiler = []
    for yol in sorted(glob.glob(os.path.join(DIE, "db", "PE", "*.sg"))):
        ad = os.path.basename(yol)
        g = die_ayristir(yol, ad)
        if g:
            die_girdiler.append(g)
    print(f"DIE: {len(die_girdiler)} kural dosyasi (EP/bolum imzali)")

    # ---- C++ peid_db.h uret
    def c_desen(d):
        return d  # zaten hex-nibble format

    baslik_peid = ("// ============================================================================\n"
                   "// peid_db.h — OTOMATIK URETIM (v7_uret.py) — DEGISTIRME\n"
                   "// ============================================================================\n"
                   "// KAYNAK: PEiD userDB (Detect-It-Easy peid_rules/PE paketi — klasik imza sozlugu)\n"
                   "//   packer.userdb.txt (992) + protector.userdb.txt (1784) +\n"
                   "//   protection.userdb.txt (943) + joiner.userdb.txt (57)\n"
                   "// LISANS NOTU: PEiD userDB topluluk imza sozlugudur (kamuya acik paylasim).\n"
                   "// FORMAT: hex nibble dizisi; '.' = joker nibble (yarim bayt)\n"
                   "// KALITE: EP imzalari >= 12 bayt desen VE >= 5 bayt kesin bayt;\n"
                   "//         tam-tarama imzalari >= 20 bayt desen VE >= 12 bayt kesin bayt\n"
                   "// ============================================================================")
    satirlar = [baslik_peid]
    satirlar.append("#pragma once")
    satirlar.append("#include <cstdint>")
    satirlar.append("namespace peiddb {")
    satirlar.append("")
    satirlar.append("struct EpImza { const char* ad; const char* aile; const char* surum; const char* desen; };")
    satirlar.append("")
    satirlar.append("// ---- EP (giris noktasi) imzalari — %d adet" % len(ep_kayitlar))
    satirlar.append("static const EpImza EP_TABLO[] = {")
    for ad, desen, ep, kat in ep_kayitlar:
        aile, surum = ad_temizle(ad)
        tam_ad = ad.replace("\\", "\\\\").replace('"', "'")
        satirlar.append('    { "%s", "%s", "%s", "%s" },' % (tam_ad, aile.replace('"', "'"), surum.replace('"', "'"), c_desen(desen)))
    satirlar.append("};")
    satirlar.append("static const int EP_TABLO_ADET = sizeof(EP_TABLO) / sizeof(EP_TABLO[0]);")
    satirlar.append("")
    satirlar.append("// ---- tam-tarama imzalari (yalniz EP-bolumu + standart-disi bolumlerde aranir) — %d adet" % len(tum_kayitlar))
    satirlar.append("static const EpImza TUM_TABLO[] = {")
    for ad, desen, ep, kat in tum_kayitlar:
        aile, surum = ad_temizle(ad)
        tam_ad = ad.replace("\\", "\\\\").replace('"', "'")
        satirlar.append('    { "%s", "%s", "%s", "%s" },' % (tam_ad, aile.replace('"', "'"), surum.replace('"', "'"), c_desen(desen)))
    satirlar.append("};")
    satirlar.append("static const int TUM_TABLO_ADET = sizeof(TUM_TABLO) / sizeof(TUM_TABLO[0]);")
    satirlar.append("")
    satirlar.append("} // namespace peiddb")
    with open(os.path.join(CIKTI, "peid_db.h"), "w") as f:
        f.write("\n".join(satirlar) + "\n")
    print("peid_db.h yazildi")

    # ---- C++ die_db.h uret
    baslik_die = ("// ============================================================================\n"
                  "// die_db.h — OTOMATIK URETIM (v7_uret.py) — DEGISTIRME\n"
                  "// ============================================================================\n"
                  "// KAYNAK: Detect It Easy imza kurallari (horsicq/Detect-It-Easy db/PE/*.sg)\n"
                  "//   https://github.com/horsicq/Detect-It-Easy — MIT lisansli acik kaynak\n"
                  "// ICERIK: modern packer/protector EP imzalari (compareEP), bolum-icerik\n"
                  "//   imzalari (isSignatureInSectionPresent), bolum-adi kontrolleri\n"
                  "// ============================================================================")
    satirlar = [baslik_die]
    satirlar.append("#pragma once")
    satirlar.append("#include <cstdint>")
    satirlar.append("namespace diedb {")
    satirlar.append("")
    satirlar.append("struct EpImza { const char* aile; const char* kategori; const char* desen; };")
    satirlar.append("struct IcerikImza { const char* aile; const char* kategori; int bolum_idx; const char* desen; };")
    satirlar.append("")
    ep_sayi, ic_sayi, ad_sayi = 0, 0, 0
    ep_satir, ic_satir, ad_satir = [], [], []
    for g in die_girdiler:
        gorulen = set()
        for d in g["ep"]:
            if not die_ep_gecerli_mi(d) or d in gorulen:
                continue
            gorulen.add(d)
            aile = g["aile"].replace('"', "'")
            kat = g["kategori"].replace('"', "'")
            ep_satir.append('    { "%s", "%s", "%s" },' % (aile, kat, d))
            ep_sayi += 1
        gorulen = set()
        for idx, d in g["secicerik"]:
            tn, kn = desen_istatistik(d)
            if tn < 24 or kn < 12 or d in gorulen:
                continue
            gorulen.add(d)
            aile = g["aile"].replace('"', "'")
            kat = g["kategori"].replace('"', "'")
            ic_satir.append('    { "%s", "%s", %d, "%s" },' % (aile, kat, idx, d))
            ic_sayi += 1
        for ad_ in sorted(set(g["secadi"])):
            if 1 <= len(ad_) <= 8:
                aile = g["aile"].replace('"', "'")
                kat = g["kategori"].replace('"', "'")
                ad_satir.append('    { "%s", "%s", "%s" },' % (aile, kat, ad_))
                ad_sayi += 1
    satirlar.append("// ---- EP imzalari (compareEP) — %d adet" % ep_sayi)
    satirlar.append("static const EpImza EP_TABLO[] = {")
    satirlar += ep_satir
    satirlar.append("};")
    satirlar.append("static const int EP_TABLO_ADET = sizeof(EP_TABLO) / sizeof(EP_TABLO[0]);")
    satirlar.append("")
    satirlar.append("// ---- bolum-icerik imzalari — %d adet" % ic_sayi)
    satirlar.append("static const IcerikImza ICERIK_TABLO[] = {")
    satirlar += ic_satir
    satirlar.append("};")
    satirlar.append("static const int ICERIK_TABLO_ADET = sizeof(ICERIK_TABLO) / sizeof(ICERIK_TABLO[0]);")
    satirlar.append("")
    satirlar.append("// ---- bolum-adi kontrolleri — %d adet (aile icin destek kaniti)" % ad_sayi)
    satirlar.append("struct AdImza { const char* aile; const char* kategori; const char* bolum; };")
    satirlar.append("static const AdImza AD_TABLO[] = {")
    satirlar += ad_satir
    satirlar.append("};")
    satirlar.append("static const int AD_TABLO_ADET = sizeof(AD_TABLO) / sizeof(AD_TABLO[0]);")
    satirlar.append("")
    satirlar.append("} // namespace diedb")
    with open(os.path.join(CIKTI, "die_db.h"), "w") as f:
        f.write("\n".join(satirlar) + "\n")
    print(f"die_db.h yazildi: {ep_sayi} EP + {ic_sayi} icerik + {ad_sayi} bolum-adi")

if __name__ == "__main__":
    main()
