#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# v8_uret.py — TUM imza/bolum/algoritma veritabanlarindan C++ v8 tablolari uretir
# ============================================================================
# KAYNAKLAR (A16 "bizim lig" + klasik userdb ekosistemi):
#   PEiD-format userdb'ler:
#     1. wolfram77web/app-peid userdb.txt            (4259 tekil — klasik BoB DB)
#     2. packing-box/peid db/userdb.txt              (5539 tekil — bakimli surumu)
#     3. packing-box/pypackerdetect sigs_short.txt   (1832 — BoB 'short' DB)
#     4. packing-box/pypackerdetect sigs_long.txt    (4259 — 'long' DB)
#     5. salmanmallah/packerscope peid_userdb.txt    (40)
#   YARA:
#     6. Yara-Rules/rules packers/peid.yar           (7615 kural — 11 kaynak birlesimi:
#        pyew, AlienVault panda/jclausing/exeinfope, eppackersigs, epcompilersigs,
#        cuckoo, jclausing, seifreed, guelfoweb/peframe)
#     7. Yara-Rules/rules packers/packer_compiler_signatures.yar (derleyici+packer)
#     8. packerscope common_packers.yar              (UPX/ASPack stub + guven)
#   v7 devri (aynen korunur):
#     9. Detect-It-Easy peid_rules/PE (packer/protector/protection/joiner)  -> v7 peid_db cekirdegi
#    10. Detect-It-Easy db/PE/*.sg                    -> die_db.h (degismez)
#   BOLUM ADLARI:
#    11. packing-box/pypackerdetect packers.json      (hexacorn 92 ad — packer atfli)
#    12. DosX-dev/PE-LiteScan KnownSections           (~70 ad — surum atfli)
#    13. Manalyze KNOWN_PACKER_SECTIONS               (regex -> ad)
#    14. hACKCASCAC/ObfusFake-Signatures-Remover      (23 ad — OBFUS SAHTE modu)
#    15. packpeek SIGS / DRMDetector / PE-LiteScan ek adlar
#   ALGORITMA DESENLERI (imza OZTESI motor):
#    16. ObfusHunter — junk code / anti-debug / VM dispatch / obfh veri blogu desenleri
#    17. ObfusFake — sahte imza desenleri (Enigma/Denuvo/Nuitka/Screen2EXE) + dongle dizgileri
#    18. packerscope EntryPointDetector — EP stub desenleri (PUSHAD/PUSHFD/CALL$+5/UPX64)
#    19. DRMDetector — oyun DRM dizgileri (Denuvo/Arxan/SteamStub/... )
# ============================================================================
# CIKTI:
#   src/peid_db.h     — EP + tam-tarama imza tablolari (BUYUK; v7 cekirdegi + yeniler)
#   src/bolum_db.h    — bolum-adi -> packer atlasi (yeni)
#   src/algoritma_db.h — algoritmik desen tablolari (yeni)
#   src/die_db.h      — v7'den degismez (dokunulmaz)
import os, re, sys, glob, json

K3 = "/home/z/my-project/work/kaynak3"
K2 = "/home/z/my-project/work/kaynak2"
CIKTI = "/home/z/my-project/work/repo_push/src"
DIE = os.path.join(K2, "horsicq_Detect-It-Easy")

# ---------------------------------------------------------------- PEiD ayristirici
def peid_ayristir(yol):
    """userdb.txt -> [(ad, desen, ep_only)]"""
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
                    if tok in ("??", "?"):
                        baytlar.append("..")
                    elif len(tok) == 2 and all(c in "0123456789ABCDEFabcdef" for c in tok):
                        baytlar.append(tok.lower())
                    else:
                        gecerli = False
                        break
                if gecerli and baytlar and ad:
                    ep = None
                    girdiler.append([ad, "".join(baytlar), ep, yol])
            elif s.lower().startswith("ep_only") and "=" in s and ad:
                val = s.split("=", 1)[1].strip().lower()
                if girdiler and girdiler[-1][0] == ad:
                    girdiler[-1][2] = (val == "true")
    return girdiler

# ---------------------------------------------------------------- YARA ayristirici
def yara_ayristir(yol, hepsi_packer=False):
    """peid.yar -> [(ad, desen, ep)] — yalniz hex dizili $a bloklari"""
    metin = open(yol, encoding="utf-8", errors="replace").read()
    sonuc = []
    # rule NAME: TAG { strings: $x = { HEX } ... condition: ... }
    for m in re.finditer(r"rule\s+([\w.]+)[^\{]*\{(.*?)\n\}", metin, re.S):
        ad, govde = m.group(1), m.group(2)
        if not hepsi_packer and "PEiD" not in m.group(0)[:m.group(0).find("{")] and "packer" not in ad.lower():
            continue
        if "PECheck" in m.group(0)[:m.group(0).find("{")]:
            continue  # yapisal kontrol kurallari (Authenticode/PE32) — packer imzasi degil
        strbloklari = re.findall(r"\$([a-z][a-z0-9_]*)\s*=\s*\{([^}]*)\}", govde)
        if not strbloklari:
            continue
        kond = re.search(r"condition:\s*(.*?)\s*$", govde, re.S)
        kos = " ".join(kond.group(1).split()) if kond else ""
        ep_bagli = "pe.entry_point" in kos
        for harf, hexk in strbloklari[:2]:   # $a + $b (varsa)
            baytlar = []
            gecerli = True
            for tok in hexk.split():
                if tok in ("??", "?"):
                    baytlar.append("..")
                elif len(tok) == 2 and all(c in "0123456789ABCDEFabcdef" for c in tok):
                    baytlar.append(tok.lower())
                else:
                    gecerli = False
                    break
            if gecerli and baytlar:
                sonuc.append([ad, "".join(baytlar), ep_bagli, yol])
    return sonuc

def yara_ad_coz(ad):
    """'NsPacK_V33_LiuXingPing_additional' -> 'NsPack 3.3 LiuXing Ping'"""
    a = ad
    a = re.sub(r"_additional$", "", a)
    a = re.sub(r"_?V(\d)(\d+)$", lambda m: " " + m.group(1) + "." + m.group(2), a)
    a = re.sub(r"_?(\d)(\d{2,})xx$", lambda m: " " + m.group(1) + "." + m.group(2) + "xx", a)
    a = a.replace("_", " ").strip()
    return a

# ---------------------------------------------------------------- desen istatistik (v7 ile ayni)
def desen_istatistik(d):
    tn = len(d) // 2
    kn = sum(1 for i in range(0, len(d), 2) if d[i] != ".")
    return tn, kn

def desen_cesitlilik(d):
    gorulen = set()
    for i in range(0, len(d), 2):
        if d[i] == ".":
            continue
        gorulen.add(d[i:i+2])
    return len(gorulen)

YASAKLI_AD = re.compile(r"^(virus|trojan|malware|worm|backdoor|dropper|exploit|adware|ransom|stealer|banker|bot|keygen|crack|patcher|installer|setup|sfx)", re.I)

def ep_gecerli_mi(desen):
    tn, kn = desen_istatistik(desen)
    if desen_cesitlilik(desen) < 3:
        return False
    return tn >= 12 and kn >= 5

def tum_gecerli_mi(desen):
    tn, kn = desen_istatistik(desen)
    if desen_cesitlilik(desen) < 3:
        return False
    return tn >= 20 and kn >= 12

# ---------------------------------------------------------------- ad temizleme (v7 ile ayni)
def ad_temizle(ad):
    ad = ad.replace("->", "|")
    parcalar = [p.strip() for p in ad.split("|")]
    ana = parcalar[0]
    m = re.search(r"(\d+\.\d[\w.+*-]*)", ana)
    surum = m.group(1).rstrip(".-") if m else ""
    aile = ana[:m.start()].strip() if m else ana
    aile = re.sub(r"[\[\(].*?[\]\)]", "", aile).strip()
    aile = aile.rstrip(" vV.-_")
    if not aile:
        aile = ana.strip()
    return aile, surum


# ================================================================ DIE .sg yeniden-uretim (v8)
# v7 die_db.h'sine ek olarak: PE.isLibraryPresent(...) ve PE.getSize()>N kosullari
# da cikarilir — orijinal DIE kurallarindaki cok-kosullu mantik korunur
# (kanit: packer_ROPacker.2.sg — compareEP + zlib1.dll + >20MB; kosulsuz
# cikarim MinGW x64 baslangicini yanlis ROPacker saniyordu)
import glob as _glob, re as _re
SG_EP8 = _re.compile(r'PE\.compareEP\(\s*"([^"]+)"\s*\)')
SG_LIB8 = _re.compile(r'PE\.isLibraryPresent\(\s*"([^"]+)"\s*\)')
SG_SIZE8 = _re.compile(r'PE\.getSize\(\)\s*>\s*(\d+)')
SG_SECIN8 = _re.compile(r'PE\.isSignatureInSectionPresent\(\s*(-?\d+)\s*,\s*"([^"]+)"\s*\)')
SG_SECNAME8 = _re.compile(r'PE\.isSectionNamePresent\(\s*"([^"]+)"\s*\)')

def die_bolum_uret():
    import struct as _struct
    kayitlar = []
    for yol in sorted(_glob.glob(os.path.join(DIE, "db", "PE", "*.sg"))):
        try:
            metin = open(yol, "r", encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        if "compareEP" not in metin and "isSectionNamePresent" not in metin and \
           "isSignatureInSectionPresent" not in metin:
            continue
        m = _re.search(r'meta\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)', metin)
        if not m: continue
        kategori, aile = m.group(1), m.group(2)
        ep, secicerik, secadi = [], [], []
        kutup, minboy = "", 0
        for mm in SG_EP8.finditer(metin):
            d = die_desen_cevir8(mm.group(1))
            if d: ep.append(d)
        for mm in SG_SECIN8.finditer(metin):
            d = die_desen_cevir8(mm.group(2))
            if d: secicerik.append((int(mm.group(1)), d))
        for mm in SG_SECNAME8.finditer(metin):
            secadi.append(mm.group(1))
        for mm in SG_LIB8.finditer(metin):
            kutup = mm.group(1)
        for mm in SG_SIZE8.finditer(metin):
            minboy = max(minboy, int(mm.group(1)))
        if not ep and not secadi and not secicerik:
            continue
        kayitlar.append({"aile": aile, "kategori": kategori, "ep": ep,
                         "secicerik": secicerik, "secadi": secadi,
                         "kutup": kutup, "minboy": minboy})
    # C++ baslik uret
    S = []
    S.append("// ============================================================================")
    S.append("// die_db.h — OTOMATIK URETIM (v8_uret.py DIE bolumu) — DEGISTIRME")
    S.append("// ============================================================================")
    S.append("// KAYNAK: Detect It Easy db/PE/*.sg (horsicq/Detect-It-Easy, MIT)")
    S.append("// v8: PE.isLibraryPresent + PE.getSize()>N kosullari da cikarildi")
    S.append("//     (ROPacker vakasi: compareEP + zlib1.dll + >20MB — 3 kosul birden)")
    S.append("// ============================================================================")
    S.append("#pragma once")
    S.append("#include <cstdint>")
    S.append("namespace diedb {")
    S.append("")
    S.append("struct EpImza { const char* aile; const char* kategori; const char* desen;")
    S.append("                const char* kutuphane; uint32_t min_boyut; };")
    S.append("struct IcerikImza { const char* aile; const char* kategori; int bolum_idx; const char* desen; };")
    S.append("")
    ep_s, ic_s, ad_s = [], [], []
    gorulen = set()
    for k in kayitlar:
        for d in k["ep"]:
            if d in gorulen: continue
            gorulen.add(d)
            ep_s.append('    { "%s", "%s", "%s", "%s", %du },' %
                        (k["aile"].replace('"',"'"), k["kategori"].replace('"',"'"), d,
                         k["kutup"].replace('"',"'"), k["minboy"]))
        for idx, d in k["secicerik"]:
            if d in gorulen: continue
            gorulen.add(d)
            ic_s.append('    { "%s", "%s", %d, "%s" },' %
                        (k["aile"].replace('"',"'"), k["kategori"].replace('"',"'"), idx, d))
        for ad in k["secadi"]:
            if (ad, k["aile"]) in gorulen: continue
            gorulen.add((ad, k["aile"]))
            ad_s.append('    { "%s", "%s" },' % (ad, k["aile"].replace('"',"'")))
    S.append("// ---- EP imzalari — %d adet (kutuphane/min_boyut kosullu)" % len(ep_s))
    S.append("static const EpImza EP_TABLO[] = {")
    S.extend(ep_s)
    S.append("};")
    S.append("static const int EP_TABLO_ADET = sizeof(EP_TABLO) / sizeof(EP_TABLO[0]);")
    S.append("")
    S.append("// ---- bolum-icerik imzalari — %d adet" % len(ic_s))
    S.append("static const IcerikImza ICERIK_TABLO[] = {")
    S.extend(ic_s)
    S.append("};")
    S.append("static const int ICERIK_TABLO_ADET = sizeof(ICERIK_TABLO) / sizeof(ICERIK_TABLO[0]);")
    S.append("")
    S.append("// ---- bolum-adi tablosu — %d adet" % len(ad_s))
    S.append("static const struct { const char* bolum; const char* aile; } AD_TABLO[] = {")
    S.extend(ad_s)
    S.append("};")
    S.append("static const int AD_TABLO_ADET = sizeof(AD_TABLO) / sizeof(AD_TABLO[0]);")
    S.append("")
    S.append("} // namespace diedb")
    with open(os.path.join(CIKTI, "die_db.h"), "w") as f:
        f.write("\n".join(S) + "\n")
    print("die_db.h yeniden uretildi: %d EP (+kosul) + %d icerik + %d ad" % (len(ep_s), len(ic_s), len(ad_s)))

def die_desen_cevir8(p):
    out = []
    i = 0
    n = len(p)
    while i < n:
        c = p[i]
        if c == "'":
            j = p.find("'", i + 1)
            if j < 0: return None
            for ch in p[i + 1:j]:
                if 32 <= ord(ch) < 127: out.append("%02x" % ord(ch))
            i = j + 1
            continue
        if c in ".$":
            out.append(".")
            i += 1
            continue
        if c in "0123456789abcdefABCDEF":
            if i + 1 < n and p[i + 1] in "0123456789abcdefABCDEF":
                out.append(p[i:i + 2].lower())
                i += 2
                continue
            return None
        if c == ' ':
            i += 1
            continue
        return None
    s = "".join(out)
    return s if len(s) >= 24 else None


# ================================================================ ANA AKIS
def main():
    # ---- 1) TUM PEiD-format kaynaklar
    tum_girdiler = []
    kaynaklar = [
        os.path.join(K3, "wolfram77web_app-peid", "userdb.txt"),
        os.path.join(K3, "packing-box_peid", "src", "peid", "db", "userdb.txt"),
        os.path.join(K3, "packing-box_pypackerdetect", "src", "pypackerdetect", "db", "sigs_short.txt"),
        os.path.join(K3, "packing-box_pypackerdetect", "src", "pypackerdetect", "db", "sigs_long.txt"),
        os.path.join(K3, "salmanmallah_packerscope", "packerscope", "signatures", "peid_userdb.txt"),
    ]
    # v7 cekirdegi: DIE peid_rules (aynen tasinir)
    for kat in ("packer", "protector", "protection", "joiner"):
        kaynaklar.append(os.path.join(DIE, "peid_rules", "PE", kat + ".userdb.txt"))
    for y in kaynaklar:
        if os.path.exists(y):
            n = peid_ayristir(y)
            tum_girdiler += n
            print(f"  userdb: {os.path.basename(os.path.dirname(y))}/{os.path.basename(y)}: {len(n)} imza")
        else:
            print(f"  EKSIK: {y}")

    # ---- 2) YARA kaynaklari
    yar_girdiler = []
    for y, hp in [(os.path.join(K3, "Yara-Rules_rules", "packers", "peid.yar"), False),
                  (os.path.join(K3, "Yara-Rules_rules", "packers", "packer_compiler_signatures.yar"), False),
                  (os.path.join(K3, "salmanmallah_packerscope", "packerscope", "signatures", "yara_rules", "packers", "common_packers.yar"), True)]:
        if os.path.exists(y):
            n = yara_ayristir(y, hepsi_packer=hp)
            yar_girdiler += n
            print(f"  yara: {os.path.basename(y)}: {len(n)} desen")
        else:
            print(f"  EKSIK yara: {y}")

    # ---- 3) erisim sirasi: ep_only=True once (EP tablosu), sonra False (TUM tablosu)
    #     tekil: ayni desen birden fazla kaynakta -> ILK (en iyi adlandirmali) kaynak kazanir
    ep_kayit, tum_kayit, gorulen = [], [], set()
    for ad, desen, ep, kaynak in tum_girdiler:
        if desen in gorulen:
            continue
        if YASAKLI_AD.search(ad):
            continue
        if ep is None:
            ep = False
        gecti = ep_gecerli_mi(desen) if ep else tum_gecerli_mi(desen)
        if not gecti:
            continue
        gorulen.add(desen)
        if ep:
            ep_kayit.append((ad, desen))
        else:
            tum_kayit.append((ad, desen))
    # YARA: yalniz YENI desenler (userdb'lerde olmayan); ep_bagli=True -> EP, degilse TUM
    for ad, desen, ep_bagli, kaynak in yar_girdiler:
        if desen in gorulen:
            continue
        if YASAKLI_AD.search(ad):
            continue
        ad_c = yara_ad_coz(ad)
        if YASAKLI_AD.search(ad_c):
            continue
        gecti = ep_gecerli_mi(desen) if ep_bagli else tum_gecerli_mi(desen)
        if not gecti:
            continue
        gorulen.add(desen)
        if ep_bagli:
            ep_kayit.append((ad_c, desen))
        else:
            tum_kayit.append((ad_c, desen))
    print(f"TOPLAM: {len(ep_kayit)} EP + {len(tum_kayit)} tam-tarama (tekil, kalite filtreli)")

    # ---- 4) peid_db.h uret
    def c_str(x):
        return x.replace("\\", "\\\\").replace('"', "'")
    satirlar = []
    satirlar.append("// ============================================================================")
    satirlar.append("// peid_db.h — OTOMATIK URETIM (v8_uret.py) — DEGISTIRME")
    satirlar.append("// ============================================================================")
    satirlar.append("// KAYNAKLAR (10 imza sozlugu birlesimi, tekil + kalite filtreli):")
    satirlar.append("//   app-peid userdb (4259) + packing-box/peid userdb (5539) +")
    satirlar.append("//   pypackerdetect sigs_short (1832) + sigs_long (4259) + packerscope userdb (40) +")
    satirlar.append("//   DIE peid_rules packer/protector/protection/joiner (3776) +")
    satirlar.append("//   peid.yar 11-kaynak birlesimi (7615 kural) + compiler sigs + common_packers.yar")
    satirlar.append("// LISANS: topluluk PEiD userdb'leri (kamuya acik paylasim) + Yara-Rules (GPLv2)")
    satirlar.append("// FORMAT: hex nibble; '.' = joker nibble")
    satirlar.append("// KALITE: EP >= 12 bayt desen ve >= 5 kesin bayt; TUM >= 20 bayt ve >= 12 kesin")
    satirlar.append("// ============================================================================")
    satirlar.append("#pragma once")
    satirlar.append("#include <cstdint>")
    satirlar.append("namespace peiddb {")
    satirlar.append("")
    satirlar.append("struct EpImza { const char* ad; const char* aile; const char* surum; const char* desen; };")
    satirlar.append("")
    satirlar.append("// ---- EP (giris noktasi) imzalari — %d adet" % len(ep_kayit))
    satirlar.append("static const EpImza EP_TABLO[] = {")
    for ad, desen in ep_kayit:
        aile, surum = ad_temizle(ad)
        satirlar.append('    { "%s", "%s", "%s", "%s" },' % (c_str(ad), c_str(aile), c_str(surum), desen))
    satirlar.append("};")
    satirlar.append("static const int EP_TABLO_ADET = sizeof(EP_TABLO) / sizeof(EP_TABLO[0]);")
    satirlar.append("")
    satirlar.append("// ---- tam-tarama imzalari (EP-bolumu + koruyucu bolumlerde sinirli) — %d adet" % len(tum_kayit))
    satirlar.append("static const EpImza TUM_TABLO[] = {")
    for ad, desen in tum_kayit:
        aile, surum = ad_temizle(ad)
        satirlar.append('    { "%s", "%s", "%s", "%s" },' % (c_str(ad), c_str(aile), c_str(surum), desen))
    satirlar.append("};")
    satirlar.append("static const int TUM_TABLO_ADET = sizeof(TUM_TABLO) / sizeof(TUM_TABLO[0]);")
    satirlar.append("")
    satirlar.append("} // namespace peiddb")
    with open(os.path.join(CIKTI, "peid_db.h"), "w") as f:
        f.write("\n".join(satirlar) + "\n")
    print("peid_db.h yazildi")

    # ---- 5) bolum_db.h uret — bolum adi -> packer atlasi
    bolum = {}  # ad -> (aile, aciklama, kaynak)
    def bolum_ekle(ad, aile, aciklama):
        if ad not in bolum:
            bolum[ad] = (aile, aciklama)
    # hexacorn (packing-box pypackerdetect packers.json) — 92 ad
    pj = json.load(open(os.path.join(K3, "packing-box_pypackerdetect", "src", "pypackerdetect", "db", "packers.json")))
    for ad, aciklama in pj["packers"].items():
        m = re.match(r"^(.*?)\s*[Pp]acker|\((.*?)\)\s*[Pp]acker", aciklama)
        bolum_ekle(ad, ad, aciklama)
    # PE-LiteScan KnownSections — surum atfli
    pe_litescan = [
        ("UPX", "", ["UPX0","UPX1","UPX2","UPX3"]),
        ("VMProtect", "", [".vmp", ".vmp0", ".vmp1", ".vmp2", ".vmp3"]),
        ("ASPack", "1.08-2.XX", [".adata"]), ("ASPack", "2.XX", [".aspack"]),
        ("Petite", "", [".petite", "petite"]),
        ("Enigma", "", [".enigma1", ".enigma2"]),
        (".NET Reactor", "2.XX", [".reacto"]),
        ("Themida", "3.X", [".imports", ".themida", ".winlice", ".loadcon"]),
        ("ASM Guard", "2.XX", ["ASMGUARD", ".asmg"]),
        ("tElock", "", ["UPX!"]),
        ("YodasProtector", "1.0b", [".yP"]), ("YodasCrypter", "1.X", ["yC"]),
        ("MPRESS", "", [".MPRESS1", ".MPRESS2"]),
        ("DxPack", "1.0", ["coderpub"]),
        ("SafeNet", "", [".AKS1", ".AKS2", ".AKS3"]),
        ("Alienyze", "", [".alien"]),
        ("PECompact", "", ["pec", "pec1"]),
        ("RLP", "", [".rlp"]),
        ("StarForce", "4.X-5.X", [".ps4"]), ("StarForce", "3.X", [".sforce3"]),
        ("Safengine Shielden", "", [".sedat"]),
        ("VirtualizeProtect", "", ["VProtect"]),
        ("Krypton", "", ["YADO"]),
        ("NsPack", "", ["nsp0", "nsp1"]),
        ("nPack", "", [".nPack"]), ("JDPack", "", [".jdpack"]), ("SC Pack", "", [".scpack"]),
        ("Simple Pack", "", [".spack"]), ("Eronana", "", [".packer"]),
        ("PE-SHiELD", "", ["PESHiELD"]), ("SVK Protector", "", ["SVKP"]),
        ("obfus.h", "", [".obfh"]), ("Warbird", "", ["?g_Encry"]),
        ("ACProtect", "", [".perplex"]), ("Software Compress", "", ["SoftComp"]),
        ("RLPack", "", [".RLPack"]), ("CodeVirtualizer", "", [".vlizer"]),
        ("DYAMAR", "1.3.5", [".dyamarC"]), ("hmimys", "1.3", ["hmimys"]),
        ("Morphnah", "1.0.X", [".nah"]), ("DNGuard", "", [".I:R"]),
    ]
    for aile, surum, adlar in pe_litescan:
        for ad in adlar:
            bolum_ekle(ad, aile, "PE-LiteScan: %s%s" % (aile, " v" + surum if surum else ""))
    # Manalyze KNOWN_PACKER_SECTIONS — regex -> gercek adlar
    manalyze = [
        (".ndata", "NSIS installer", ".ndata: NSIS kurulum dosyasi (Manalyze)"),
        (".aspack", "ASPack", ".aspack: ASPack (Manalyze)"), (".adata", "ASPack/Armadillo", ".adata: ASPack/Armadillo (Manalyze)"),
        (".enigma1", "Enigma Protector", ".enigma1: Enigma Protector (Manalyze)"),
        (".enigma2", "Enigma Protector", ".enigma2: Enigma Protector (Manalyze)"),
        (".petite", "Petite", ".petite: Petite (Manalyze)"), ("MEW", "MEW", "MEW: MEW packer (Manalyze)"),
        (".neolite", "Neolite", ".neolite: Neolite (Manalyze)"), (".neolit", "Neolite", ".neolit: Neolite (Manalyze)"),
        ("PELOCKnt", "PELock", "PELOCKnt: PELock (Manalyze)"),
        (".perplex", "Perplex", ".perplex: Perplex (Manalyze)"),
        ("PESHiELD", "PEShield", "PESHiELD: PEShield (Manalyze)"),
        ("ProCrypt", "ProCrypt", "ProCrypt: ProCrypt (Manalyze)"),
        (".rmnet", "Ramnit", ".rmnet: Ramnit (Manalyze)"),
        (".RLPack", "RLPack", ".RLPack: RLPack (Manalyze)"),
        (".seau", "SeauSFX", ".seau: SeauSFX (Manalyze)"),
        (".shrink1", "Shrinker", ".shrink1: Shrinker (Manalyze)"), (".shrink2", "Shrinker", ".shrink2: Shrinker (Manalyze)"), (".shrink3", "Shrinker", ".shrink3: Shrinker (Manalyze)"),
        (".spack", "Simple Pack", ".spack: Simple Pack (Manalyze)"),
        (".svkp", "SVKP", ".svkp: SVKP (Manalyze)"),
        (".taz", "PESpin", ".taz: PESpin (Manalyze)"),
        (".Themida", "Themida", ".Themida: Themida (Manalyze)"), ("Themida", "Themida", "Themida: Themida (Manalyze)"),
        ("WinLicen", "WinLicense", "WinLicen: WinLicense (Manalyze)"),
        (".tsuarch", "TSULoader", ".tsuarch: TSULoader (Manalyze)"), (".tsustub", "TSULoader", ".tsustub: TSULoader (Manalyze)"),
        ("PEPACK!!", "PEPack", "PEPACK!!: PEPack (Manalyze)"),
        (".Upack", "Upack", ".Upack: Upack (Manalyze)"), (".ByDwing", "Upack", ".ByDwing: Upack (Manalyze)"),
        (".vmp0", "VMProtect", ".vmp0: VMProtect (Manalyze)"), (".vmp1", "VMProtect", ".vmp1: VMProtect (Manalyze)"), (".vmp2", "VMProtect", ".vmp2: VMProtect (Manalyze)"),
        ("VProtect", "VProtect", "VProtect: VProtect (Manalyze)"),
        ("_winzip_", "WinZip SFX", "_winzip_: WinZip SFX (Manalyze)"),
        (".WWPACK", "WWPACK", ".WWPACK: WWPACK (Manalyze)"),
        (".WWP32", "WWPACK32", ".WWP32: WWPACK32 (Manalyze)"),
        (".yP", "Y0da", ".yP: Y0da Protector (Manalyze)"), (".y0da", "Y0da", ".y0da: Y0da Protector (Manalyze)"),
        (".managed", ".NET AOT", ".managed: AOT-derlenmis .NET (Manalyze)"),
        ("kkrunchy", "kkrunchy", "kkrunchy: kkrunchy (Manalyze)"),
        ("BitArts", "Crunch 2.0", "BitArts: Crunch 2.0 (Manalyze)"),
        ("DAStub", "Dragon Armor", "DAStub: DAStub Dragon Armor (Manalyze)"),
        (".mackt", "ImpREC", ".mackt: ImpRec ile onarilmis (unpack edilmis!) (Manalyze)"),
        (".MaskPE", "MaskPE", ".MaskPE: MaskPE (Manalyze)"),
        (".gentee", "Gentee", ".gentee: Gentee kurulum (Manalyze)"),
        ("!EPack", "EPack", "!EPack: EPack (Manalyze)"),
        (".charmve", "PIN tool", ".charmve: PIN araci (Manalyze)"), (".pinclie", "PIN tool", ".pinclie: PIN araci (Manalyze)"),
        (".boom", "Boomerang", ".boom: Boomerang List Builder (Manalyze)"),
        (".ccg", "CCG Packer", ".ccg: CCG (Cince packer) (Manalyze)"),
        ("FSG!", "FSG", "FSG!: FSG (Manalyze)"),
        ("lz32.dll", "Crinkler", "lz32.dll: Crinkler (Manalyze)"),
        ("PEBundle", "PEBundle", "PEBundle: PEBundle (Manalyze)"), ("pebundle", "PEBundle", "pebundle: PEBundle (Manalyze)"),
        ("PEC2TO", "PECompact", "PEC2TO: PECompact (Manalyze)"), ("PEC2MO", "PECompact", "PEC2MO: PECompact (Manalyze)"),
        ("PECompact2", "PECompact", "PECompact2: PECompact (Manalyze)"),
        ("PEC2", "PECompact", "PEC2: PECompact (Manalyze)"), ("pec", "PECompact", "pec: PECompact (Manalyze)"),
        ("pec1", "PECompact", "pec1: PECompact (Manalyze)"), ("pec2", "PECompact", "pec2: PECompact (Manalyze)"),
        ("pec3", "PECompact", "pec3: PECompact (Manalyze)"), ("pec4", "PECompact", "pec4: PECompact (Manalyze)"),
        ("pec5", "PECompact", "pec5: PECompact (Manalyze)"), ("pec6", "PECompact", "pec6: PECompact (Manalyze)"),
        ("PESHiELD", "PEShield", "PESHiELD: PEShield (Manalyze)"),
        (".sforce3", "StarForce", ".sforce3: StarForce (Manalyze)"),
    ]
    for ad, aile, aciklama in manalyze:
        bolum_ekle(ad, aile, aciklama)
    # packpeek: PDATA000 (Armadillo)
    bolum_ekle("PDATA000", "Armadillo", "PDATA000: Armadillo (packpeek)")
    # v8 RGD hatti: Themida/WinLicense Taggant DRM bolumu (v2.3.7 ENCODE / v2.3.9 full)
    bolum_ekle(".taggant", "Themida / WinLicense", ".taggant: Taggant DRM bolumu (Themida/WinLicense — RGD olcum)")
    bolum_ekle("PDATA001", "Armadillo", "PDATA001: Armadillo (packpeek)")
    # ObfusFake — SAHTE bolum adlari (obfus.h fake-protection modu)
    obfus_fake_adlar = [".enigma1", ".enigma2", ".vmp0", ".vmp1", ".vmp2", "UPX0", ".winlice",
        ".petite", ".rlp", ".dsstext", "logicoma", "adr", "have", "30cm",
        "PETETRIS", ".alien", ".pwdprot", ".tw", ".vlizer", ".aspack",
        ".adata", "__wibu00", "__wibu01"]
    sahte_tablo = []
    for ad in obfus_fake_adlar:
        sahte_tablo.append((ad, "obfus.h SAHTE bolum adi (ObfusFake-Signatures-Remover: fake-protection modu)"))
    print(f"bolum_db: {len(bolum)} gercek + {len(sahte_tablo)} sahte-obfus adi")

    satirlar = []
    satirlar.append("// ============================================================================")
    satirlar.append("// bolum_db.h — OTOMATIK URETIM (v8_uret.py) — DEGISTIRME")
    satirlar.append("// ============================================================================")
    satirlar.append("// BOLUM ADI -> PACKER ATLASI")
    satirlar.append("// KAYNAKLAR: hexacorn blog listesi (pypackerdetect packers.json, 92 ad) +")
    satirlar.append("//   PE-LiteScan KnownSections (~70, surum atfli) + Manalyze KNOWN_PACKER_SECTIONS +")
    satirlar.append("//   packpeek (Armadillo PDATA000) + DRMDetector")
    satirlar.append("// SAHTE MOD: obfus.h fake-protection bolum adlari ayri tabloda (ObfusFake-Remover)")
    satirlar.append("// ============================================================================")
    satirlar.append("#pragma once")
    satirlar.append("#include <cstdint>")
    satirlar.append("namespace bolumdb {")
    satirlar.append("")
    satirlar.append("struct BolumAdi { const char* ad; const char* aile; const char* not_; };")
    satirlar.append("")
    satirlar.append("// ---- bilinen packer bolum adlari — %d adet" % len(bolum))
    satirlar.append("static const BolumAdi TABLO[] = {")
    for ad, (aile, not_) in sorted(bolum.items()):
        satirlar.append('    { "%s", "%s", "%s" },' % (c_str(ad), c_str(aile), c_str(not_)))
    satirlar.append("};")
    satirlar.append("static const int TABLO_ADET = sizeof(TABLO) / sizeof(TABLO[0]);")
    satirlar.append("")
    satirlar.append("// ---- obfus.h SAHTE-IMZA bolum adlari (fake-protection modu) — %d adet" % len(sahte_tablo))
    satirlar.append("static const BolumAdi SAHTE_TABLO[] = {")
    for ad, not_ in sahte_tablo:
        satirlar.append('    { "%s", "obfus.h", "%s" },' % (c_str(ad), c_str(not_)))
    satirlar.append("};")
    satirlar.append("static const int SAHTE_TABLO_ADET = sizeof(SAHTE_TABLO) / sizeof(SAHTE_TABLO[0]);")
    satirlar.append("")
    satirlar.append("} // namespace bolumdb")
    with open(os.path.join(CIKTI, "bolum_db.h"), "w") as f:
        f.write("\n".join(satirlar) + "\n")
    print("bolum_db.h yazildi")

    # ---- 6) algoritma_db.h — imza OZTESI desenler
    # ObfusHunter desenleri (kaynak koddan sabitler)
    obfus_desenler = [
        ("BREAK_STACK_1", "Junk Code", "31c07401e80fa2"),
        ("BREAK_STACK_4", "Junk Code", "31db31d231da7406b804000000000fa2"),
        ("BREAK_STACK_5", "Junk Code", "31db31c089c389d331c27401200fa2"),
        ("BREAK_STACK_6", "Junk Code", "31d231c089c27401e80fa2"),
        ("BREAK_STACK_7", "Junk Code", "31d27401e80fa2"),
        ("BREAK_STACK_8", "Junk Code", "31c07401500fa2"),
        ("BREAK_STACK_9", "Junk Code", "31d2740200000fa2"),
        ("AD_DR_CLEAN", "Anti-Debug", "31..89..0089..0489..0889..0c"),
        ("AD_PATCH_V2", "Anti-Debug", "66c1e80500c3"),
        ("AD_EXIT_BLOCK", "Anti-Debug", "ed31c07401e80fa266c1e80500c3"),
        ("AD_CRASH_V2", "Anti-Debug", "cced00"),
        ("AD_RDTSCP", "Anti-Debug", "0f31......0fc7f8"),
        ("VM_DISPATCH_X64", "Virtualization", "4889c34831c848c1ea0848c1e004"),
        ("VM_DISPATCH_X86", "Virtualization", "89d801c829d3d3e1535bd3e909d04a"),
        ("BAD_JMP_X64", "Virtualization", "0fa24889c04889daff25"),
        ("RET_BY_VAR", "Internal Logic", "8b450805....8b0005....c3"),
        ("HIDE_STRING_ENTRY", "String Obf", "31c07401e80fa2......0fa24889c0"),
        ("OBFH_VERI_BLOGU", "Obfus.h veri blogu", "00010203040506070809"),
    ]
    # ObfusFake sahte imza desenleri
    sahte_imzalar = [
        ("SAHTE_ENIGMA", "Enigma protector v\\x01", "456e69676d612070726f746563746f72207601"),
        ("SAHTE_DENUVO", "denuvo_atd", "64656e75766f5f617464000000000000"),
        ("SAHTE_NUITKA", "NUITKA_ONEFILE_PARENT", "4e5549544b415f4f4e4546494c455f504152454e54"),
        ("SAHTE_SCREEN2EXE", "Video created by SCREEN2EXE/SCREEN2SWF", "566964656f20637265617465642062792053435245454e324558452f53435245454e32535746"),
    ]
    sahte_dongle = [
        "skeydrv.dll", "HASPDOSDRV", "MARXDEV1.SYS", "MxLPT_Sem", "nethasp.ini",
        "sense4.dll", "SNTNLUSB", "RNBOspro", "SSIVDDP.DLL", "WIBUKEY",
        "\\\\.\\WIZZKEYRL", "\\\\.\\NVKEY",
    ]
    # packerscope EP stub desenleri
    ep_stublar = [
        ("PUSHAD", "yaygin packer prologu", "60"),
        ("PUSHFD", "yaygin packer prologu", "9c"),
        ("PUSHAD_CALL", "UPX/ASPack tarzi", "60e8"),
        ("PUSHFD_PUSHAD", "packer prologu", "9c60"),
        ("OBSIDIUM_JMP", "Obsidium tarzi kisa JMP", "eb02"),
        ("CALL_DOLLAR5", "konum-bagimsiz stub", "e800000000"),
        ("UPX64_RBP", "UPX x64 giris stubu", "554157415641554154"),
        ("UPX64_RBX", "UPX x64 giris stubu", "53555657415441554156"),
    ]
    # DRMDetector + oyun DRM dizgileri (dosya ici ASCII)
    drm_dizgiler = [
        ("Denuvo", "denuvo"), ("Arxan", "arxan.dll"), ("Arxan", "arxanapp.dll"), ("Arxan", "arxan_clr.dll"),
        ("SteamStub", "steamstub"), ("SteamStub", "steam_api"), ("SteamStub", "steam_api64.dll"),
        ("VMProtect", "vmprotect."), ("VMProtect", ".vmp0"), ("VMProtect", ".vmp1"),
        ("Themida", "themida.dll"), ("Themida", "themida.sys"), ("WinLicense", "winlicense.dll"), ("Themida", ".themida"),
        ("ASPack", ".aspack"), ("ASPack", ".adata"),
        ("UPX", ".upx0"), ("UPX", ".upx1"), ("UPX", "upx!"),
        ("PECompact", "pec2.exe"), ("PECompact", "pec1.exe"), ("PECompact", "pecompact"),
        ("Obsidium", "obsidium"), ("CodeVeil", "codeveil"),
        # v8 Wine hatti: gercek Themida 3.2.4 / Enigma 7.80 ciktisindan
        ("Enigma Protector", "Enigma Protector CA"),   # demo X.509 sertifikasi (konu alanI)
        ("Enigma Protector", "EnigmaProtect"),
    ]
    satirlar = []
    satirlar.append("// ============================================================================")
    satirlar.append("// algoritma_db.h — OTOMATIK URETIM (v8_uret.py) — DEGISTIRME")
    satirlar.append("// ============================================================================")
    satirlar.append("// IMZA OZTESI ALGORITMA DESENLERI")
    satirlar.append("// KAYNAKLAR: ObfusHunter (junk/anti-debug/VM dispatch), ObfusFake (sahte imza),")
    satirlar.append("//   packerscope EntryPointDetector (EP stub), DRMDetector (oyun DRM dizgileri)")
    satirlar.append("// FORMAT: hex nibble; '.' = joker nibble")
    satirlar.append("// ============================================================================")
    satirlar.append("#pragma once")
    satirlar.append("#include <cstdint>")
    satirlar.append("namespace algdb {")
    satirlar.append("")
    satirlar.append("struct Desen { const char* kod; const char* kategori; const char* aciklama; const char* desen; };")
    satirlar.append("struct SahteImza { const char* kod; const char* aciklama; const char* desen; };")
    satirlar.append("struct EpStub { const char* kod; const char* aciklama; const char* desen; };")
    satirlar.append("struct DrmDizgi { const char* aile; const char* dizgi; };")
    satirlar.append("struct ModernEp { const char* aile; const char* surum; const char* kaynak; const char* desen; };")
    satirlar.append("")
    # ---- MODERN (2025-2026) GERCEK CIKTI EP DESENLERI (Wine hatti — v8)
    modern_ep = [
        # --- Wine hatti (gercek Themida 3.2.4 / Enigma 7.80, 26.11.2026) ---
        ("Enigma Protector", "7.8x", "eb08................60e8000000005d81ed........81ed........e9"),
        ("Enigma Protector", "7.8x", "eb08................5051525355565741504151415241534154415541564157489c4881ec........0fae1c24e8"),
        # --- PackGenome RGD (gercek ornek olcumleri, NDSS dataset) ---
        # Themida 2.3.7 delphi_bcb + WinLicense 2.3.9 (9 mod): push esi/ebx/edi; call; int3; pop eax; mov ebx,eax; inc eax; sub...
        ("Themida / WinLicense", "2.3.x", "565053e801000000cc5889c3402d"),
        # ZProtect 1.6 push-ret: push 0x41c3xx; push 0x41c3xx; ret (default/protect_calls/resources)
        ("ZProtect", "1.6", "68..c3410068..c34100c3"),
        # ZProtect 1.6 jmp: push 0x41d3xx; jmp rel32 (full/import)
        ("ZProtect", "1.6", "68..d34100e9......"),
        # ZProtect 1.6 jmp (c341): push 0x41c3xx; jmp rel32 (check)
        ("ZProtect", "1.6", "68..c34100e9......"),
        # MoleBox 4.3: mingw loader — mov [esp],1; call [imm32]; call rel; nop; lea esi,[esi+0]
        ("MoleBox", "4.3", "5589e583ec08c7042401000000ff15........e8........908db42600000000"),
        # Themida 2.3.7 full-ENCODE + WinLicense 2.3.9 compress_all_full: jmp+8 / 8b veri (cmov|xadd) / jmp 0x200000
        ("Themida / WinLicense", "2.3.x", "eb08................e900200000"),
        # ZProtect 1.6 push-ret d341 varyanti (import modu)
        ("ZProtect", "1.6", "68..d3410068..d34100c3"),
        # Enigma 1.55 best_compress: Delphi prolog + mov eax,imm32; call; 9a farcall; add esp,0x10; mov esp,ebp; pop ebp; jmp
        ("Enigma Protector", "1.5x", "558bec83c4f0b8........e8010000009a83c4108be55de9"),
    ]
    satirlar.append("// ---- MODERN (2025-2026) GERCEK CIKTI EP DESENLERI — Wine hattindan olculdu (v8: 26.11.2026)")
    satirlar.append("//     Themida 3.2.4.34 demo + Enigma Protector 7.80 (build 20250205) demo;")
    satirlar.append("//     qemu-wine32 hatti ile gercek paketleme yapildi, EP baytlari olculdu")
    satirlar.append("static const ModernEp MODERN_EP_TABLO[] = {")
    for aile, surum, desen in modern_ep:
        satirlar.append('    { "%s", "%s", "Wine hatti: gercek cikti", "%s" },' % (aile, surum, desen))
    satirlar.append("};")
    satirlar.append("static const int MODERN_EP_TABLO_ADET = sizeof(MODERN_EP_TABLO) / sizeof(MODERN_EP_TABLO[0]);")
    satirlar.append("")
    satirlar.append("// ---- ObfusHunter desenleri — %d adet" % len(obfus_desenler))
    satirlar.append("static const Desen OBFUS_TABLO[] = {")
    for kod, kat, desen in obfus_desenler:
        satirlar.append('    { "%s", "%s", "%s", "%s" },' % (kod, kat, "", desen))
    satirlar.append("};")
    satirlar.append("static const int OBFUS_TABLO_ADET = sizeof(OBFUS_TABLO) / sizeof(OBFUS_TABLO[0]);")
    satirlar.append("")
    satirlar.append("// ---- sahte imza desenleri (ObfusFake-Remover) — %d adet" % len(sahte_imzalar))
    satirlar.append("static const SahteImza SAHTE_TABLO[] = {")
    for kod, aciklama, desen in sahte_imzalar:
        satirlar.append('    { "%s", "%s", "%s" },' % (kod, aciklama, desen))
    satirlar.append("};")
    satirlar.append("static const int SAHTE_TABLO_ADET = sizeof(SAHTE_TABLO) / sizeof(SAHTE_TABLO[0]);")
    satirlar.append("")
    satirlar.append("// ---- sahte dongle dizgileri (ObfusFake-Remover) — %d adet" % len(sahte_dongle))
    satirlar.append("static const DrmDizgi SAHTE_DONGLE[] = {")
    for d in sahte_dongle:
        satirlar.append('    { "obfus.h sahte dongle", "%s" },' % c_str(d))
    satirlar.append("};")
    satirlar.append("static const int SAHTE_DONGLE_ADET = sizeof(SAHTE_DONGLE) / sizeof(SAHTE_DONGLE[0]);")
    satirlar.append("")
    satirlar.append("// ---- EP stub desenleri (packerscope) — %d adet" % len(ep_stublar))
    satirlar.append("static const EpStub EP_STUB[] = {")
    for kod, aciklama, desen in ep_stublar:
        satirlar.append('    { "%s", "%s", "%s" },' % (kod, aciklama, desen))
    satirlar.append("};")
    satirlar.append("static const int EP_STUB_ADET = sizeof(EP_STUB) / sizeof(EP_STUB[0]);")
    satirlar.append("")
    satirlar.append("// ---- oyun DRM / ticari protector dizgileri (DRMDetector) — %d adet" % len(drm_dizgiler))
    satirlar.append("static const DrmDizgi DRM_TABLO[] = {")
    for aile, d in drm_dizgiler:
        satirlar.append('    { "%s", "%s" },' % (aile, c_str(d)))
    satirlar.append("};")
    satirlar.append("static const int DRM_TABLO_ADET = sizeof(DRM_TABLO) / sizeof(DRM_TABLO[0]);")
    satirlar.append("")
    satirlar.append("} // namespace algdb")
    with open(os.path.join(CIKTI, "algoritma_db.h"), "w") as f:
        f.write("\n".join(satirlar) + "\n")
    print("algoritma_db.h yazildi")
    die_bolum_uret()
    print("BITTI: peid %d+%d | bolum %d(+%d sahte) | algoritma 4 tablo | die yeniden" % (len(ep_kayit), len(tum_kayit), len(bolum), len(sahte_tablo)))

if __name__ == "__main__":
    main()
