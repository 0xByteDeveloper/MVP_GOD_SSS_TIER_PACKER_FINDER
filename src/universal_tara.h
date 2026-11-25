// ============================================================================
// universal_tara.h — UNIVERSAL PACKER TARAMA MOTORU v6
// ============================================================================
// universal_db.h veritabanini isler; vmpdet5.cpp tarafindan cagrilir.
// CIKTI: EvrenTarama — aile adi, kanit listesi, sahte-imza uyarilari,
//        UPX derin cozumleme (surum/yontem), PyInstaller cookie cozumleme.
// GUVENLIK: tum dizgi aramalari bolge kisitli (baslik / koruyucu bolum /
//        kuyruk) — dedektorun KENDI statik binary'si temiz gecmelidir.
// ============================================================================
#pragma once
#include <string>
#include <vector>
#include <cstring>
#include <cstdint>
#include <algorithm>
#include "universal_db.h"

// ---- vmpdet5.cpp'den beklenen tipler (one-definition: burada sadece imzalar)
// struct Bolum { std::string ad; uint32_t vsz, va, rsz, ro, oz; };
// PE yapisi: p.veri (tum dosya), p.bolumler (vector<Bolum>)

namespace evren {

struct Kanit { std::string metin; int agirlik; };   // agirlik: 3=kesin, 2=guclu, 1=zayif

struct EvrenTarama {
    std::string aile;                 // ana aile karari (bos = bilinmeyen)
    std::string kategori;
    std::string kanit_seviyesi;       // K1 / K2 / K3
    std::vector<Kanit> kanitlar;
    bool sahte_imza_demeti = false;   // obfus.h/obfusheader.h/yap sahteciligi
    std::vector<std::string> sahte_bolumler;
    std::string upx_surum;            // UPX ise: "UPX 5.x"
    std::string upx_yontem;           // "NRV2B_LE32" / "LZMA" ...
    std::string upx_seviye;
    std::string pyi_surum;            // PyInstaller ise python surumu
    std::string pyi_kutuphane;        // python3x.dll
    bool tespit_edildi = false;
};

// ---------- yardimcilar (harici dosya verisi uzerinde) ----------
inline bool bayt_icinde(const std::vector<uint8_t>& v, size_t bas, size_t son,
                        const char* dizgi) {
    size_t n = strlen(dizgi);
    if (son > v.size()) son = v.size();
    if (bas >= v.size() || son <= bas || son - bas < n) return false;
    for (size_t i = bas; i + n <= son; i++)
        if (!memcmp(&v[i], dizgi, n)) return true;
    return false;
}

inline bool dizgi_esit_mi_kucuk(const std::string& a, const char* b) {
    size_t n = strlen(b);
    if (a.size() != n) return false;
    for (size_t i = 0; i < n; i++) {
        char ca = a[i] >= 'A' && a[i] <= 'Z' ? a[i] + 32 : a[i];
        char cb = b[i] >= 'A' && b[i] <= 'Z' ? b[i] + 32 : b[i];
        if (ca != cb) return false;
    }
    return true;
}

// ---------- ana motor ----------
// pe_veri       : tum dosya baytlari
// bolumler      : {ad, vsz, va, rsz, ro, oz} listesi
// standart_adi  : ".text",".data",... standart bolum predicate'i (vmpdet'ten)
template <class BolumTipi, class StandadPred>
EvrenTarama tara(const std::vector<uint8_t>& pe_veri,
                 const std::vector<BolumTipi>& bolumler,
                 StandadPred standart_adi,
                 bool (*korude_ara)(const std::vector<uint8_t>&, const char*, void*),
                 void* koru_baglam) {
    using namespace universaldb;
    EvrenTarama e;

    // --- bolge hesaplari
    size_t dosya_boyu = pe_veri.size();
    size_t baslik_son = std::min<size_t>(0x1000, dosya_boyu);
    size_t kuyruk_bas = dosya_boyu > 8192 ? dosya_boyu - 8192 : 0;

    // koruyucu (standart-disi) bolumler
    // NOT: standart_ad UPX0/UPX1/UPX2'yi de 'standart' sayar (v5 kamuflaj mantigi) —
    // evrensel motor UPX bolumlerini ESLESMEYE dahil etmeli, bu yuzden UPX istisnasi.
    std::vector<const BolumTipi*> koru;
    std::vector<const BolumTipi*> tum;
    for (auto& b : bolumler) {
        bool upx_adi = false;
        for (const char* u : {"UPX0","UPX1","UPX2",".UPX0",".UPX1",".UPX2"})
            if (dizgi_esit_mi_kucuk(b.ad, u)) { upx_adi = true; break; }
        if (!standart_adi(b.ad) || upx_adi) { koru.push_back(&b); tum.push_back(&b); }
        else tum.push_back(&b);
    }
    // eslesme listesi: yalniz STANDART-OLMAYAN bolumler (MinGW .edata catismasi gibi
    // yanlis pozitifleri engeller) — UPX istisnasi yukarida
    std::vector<const BolumTipi*> eslesme_listesi = koru;

    // --- S1: bolum-adi eslesmesi + sahte demet analizi
    uint8_t vuran_saticilar[8] = {0,0,0,0,0,0,0,0};
    int vuran_sayi = 0;
    const BolumImza* en_iyi = nullptr;
    int en_iyi_eslesme = 0;

    for (auto& imza : BOLUM_TABLO) {
        int eslesme = 0;
        for (auto* b : eslesme_listesi)
            for (const char* bn : imza.bolumler)
                if (bn && dizgi_esit_mi_kucuk(b->ad, bn)) { eslesme++; break; }
        if (eslesme == 0) continue;
        int gerekli = imza.istenen > 0 ? imza.istenen : 1;
        if (eslesme >= gerekli) {
            // daha iyi eslesme (cok bolumlu aile) kazanir
            if (!en_iyi || eslesme > en_iyi_eslesme) {
                en_iyi = &imza;
                en_iyi_eslesme = eslesme;
            }
            // satici sayaci (demet analizi — ayni satici 1 kez sayilir)
            bool var = false;
            for (int i = 0; i < vuran_sayi; i++) if (vuran_saticilar[i] == imza.satici) var = true;
            if (!var && vuran_sayi < 8) vuran_saticilar[vuran_sayi++] = imza.satici;
        }
    }

    // --- S2: sahte imza demeti kurali
    // FARKLI uretici ailelerinden >=2 bolum-ailesi ayni dosyada => sahtecilik
    if (vuran_sayi >= 2) {
        int sahte_aday = 0;
        for (int i = 0; i < vuran_sayi; i++)
            for (auto& sa : SAHTE_AILELER)
                if (sa.satici == vuran_saticilar[i]) sahte_aday++;
        if (sahte_aday >= 2) {
            e.sahte_imza_demeti = true;
            // sahte bolumleri listele
            for (auto* b : tum)
                for (const char* sb : SAHTE_BOLUMLER)
                    if (dizgi_esit_mi_kucuk(b->ad, sb))
                        e.sahte_bolumler.push_back(b->ad);
            e.aile = "obfus.h / obfusheader.h (SAHTE IMZA MODU)";
            e.kategori = "obfuscator";
            e.kanit_seviyesi = "K1";
            char tampon[256];
            snprintf(tampon, sizeof tampon, "%zu sahte protector bolumu birden: obfus.h FAKE_SIGNATURES (include/obfus.h:329-402) veya obfusheader.h FAKE_SIG (satir 1874-1890)", e.sahte_bolumler.size());
            e.kanitlar.push_back({tampon, 3});
            e.kanitlar.push_back({"hicbir GERCEK protector baska ureticinin bolumunu birakmaz", 3});
            if (e.sahte_bolumler.size() > 0)
                for (auto& sb : e.sahte_bolumler) e.kanitlar.push_back({"sahte bolum: " + sb, 2});
            e.tespit_edildi = true;
            return e;   // demet karari FINAL — tek tek aile raporlamak YANLIS olur
        }
    }

    // --- S3: bayt-dizgisi imzalari (bolge kisitli)
    auto dizgi_bolge_vur = [&](const char* dizgi, uint8_t bolge) {
        if (bolge & R_BASLIK) if (bayt_icinde(pe_veri, 0, baslik_son, dizgi)) return true;
        if (bolge & R_KUYRUK) if (bayt_icinde(pe_veri, kuyruk_bas, dosya_boyu, dizgi)) return true;
        if ((bolge & R_KORU) && korude_ara) if (korude_ara(pe_veri, dizgi, koru_baglam)) return true;
        if (bolge == R_TUM) if (bayt_icinde(pe_veri, 0, dosya_boyu, dizgi)) return true;
        return false;
    };

    std::vector<std::pair<const BaytImza*, int>> dizgi_vuruslari;
    for (auto& imza : DIZGI_TABLO)
        if (dizgi_bolge_vur(imza.dizgi, imza.bolge))
            dizgi_vuruslari.push_back({&imza, 2});
    for (auto& kv : dizgi_vuruslari) e.kanitlar.push_back({"dizgi: \"" + std::string(kv.first->dizgi) + "\" (" + kv.first->not_ + ")", kv.second});

    // --- S4: ozel desenler
    // TinyLoad .pxkey XXTEA anahtar blogu — koruyucu bolumlerde 24 bayt desen
    if (korude_ara) {
        // (bayt deseni icin ayozel arama: motor koru bolgelerini disaridan taratamiyor
        //  genel dizgi API'siyle; bu yuzden dosya-geneli + kuyruk kontrolu yapariz)
    }
    {
        // TinyLoad anahtar blogu — dosya geneli (desen 24 bayt, cakisma olasiligi dusuk)
        size_t n = sizeof(TINYLOAD_ANAHTAR);
        if (dosya_boyu >= n)
            for (size_t i = 0; i + n <= dosya_boyu; i++)
                if (!memcmp(&pe_veri[i], TINYLOAD_ANAHTAR, n)) {
                    e.kanitlar.push_back({"TinyLoad XXTEA anahtar blogu (C0DE1337/FEEDF00D/CAFEBABE/DEADBEEF/8BADF00D/B007DEAD) @0x" + std::to_string(i), 3});
                    if (e.aile.empty()) { e.aile = "TinyLoad"; e.kategori = "packer/vm"; e.kanit_seviyesi = "K1"; }
                    break;
                }
    }

    // --- S5: UPX derin cozumleme — 32 bayt packheader'i coz
    {
        for (size_t i = 0; i + 32 <= dosya_boyu && i < 0x1000; i++) {
            if (!memcmp(&pe_veri[i], "UPX!", 4)) {
                const UpxBaslik* h = (const UpxBaslik*)&pe_veri[i];
                if (h->surum >= 9 && h->surum <= 13 && h->seviye >= 1 && h->seviye <= 10) {
                    e.upx_surum = upx_surum_adi(h->surum);
                    e.upx_yontem = upx_yontem_adi(h->yontem);
                    e.upx_seviye = std::to_string((int)h->seviye);
                    char tampon[128];
                    snprintf(tampon, sizeof tampon, "UPX packheader @0x%zX: surum=%d yontem=%d(%s) seviye=%d",
                             i, h->surum, h->yontem, e.upx_yontem.c_str(), h->seviye);
                    e.kanitlar.push_back({tampon, 3});
                    break;
                }
            }
        }
    }

    // --- S6: PyInstaller EOF cookie cozumleme
    {
        if (dosya_boyu >= sizeof(PyiCookie)) {
            // cookie son 88 baytta; sihrin ilk 3 bayti "MEI", 4. bayt surume gore degisir (K1: pyi_utils.c:169-171)
            for (size_t ofset : {(size_t)0, (size_t)8, (size_t)88}) {
                size_t konum = dosya_boyu - (ofset == 0 ? sizeof(PyiCookie) : ofset);
                if (konum + 8 > dosya_boyu) continue;
                if (pe_veri[konum] == 'M' && pe_veri[konum+1] == 'E' && pe_veri[konum+2] == 'I') {
                    // py cookie: MEI\x00\x0b\x0a\x0b\x0e — 4. bayt degisken ama 5-8 sabit kontrol
                    if (pe_veri[konum+4] == 0x0b && pe_veri[konum+5] == 0x0a &&
                        pe_veri[konum+6] == 0x0b && pe_veri[konum+7] == 0x0e) {
                        const PyiCookie* c = (const PyiCookie*)&pe_veri[konum];
                        e.pyi_surum = std::to_string(c->py_surum);
                        char tampon[160];
                        snprintf(tampon, sizeof tampon, "PyInstaller EOF cookie @0x%zX: python=%u paket=%u bayt",
                                 konum, c->py_surum, c->paket_uzunluk);
                        e.kanitlar.push_back({tampon, 3});
                        if (c->py_kutuphane[0])
                            e.pyi_kutuphane = std::string(c->py_kutuphane, strnlen(c->py_kutuphane, 64));
                        if (e.aile.empty()) { e.aile = "PyInstaller"; e.kategori = "script-packer"; e.kanit_seviyesi = "K1"; }
                        break;
                    }
                }
            }
        }
    }

    // --- S7: nihai aile karari
    if (!e.aile.empty()) { e.tespit_edildi = true; return e; }

    if (en_iyi) {
        e.aile = en_iyi->aile;
        e.kategori = en_iyi->kategori;
        e.kanit_seviyesi = std::string(en_iyi->kanit).substr(0, 2);
        char tampon[192];
        snprintf(tampon, sizeof tampon, "bolum eslesmesi x%d: %s", en_iyi_eslesme, en_iyi->kanit);
        e.kanitlar.push_back({tampon, 3});
        e.tespit_edildi = true;
        return e;
    }

    // dizgi vuruslarindan aile turetme (sadece agirlik-3 kanitlar)
    for (auto& kv : dizgi_vuruslari) {
        const char* d = kv.first->dizgi;
        if (kv.second >= 2) {
            if (!strcmp(d, "ConfusedByAttribute") || !strcmp(d, "ConfuserEx") || !strcmp(d, "KoiVM")) {
                e.aile = "ConfuserEx (.NET)"; e.kategori = ".NET obfuscator"; e.kanit_seviyesi = "K1"; e.tespit_edildi = true; return e;
            }
            if (!strcmp(d, "__compiled__")) { e.aile = "Nuitka"; e.kategori = "script-packer"; e.kanit_seviyesi = "K1"; e.tespit_edildi = true; return e; }
            if (!strcmp(d, "Pyarmor") || !strcmp(d, "__pyarmor__") || !strcmp(d, "pytransform")) {
                e.aile = "PyArmor"; e.kategori = "script-obfuscator"; e.kanit_seviyesi = "K1"; e.tespit_edildi = true; return e; }
            if (!strcmp(d, "Nullsoft") || !strcmp(d, "NSIS Error")) { e.aile = "Nullsoft NSIS"; e.kategori = "installer"; e.tespit_edildi = true; return e; }
            if (!strcmp(d, "Inno Setup")) { e.aile = "Inno Setup"; e.kategori = "installer"; e.tespit_edildi = true; return e; }
            if (!strcmp(d, "SecureEngine")) { e.aile = "Themida / WinLicense (SecureEngine)"; e.kategori = "protector"; e.kanit_seviyesi = "K3"; e.tespit_edildi = true; return e; }
            if (!strcmp(d, "Enigma protector") || !strcmp(d, "The Enigma Protector")) { e.aile = "Enigma Protector"; e.kategori = "protector"; e.kanit_seviyesi = "K3"; e.tespit_edildi = true; return e; }
            if (!strcmp(d, "Themida") || !strcmp(d, "WinLicense")) { e.aile = "Themida / WinLicense"; e.kategori = "protector"; e.kanit_seviyesi = "K3"; e.tespit_edildi = true; return e; }
            if (!strcmp(d, "PECompact2")) { e.aile = "PECompact"; e.kategori = "compressor"; e.tespit_edildi = true; return e; }
            if (!strcmp(d, "ASProtect")) { e.aile = "ASProtect"; e.kategori = "protector"; e.tespit_edildi = true; return e; }
            if (!strcmp(d, "Obsidium")) { e.aile = "Obsidium"; e.kategori = "protector"; e.tespit_edildi = true; return e; }
        }
    }

    return e;
}

} // namespace evren
