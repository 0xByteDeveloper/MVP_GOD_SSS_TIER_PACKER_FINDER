// ============================================================================
// universal_tara.h — UNIVERSAL PACKER TARAMA MOTORU v7 (IMMORTAL)
// ============================================================================
// Girdi: universal_db.h (K1/K2/K3 imza DB) + peid_db.h (2771+385 PEiD imzasi,
// otomatik uretim) + die_db.h (1292 EP + 42 bolum-icerik + 90 bolum-adi,
// Detect-It-Easy kurallarindan otomatik uretim).
//
// v7 KATMANLARI:
//   S0  .NET CLI metadata motoru (BSJB kok, stream dizini, #Strings/#US yigin
//       taramasi) — ConfuserEx/KoiVM/Reactor/Agile.NET/Babel/Dotfuscator/
//       SmartAssembly/Spices/Goliath/MaxtoCode/DNGuard/ILProtector/Xenocode/
//       CodeVeil... + ConfuserEx surum su damgasi cozumleme
//   S1  bolum-adi aile eslesmesi (v6, korunur) + DIE bolum-adi destek kaniti
//   S2  sahte-imza demeti kalkani (obfus.h FAKE_SIGNATURES)
//   S3  bolge-kisitli dizgi imzalari (v6, korunur)
//   S4  GIRIS NOKTASI (EP) bayt-imza motoru — PEiD 2771 + DIE 1292 desen,
//       nibble-joker destekli, en-kesin-desen kazanir; PEiD adi surum tasir
//   S5  tam-tarama imzalari (PEiD 385) — YALNIZ EP-bolumu + standart-disi
//       bolumlerin ilk/son parcalarinda aranir (yanlis pozitif korumasi)
//   S6  ozel bloklar: TinyLoad XXTEA, UPX packheader, PyInstaller cookie
//   S7  THEMIDA DERIN BLOGU — DIE EP imzalarindan surum haritasi (1.0→2.1),
//       x64→3.x kurali (K1: Magicmida Themida64.pas:63 "V2 is not supported")
//   S8  nihai aile karari — oncelik: sahte-demet > bolum-ailesi > .NET >
//       EP-ailesi (>=6 kesin bayt) > dizgi-ailesi
//
// GUVENLIK: dedektorun KENDI binary'si temiz gecmelidir; tum aramalar bolge
// kisitli; EP imzalari yalniz GIRIS NOKTASI ofsetinde eslesir.
// ============================================================================
#pragma once
#include <string>
#include <vector>
#include <cstring>
#include <cstdint>
#include <algorithm>
#include "universal_db.h"
#include "peid_db.h"
#include "die_db.h"

// ---- vmpdet5.cpp'den beklenen tipler (one-definition: burada sadece imzalar)
// struct Bolum { std::string ad; uint32_t vsz, va, rsz, ro, oz; };
// PE yapisi: p.veri (tum dosya), p.bolumler (vector<Bolum>)

namespace evren {

struct Kanit { std::string metin; int agirlik; };   // agirlik: 3=kesin, 2=guclu, 1=zayif

// v7 girde baglami — vmpdet5.cpp adapter'dan doldurulur
struct Girdi {
    uint32_t giris_rva = 0;      // AddressOfEntryPoint
    uint32_t cli_rva = 0;        // veri_dizin[14][0] (.NET CLI basligi)
    uint32_t cli_boy = 0;        // veri_dizin[14][1]
    bool makine64 = false;       // AMD64
};

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
    // v7:
    std::string ep_aile, ep_surum, ep_imza;   // en iyi EP imzasi
    std::string ep_tablo;                     // "PEiD" / "DIE"
    std::vector<std::string> ep_adaylar;      // ilk 8 aday (kanit listesi)
    std::string net_aile, net_surum;          // .NET motor karari
    std::vector<std::string> net_streamlar;   // standart-disi metadata stream'leri
    std::string themida_surum;                // Themida derin blogu
    bool ep_kararli = false;                  // v7: aile karari EP imzasindan mi geldi?
    bool tespit_edildi = false;
};

// ---------- yardimcilar ----------
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

// RVA -> dosya ofseti (bolumler uzerinden)
template <class BolumTipi>
inline uint32_t rva_ofset(const std::vector<BolumTipi>& bolumler, uint32_t rva) {
    for (auto& b : bolumler)
        if (rva >= b.va && rva < b.va + (b.vsz ? b.vsz : b.rsz))
            return b.ro + (rva - b.va);
    return 0;
}

// ---------- nibble-joker desen eslestirici (PEiD/DIE format) ----------
// desen: hex karakterleri + '.' (joker nibble). 2 karakter = 1 bayt.
// geri donus: eslesirse KESIN-nibble sayisi, yoksa -1
inline int desen_ep_eslestir(const uint8_t* v, size_t kalan, const char* desen) {
    int kesin = 0;
    size_t di = 0, bi = 0;
    while (desen[di]) {
        if (bi >= kalan) return -1;
        char h = desen[di];
        char l = desen[di + 1] ? desen[di + 1] : '0';
        if (h == '.' && l == '.') {           // tam bayt joker
            // kesinlik yok
        } else if (h == '.' || l == '.') {    // yarim bayt joker (tek nibble sabit)
            uint8_t gercek = v[bi];
            int gh = (gercek >> 4) & 0xF, gl = gercek & 0xF;
            int hh = -1, ll = -1;
            if (h != '.') hh = (h <= '9') ? h - '0' : (h | 32) - 'a' + 10;
            if (l != '.') ll = (l <= '9') ? l - '0' : (l | 32) - 'a' + 10;
            if (hh >= 0 && hh != gh) return -1;
            if (ll >= 0 && ll != gl) return -1;
            if (hh >= 0) kesin++;
            if (ll >= 0) kesin++;
        } else {                              // tam bayt sabit
            uint8_t istenen = 0;
            for (int k = 0; k < 2; k++) {
                char c = (k == 0) ? h : l;
                istenen <<= 4;
                if (c >= '0' && c <= '9') istenen |= (uint8_t)(c - '0');
                else if (c >= 'a' && c <= 'f') istenen |= (uint8_t)(c - 'a' + 10);
                else if (c >= 'A' && c <= 'F') istenen |= (uint8_t)(c - 'A' + 10);
                else return -1;
            }
            if (v[bi] != istenen) return -1;
            kesin += 2;
        }
        di += 2;
        bi += 1;
    }
    return kesin;
}

// ============================================================================
// S0 — .NET CLI METADATA MOTORU
// ============================================================================
struct NetStream { std::string ad; uint32_t ofset, boy; };   // ofset: meta kokune gore

template <class BolumTipi>
struct NetCozum {
    bool gecerli = false;                 // BSJB bulundu
    uint32_t meta_kok = 0;                // dosya ofseti
    uint32_t meta_boy = 0;
    std::string clr_surum;                // "v4.0.30319"
    std::vector<NetStream> streamlar;
    int strings_idx = -1;                 // #Strings stream indeksi
    int us_idx = -1;                      // #US stream indeksi
};

template <class BolumTipi>
NetCozum<BolumTipi> net_cozumle(const std::vector<uint8_t>& v,
                                const std::vector<BolumTipi>& bolumler,
                                uint32_t cli_rva) {
    NetCozum<BolumTipi> nc;
    if (!cli_rva || cli_rva == 0xFFFF) return nc;
    uint32_t cli_ofset = rva_ofset(bolumler, cli_rva);
    if (!cli_ofset || cli_ofset + 24 > v.size()) return nc;
    // CLI header: +0 cb, +4 maj, +6 min, +8 MetaData RVA, +12 MetaData Size
    uint32_t meta_rva, meta_boy;
    memcpy(&meta_rva, &v[cli_ofset + 8], 4);
    memcpy(&meta_boy, &v[cli_ofset + 12], 4);
    if (!meta_rva) return nc;
    uint32_t kok = rva_ofset(bolumler, meta_rva);
    if (!kok || kok + 16 > v.size()) return nc;
    if (memcmp(&v[kok], "BSJB", 4) != 0) return nc;
    nc.gecerli = true;
    nc.meta_kok = kok;
    nc.meta_boy = meta_boy ? meta_boy : (uint32_t)v.size() - kok;
    if ((uint64_t)nc.meta_kok + nc.meta_boy > v.size()) nc.meta_boy = (uint32_t)v.size() - kok;
    // surum dizgisi: +12 Length, +16 VersionString
    uint32_t ver_boy = 0;
    memcpy(&ver_boy, &v[kok + 12], 4);
    if (ver_boy && ver_boy <= 256 && kok + 16 + ver_boy <= v.size()) {
        char tb[256] = {0};
        memcpy(tb, &v[kok + 16], std::min<size_t>(ver_boy, 255));
        nc.clr_surum = std::string(tb, strnlen(tb, 255));
    }
    uint32_t p = kok + 16 + ((ver_boy + 3) & ~3u);   // 4'e hizala
    if (p + 4 > v.size()) return nc;
    uint16_t stream_adet = 0;
    memcpy(&stream_adet, &v[p + 2], 2);
    p += 4;
    // stream basliklari: Offset(4) Size(4) Name\0 (4'e hizali)
    for (uint16_t i = 0; i < stream_adet && i < 16 && p + 8 <= v.size(); i++) {
        uint32_t so = 0, sb = 0;
        memcpy(&so, &v[p], 4);
        memcpy(&sb, &v[p + 4], 4);
        p += 8;
        char ad[32] = {0};
        size_t an = 0;
        while (p < v.size() && an < 31 && v[p] != 0) { ad[an++] = (char)v[p++]; }
        if (p < v.size()) p++;                    // NUL
        p = (p + 3) & ~3u;                        // hizala
        std::string ad_s(ad, an);
        size_t bosluksuz = ad_s.find(' ');
        if (bosluksuz != std::string::npos) ad_s = ad_s.substr(0, bosluksuz);  // "#Strings " -> "#Strings"
        nc.streamlar.push_back({ad_s, so, sb});
        if (ad_s == "#Strings") nc.strings_idx = (int)nc.streamlar.size() - 1;
        else if (ad_s == "#US") nc.us_idx = (int)nc.streamlar.size() - 1;
    }
    return nc;
}

// yigin/metaveri bolgesinde ASCII terim ara
inline bool bolgede_ascii(const std::vector<uint8_t>& v, uint32_t bas, uint32_t boy,
                          const char* terim) {
    if (!bas || bas >= v.size()) return false;
    uint32_t son = bas + boy;
    if (son > v.size()) son = (uint32_t)v.size();
    size_t n = strlen(terim);
    if (!n || bas + n > son) return false;
    for (uint32_t i = bas; i + n <= son; i++)
        if (memcmp(&v[i], terim, n) == 0) return true;
    return false;
}

// UTF-16LE isaret arama (#US yigini / metadata)
inline bool utf16_isaret(const std::vector<uint8_t>& v, uint32_t bas, uint32_t boy,
                         const char* metin) {
    if (!bas || bas >= v.size()) return false;
    uint32_t son = bas + boy;
    if (son > v.size()) son = (uint32_t)v.size();
    size_t n = strlen(metin);
    if (!n) return false;
    for (uint32_t i = bas; i + n * 2 <= son; i += 2) {
        bool tamam = true;
        for (size_t k = 0; k < n; k++)
            if (v[i + k * 2] != (uint8_t)metin[k] || v[i + k * 2 + 1] != 0) { tamam = false; break; }
        if (tamam) return true;
    }
    return false;
}

// .NET motoru — isaretleri tarar, kanit + aile karari uretir
template <class BolumTipi>
void net_motor(const std::vector<uint8_t>& v, const NetCozum<BolumTipi>& nc,
               EvrenTarama& e) {
    using namespace universaldb;
    if (!nc.gecerli) return;

    // --- standart-disi metadata stream'leri (kanit + Babel ailesi)
    static const char* const STANDART[] = {"#~", "#-", "#Strings", "#US", "#GUID", "#Blob", "#Pdb", ""};
    for (auto& s : nc.streamlar) {
        bool standart = false;
        for (int i = 0; STANDART[i][0]; i++)
            if (s.ad == STANDART[i]) { standart = true; break; }
        if (!standart && !s.ad.empty()) {
            e.net_streamlar.push_back(s.ad);
            if (s.ad == "Babel") {
                e.kanitlar.push_back({"metadata stream adi \"Babel\" — Babel .NET (K1: de4dot Babel_NET/Deobfuscator.cs:125 HasMetadataStream)", 3});
                if (e.net_aile.empty()) e.net_aile = "Babel .NET";
            } else {
                e.kanitlar.push_back({"standart-disi metadata stream: \"" + s.ad + "\"", 2});
            }
        }
    }

    // --- #Strings yigini taramasi (tip/ad-uzayi adlari)
    if (nc.strings_idx >= 0) {
        const NetStream& s = nc.streamlar[nc.strings_idx];
        uint32_t sb = nc.meta_kok + s.ofset;
        uint32_t sboy = s.boy;
        for (auto& m : NET_TABLO) {
            if (bolgede_ascii(v, sb, sboy, m.isaret)) {
                e.kanitlar.push_back({std::string(".NET metadata \"") + m.isaret + "\" — " + m.aile + " (" + m.not_ + ")", 3});
                if (e.net_aile.empty()) e.net_aile = m.aile;
            }
        }
    }

    // --- ham metadata bolgesi taramasi (surum su damgalari — #Blob icinde yasar)
    for (auto& m : NET_SU_TABLO) {
        size_t n = strlen(m.isaret);
        for (uint32_t i = nc.meta_kok; i + n <= (uint64_t)nc.meta_kok + nc.meta_boy; i++) {
            if (memcmp(&v[i], m.isaret, n) != 0) continue;
            // surum cozumle: izleyen [0-9A-Za-z.+-] karakterleri
            char su[48] = {0};
            size_t k = 0;
            while (k < 47 && i + n + k < v.size()) {
                char c = (char)v[i + n + k];
                if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                    (c >= 'A' && c <= 'Z') || c == '.' || c == '+' || c == '-')
                    { su[k] = c; k++; }
                else break;
            }
            e.kanitlar.push_back({std::string(".NET su damgasi \"") + m.isaret + su + "\" — " + m.aile, 3});
            if (e.net_aile.empty()) { e.net_aile = m.aile; e.net_surum = su; }
            else if (e.net_aile == m.aile && k > 0) e.net_surum = su;
            break;
        }
    }

    // --- .NET Reactor UTF-16 anti-tamper mesaji (#US / metadata)
    if (utf16_isaret(v, nc.meta_kok, nc.meta_boy, "is tampered.")) {
        e.kanitlar.push_back({".NET user-string \"is tampered.\" — .NET Reactor anti-tamper (K3: DIE protector_NetReactor.2.sg)", 3});
        if (e.net_aile.empty()) e.net_aile = ".NET Reactor";
    }
}

// ============================================================================
// S7 — THEMIDA DERIN BLOGU
// ============================================================================
// EP deseni -> surum (K3: DIE protector_Themida.2.sg surum dallari;
// K1 capraz: Magicmida Themida64.pas:63 — x64'de V2 yok → 3.x)
struct ThemidaEp { const char* desen; const char* surum; };
static const ThemidaEp THEMIDA_EP[] = {
    { "83ec045053e801000000cc588bd840", "2.0.1.0-2.1.8.0" },
    { "83ec045053e801000000cc5889c3402d........2d........05........803bcc75..c60300", "2.X" },
    { "4883ec085053e801000000cc584889c348ffc0482d........482d........4805........803bcc75..c60300", "2.X (x64)" },
    { "558bec83c4d860e8000000005a81ea........8bdac745d8000000008b45d8408945d8817dd880000000", "1.0.X-1.8.X (sikistirmasiz)" },
    { "8bc58bd460e8000000005d81ed........8995........89b5........8985........83bd", "1.X SecureEngine (sikistirmasiz)" },
    { "e9........8bc58bd460e8", "1.1.X-1.2.X" },
    { "eb..e9........e9........565053e8........5889c3402d", "2.X+" },
    { "b8........600bc074..e8000000005805..0000008038e975", "1.0.X.X-1.9.X" },
};
static const int THEMIDA_EP_ADET = sizeof(THEMIDA_EP) / sizeof(THEMIDA_EP[0]);

// ============================================================================
// ANA MOTOR
// ============================================================================
template <class BolumTipi, class StandadPred>
EvrenTarama tara(const std::vector<uint8_t>& pe_veri,
                 const std::vector<BolumTipi>& bolumler,
                 StandadPred standart_adi,
                 bool (*korude_ara)(const std::vector<uint8_t>&, const char*, void*),
                 void* koru_baglam,
                 const Girdi& girdi = Girdi()) {
    using namespace universaldb;
    EvrenTarama e;
    Girdi g = girdi;

    // --- bolge hesaplari
    size_t dosya_boyu = pe_veri.size();
    size_t baslik_son = std::min<size_t>(0x1000, dosya_boyu);
    size_t kuyruk_bas = dosya_boyu > 8192 ? dosya_boyu - 8192 : 0;

    // koruyucu (standart-disi) bolumler — UPX istisnasiyla (v6 notu korunur)
    std::vector<const BolumTipi*> koru;
    std::vector<const BolumTipi*> tum;
    for (auto& b : bolumler) {
        bool upx_adi = false;
        for (const char* u : {"UPX0","UPX1","UPX2",".UPX0",".UPX1",".UPX2"})
            if (dizgi_esit_mi_kucuk(b.ad, u)) { upx_adi = true; break; }
        if (!standart_adi(b.ad) || upx_adi) { koru.push_back(&b); tum.push_back(&b); }
        else tum.push_back(&b);
    }
    std::vector<const BolumTipi*> eslesme_listesi = koru;

    // EP ofseti + EP bolumu
    uint32_t ep_ofset = g.giris_rva ? rva_ofset(bolumler, g.giris_rva) : 0;
    const BolumTipi* ep_bolumu = nullptr;
    if (g.giris_rva)
        for (auto& b : bolumler)
            if (g.giris_rva >= b.va && g.giris_rva < b.va + (b.vsz ? b.vsz : b.rsz))
                { ep_bolumu = &b; break; }

    // --- S0: .NET CLI metadata motoru
    NetCozum<BolumTipi> nc = net_cozumle(pe_veri, bolumler, g.cli_rva);
    if (nc.gecerli) {
        e.kanitlar.push_back({".NET CLR metadata (BSJB) — CLR surum " + nc.clr_surum, 1});
        net_motor(pe_veri, nc, e);
    }

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
            if (!en_iyi || eslesme > en_iyi_eslesme) {
                en_iyi = &imza;
                en_iyi_eslesme = eslesme;
            }
            bool var = false;
            for (int i = 0; i < vuran_sayi; i++) if (vuran_saticilar[i] == imza.satici) var = true;
            if (!var && vuran_sayi < 8) vuran_saticilar[vuran_sayi++] = imza.satici;
        }
    }

    // DIE bolum-adi kontrolleri — DESTEK KANITI (aile karari degil; genel adlar filtreli)
    {
        static const char* const GENEL_ADLAR[] = {".text",".data",".rsrc",".idata",".didata",".reloc",
            ".CRT",".drectve",".minfo",".debug","CODE","DATA","BSS",".bss",".tls",".rdata",".pdata",
            ".xdata",".edata",".gfids",".00cfg","!Sugar","30cm","adr","have","txt0",""};
        for (auto& ad : diedb::AD_TABLO) {
            bool genel = false;
            for (int i = 0; GENEL_ADLAR[i][0]; i++)
                if (dizgi_esit_mi_kucuk(ad.bolum, GENEL_ADLAR[i])) { genel = true; break; }
            if (genel) continue;
            for (auto* b : eslesme_listesi)
                if (dizgi_esit_mi_kucuk(b->ad, ad.bolum)) {
                    e.kanitlar.push_back({std::string("bolum adi '") + b->ad + "' — " + ad.aile +
                                          " (K3: DIE kurali)", 2});
                    break;
                }
        }
    }

    // --- S2: sahte imza demeti kurali (v6 korunur)
    if (vuran_sayi >= 2) {
        int sahte_aday = 0;
        for (int i = 0; i < vuran_sayi; i++)
            for (auto& sa : SAHTE_AILELER)
                if (sa.satici == vuran_saticilar[i]) sahte_aday++;
        if (sahte_aday >= 2) {
            e.sahte_imza_demeti = true;
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
            return e;
        }
    }

    // --- S3: bayt-dizgisi imzalari (bolge kisitli, v6 korunur)
    auto dizgi_bolge_vur = [&](const char* dizgi, uint8_t bolge) {
        if (bolge & R_BASLIK) if (bayt_icinde(pe_veri, 0, baslik_son, dizgi)) return true;
        if (bolge & R_KUYRUK) if (bayt_icinde(pe_veri, kuyruk_bas, dosya_boyu, dizgi)) return true;
        if ((bolge & R_KORU) && korude_ara) if (korude_ara(pe_veri, dizgi, koru_baglam)) return true;
        return false;
    };

    std::vector<std::pair<const BaytImza*, int>> dizgi_vuruslari;
    for (auto& imza : DIZGI_TABLO)
        if (dizgi_bolge_vur(imza.dizgi, imza.bolge))
            dizgi_vuruslari.push_back({&imza, 2});
    for (auto& kv : dizgi_vuruslari)
        e.kanitlar.push_back({"dizgi: \"" + std::string(kv.first->dizgi) + "\" (" + kv.first->not_ + ")", kv.second});

    // v7: R_TUM imzalari — KARISTIRILMIS SAKLI_TABLO'dan (oz-referans kalkani:
    // bu dizgiler dedektorun kendi binary'sinde ACIK yer almaz; obfus.h
    // FAKE_SIGNATURES sahteciligi ile gercek korumali dosyada hala bulunur)
    std::vector<std::string> sakli_vuruslar;
    for (auto& si : SAKLI_TABLO) {
        char coz[96];
        size_t n = sakli_coz(*si.dizgi, coz, sizeof coz);
        if (n && bayt_icinde(pe_veri, 0, dosya_boyu, coz)) {
            e.kanitlar.push_back({std::string("dizgi: \"") + coz + "\" (" + si.not_ + ")", 2});
            sakli_vuruslar.push_back(coz);
        }
    }
    // sakli vuruslar SADECE kanit uretir (obfus.h sahtecilik destegi);
    // aile karari bolum-adi demet kuraliyla verilir (S2) — burada dizgi
    // karsilastirma SABITI YOK: oz-referans kalkani (dedektorun kendi
    // binary'sinde bu dizgiler bulunmaz, karsilastirma sabitleri bulunurdu!)

    // --- S4: GIRIS NOKTASI bayt-imza motoru (PEiD 2771 + DIE 1292)
    struct EpVurus { const char* ad; const char* aile; const char* surum; int kesin; int toplam; const char* tablo; };
    std::vector<EpVurus> ep_vuruslar;
    if (ep_ofset && ep_ofset < dosya_boyu) {
        size_t kalan = dosya_boyu - ep_ofset;
        for (auto& imza : peiddb::EP_TABLO) {
            int k = desen_ep_eslestir(&pe_veri[ep_ofset], kalan, imza.desen);
            if (k >= 0)
                ep_vuruslar.push_back({imza.ad, imza.aile, imza.surum, k,
                                       (int)strlen(imza.desen), "PEiD"});
        }
        for (auto& imza : diedb::EP_TABLO) {
            int k = desen_ep_eslestir(&pe_veri[ep_ofset], kalan, imza.desen);
            if (k >= 0)
                ep_vuruslar.push_back({imza.aile, imza.aile, "", k,
                                       (int)strlen(imza.desen), "DIE"});
        }
        std::sort(ep_vuruslar.begin(), ep_vuruslar.end(),
                  [](const EpVurus& a, const EpVurus& b) {
                      if (a.kesin != b.kesin) return a.kesin > b.kesin;
                      return a.toplam > b.toplam;
                  });
        int sira = 0;
        for (auto& ev : ep_vuruslar) {
            if (sira < 8) {
                char tampon[352];
                snprintf(tampon, sizeof tampon, "EP imzasi (%s): %s%s%s [@0x%X, %d kesin bayt]",
                         ev.tablo, ev.ad, ev.surum[0] ? " v" : "", ev.surum, ep_ofset, ev.kesin / 2);
                e.kanitlar.push_back({tampon, ev.kesin >= 12 ? 3 : 2});
                e.ep_adaylar.push_back(std::string(ev.ad) + (ev.surum[0] ? " v" + std::string(ev.surum) : ""));
            }
            sira++;
        }
    }

    // --- S5: tam-tarama imzalari (PEiD ep_only=false) — SINIRLI bolge:
    //     EP-bolumu + koruyucu bolumlerin ilk 256KB / son 64KB parcasi
    {
        auto parcada_ara = [&](uint32_t bas, uint32_t son) {
            if (bas >= son || son > dosya_boyu) return;
            for (auto& imza : peiddb::TUM_TABLO) {
                for (uint32_t i = bas; i < son; i++) {
                    int k = desen_ep_eslestir(&pe_veri[i], dosya_boyu - i, imza.desen);
                    if (k >= 24) {
                        char tampon[352];
                        snprintf(tampon, sizeof tampon, "bolum-imzasi (PEiD): %s%s%s [@0x%X]",
                                 imza.ad, imza.surum[0] ? " v" : "", imza.surum, i);
                        e.kanitlar.push_back({tampon, 2});
                        if (e.ep_aile.empty()) { e.ep_aile = imza.aile; e.ep_surum = imza.surum; e.ep_imza = imza.ad; e.ep_tablo = "PEiD(bolum)"; }
                        break;
                    }
                }
            }
        };
        if (ep_bolumu && ep_bolumu->rsz) {
            uint32_t bb = ep_bolumu->ro, bo = ep_bolumu->rsz;
            uint32_t son1 = bb + std::min<uint32_t>(bo, 0x40000);
            parcada_ara(bb, son1 > dosya_boyu ? (uint32_t)dosya_boyu : son1);
            if (bo > 0x50000) parcada_ara(bb + bo - 0x10000, bb + bo);
        }
        for (auto* b : koru) {
            if (b == ep_bolumu || !b->rsz) continue;
            uint32_t bb = b->ro, bo = b->rsz;
            if (bb + bo > dosya_boyu) continue;
            parcada_ara(bb, bb + std::min<uint32_t>(bo, 0x40000));
            if (bo > 0x50000) parcada_ara(bb + bo - 0x10000, bb + bo);
        }
    }

    // --- S6a: TinyLoad .pxkey XXTEA anahtar blogu (v7: cozulmus karsilastirma)
    {
        uint8_t anahtar[32];
        sakli_coz_bayt(SK_TINYLOAD, anahtar);
        size_t n = SK_TINYLOAD.boy;
        if (dosya_boyu >= n)
            for (size_t i = 0; i + n <= dosya_boyu; i++)
                if (!memcmp(&pe_veri[i], anahtar, n)) {
                    e.kanitlar.push_back({"TinyLoad XXTEA anahtar blogu (C0DE1337/FEEDF00D/CAFEBABE/DEADBEEF/8BADF00D/B007DEAD) @0x" + std::to_string(i), 3});
                    if (e.aile.empty()) { e.aile = "TinyLoad"; e.kategori = "packer/vm"; e.kanit_seviyesi = "K1"; e.tespit_edildi = true; }
                    break;
                }
    }

    // --- S6b: UPX derin cozumleme
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

    // --- S6c: PyInstaller EOF cookie cozumleme
    {
        if (dosya_boyu >= sizeof(PyiCookie)) {
            for (size_t ofset : {(size_t)0, (size_t)8, (size_t)88}) {
                size_t konum = dosya_boyu - (ofset == 0 ? sizeof(PyiCookie) : ofset);
                if (konum + 8 > dosya_boyu) continue;
                if (pe_veri[konum] == 'M' && pe_veri[konum+1] == 'E' && pe_veri[konum+2] == 'I') {
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
                        if (e.aile.empty()) { e.aile = "PyInstaller"; e.kategori = "script-packer"; e.kanit_seviyesi = "K1"; e.tespit_edildi = true; }
                        break;
                    }
                }
            }
        }
    }

    // --- S7: THEMIDA DERIN BLOGU
    bool themida_bolum = false;
    for (auto* b : eslesme_listesi)
        for (const char* tn : {".themida", ".taz", ".tsuarch", ".tsustub", ".winlice", ".themidac", ".boom"})
            if (dizgi_esit_mi_kucuk(b->ad, tn)) { themida_bolum = true; break; }
    if (ep_ofset && ep_ofset < dosya_boyu) {
        size_t kalan = dosya_boyu - ep_ofset;
        for (auto& t : THEMIDA_EP) {
            int k = desen_ep_eslestir(&pe_veri[ep_ofset], kalan, t.desen);
            if (k >= 0) {
                e.themida_surum = t.surum;
                char tampon[192];
                snprintf(tampon, sizeof tampon, "Themida EP imzasi: %s [%d kesin bayt @EP] (K3: DIE Themida kurali)", t.surum, k / 2);
                e.kanitlar.push_back({tampon, 3});
                break;
            }
        }
    }
    // x64 + Themida yapisi → 3.x (K1: Magicmida Themida64.pas:63)
    if (g.makine64 && (themida_bolum || !e.themida_surum.empty())) {
        if (!e.themida_surum.empty())
            e.themida_surum += " — x64 → 3.x+ (K1: Magicmida Themida64.pas:63)";
        else
            e.themida_surum = "3.x+ (x64 — K1: Magicmida Themida64.pas:63 'Themida V2 is not supported on x64')";
    }
    // Themida .NET stub bolum 0 icinde (DIE: 1.9 / 2.X)
    if (nc.gecerli && bolumler.size() >= 1) {
        const auto& b0 = bolumler[0];
        if (b0.rsz && b0.ro + b0.rsz <= dosya_boyu) {
            if (bolgede_ascii(pe_veri, b0.ro, b0.rsz, "\xB8\x00\x00\x00\x00\x60\x11\xC0")) {
                e.themida_surum = "1.9 (.NET)";
                e.kanitlar.push_back({"Themida .NET stub @bolum0: 1.9 (K3: DIE)", 3});
            } else if (bolgede_ascii(pe_veri, b0.ro, b0.rsz, "\x83\xEC\x04\x80\x53\xE8\x01\x00")) {
                e.themida_surum = "2.X (.NET)";
                e.kanitlar.push_back({"Themida .NET stub @bolum0: 2.X (K3: DIE)", 3});
            }
        }
    }

    // --- S8: NIHAI AILE KARARI
    // oncelik: bolum-ailesi (v6 guvenilir) > .NET > EP (>=6 kesin bayt) > dizgi

    if (en_iyi && e.aile.empty()) {
        e.aile = en_iyi->aile;
        e.kategori = en_iyi->kategori;
        e.kanit_seviyesi = std::string(en_iyi->kanit).substr(0, 2);
        char tampon[192];
        snprintf(tampon, sizeof tampon, "bolum eslesmesi x%d: %s", en_iyi_eslesme, en_iyi->kanit);
        e.kanitlar.push_back({tampon, 3});
    }

    // .NET ailesi
    if (!e.net_aile.empty()) {
        if (e.aile.empty() || e.aile.rfind("VMProtect", 0) != 0) {
            if (e.aile.empty()) {
                e.aile = e.net_aile + (e.net_surum.empty() ? "" : " " + e.net_surum);
                e.kategori = ".NET protector/obfuscator";
                e.kanit_seviyesi = "K1/K3";
            } else {
                e.kanitlar.push_back({".NET katmani: " + e.net_aile + (e.net_surum.empty() ? "" : " " + e.net_surum), 2});
            }
        }
    }

    // EP ailesi (en kesin vurus >= 6 bayt kesin = 12 nibble)
    if (!ep_vuruslar.empty()) {
        const EpVurus& en = ep_vuruslar[0];
        e.ep_aile = en.aile; e.ep_surum = en.surum; e.ep_imza = en.ad; e.ep_tablo = en.tablo;
        if (e.aile.empty() && en.kesin >= 12) {
            e.aile = en.aile;
            e.kanit_seviyesi = "K3";
            e.kategori = "packer/protector (EP imzasi)";
            e.ep_kararli = true;                 // v7: aile EP imzasindan — VMP kapisina birakilabilir
            if (en.surum[0]) e.aile += std::string(" ") + en.surum;
        } else if (!e.aile.empty() && e.aile.rfind("VMProtect", 0) != 0 &&
                   en.kesin >= 12 && std::string(en.aile) != e.aile) {
            e.kanitlar.push_back({std::string("katman suphesi: EP ") + en.aile + " + bolum/yapi " + e.aile, 1});
        }
    }

    // dizgi ailesi (v6 mantigi) + v7 sakli dizgi vuruslari
    if (e.aile.empty()) {
        for (auto& kv : dizgi_vuruslari) {
            const char* d = kv.first->dizgi;
            if (kv.second >= 2) {
                if (!strcmp(d, "ConfusedByAttribute") || !strcmp(d, "ConfuserEx") || !strcmp(d, "KoiVM")) {
                    e.aile = "ConfuserEx (.NET)"; e.kategori = ".NET obfuscator"; e.kanit_seviyesi = "K1"; break;
                }
                if (!strcmp(d, "__compiled__")) { e.aile = "Nuitka"; e.kategori = "script-packer"; e.kanit_seviyesi = "K1"; break; }
                if (!strcmp(d, "Pyarmor") || !strcmp(d, "__pyarmor__") || !strcmp(d, "pytransform")) {
                    e.aile = "PyArmor"; e.kategori = "script-obfuscator"; e.kanit_seviyesi = "K1"; break; }
                if (!strcmp(d, "Nullsoft") || !strcmp(d, "NSIS Error")) { e.aile = "Nullsoft NSIS"; e.kategori = "installer"; break; }
                if (!strcmp(d, "Inno Setup")) { e.aile = "Inno Setup"; e.kategori = "installer"; break; }
                if (!strcmp(d, "SecureEngine")) { e.aile = "Themida / WinLicense (SecureEngine)"; e.kategori = "protector"; e.kanit_seviyesi = "K3"; break; }
                if (!strcmp(d, "Enigma protector") || !strcmp(d, "The Enigma Protector")) { e.aile = "Enigma Protector"; e.kategori = "protector"; e.kanit_seviyesi = "K3"; break; }
                if (!strcmp(d, "Themida") || !strcmp(d, "WinLicense")) { e.aile = "Themida / WinLicense"; e.kategori = "protector"; e.kanit_seviyesi = "K3"; break; }
                if (!strcmp(d, "PECompact2")) { e.aile = "PECompact"; e.kategori = "compressor"; break; }
                if (!strcmp(d, "ASProtect")) { e.aile = "ASProtect"; e.kategori = "protector"; break; }
                if (!strcmp(d, "Obsidium")) { e.aile = "Obsidium"; e.kategori = "protector"; break; }
            }
        }
        // (sakli vuruslar aile karari uretmez — yalnizca kanit; S2 demet kurali asil karar)
    }

    // Themida surum notu
    if (e.aile.rfind("Themida", 0) == 0 && !e.themida_surum.empty())
        e.kanitlar.push_back({"Themida surum: " + e.themida_surum, 3});

    e.tespit_edildi = !e.aile.empty();
    return e;
}

} // namespace evren
