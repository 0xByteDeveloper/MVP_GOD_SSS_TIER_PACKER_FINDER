// ============================================================================
// universal_tara.h — UNIVERSAL PACKER TARAMA MOTORU v8 (GOD STATE)
// ============================================================================
// Girdi: universal_db.h (K1/K2/K3 imza DB) + peid_db.h (4787 EP + 450 tam
// tarama imzasi; 10 kaynak sozlugu birlesimi) + die_db.h (1287 EP + 42
// bolum-icerik + 90 bolum-adi) + bolum_db.h (129 packer bolum adi + 23 obfus
// sahtesi) + algoritma_db.h (obfus desenleri + sahte imza + EP stub + DRM).
//
// v8 KATMANLARI (v7'nin tamami korunur):
//   S0   .NET CLI metadata motoru (v7)
//   S1   bolum-adi aile eslesmesi (v6) + DIE bolum-adi + BOLUM ATLASI (v8:
//        hexacorn 92 + PE-LiteScan ~70 surumli + Manalyze + packpeek)
//   S2   sahte-imza demeti kalkani (v6) + obfus SAHTE bolum adi tablosu (v8)
//   S3   bolge-kisitli dizgi imzalari (v6)
//   S4   EP bayt-imza motoru — PEiD 4787 + DIE 1287 (v8: 2.4k yeni imza)
//   S5   tam-tarama imzalari — sinirli bolge (v7)
//   S6   ozel bloklar: TinyLoad XXTEA, UPX packheader, PyInstaller (v7)
//   S7   THEMIDA derin blogu (v7)
//   S8   nihai aile karari (v7) — v8: yeni kanit turleri baglanir
//   S9   BINTROPY ENTROPI MOTORU (v8 YENI) — IEEE 4140989: 256-bayt blok
//        Shannon entropisi, yari-sifir bloklar yok sayilir; esikler
//        ort>=6.677 en-yuksek>=7.199 (packing-box/bintropy THRESHOLD'leri);
//        dosya-geneli + bolum-bazli + kuyruk(overlay) analizi
//   S10  YAPISAL SEZGISEL MOTOR (v8 YENI) — 5 aractan birlesik algoritma:
//        pypackerdetect (EP-bolum siniflandirmasi: acceptable/delphi/driver/
//        alternative, ithalat<10, standart-disi bolum>=3), Manalyze (bolum
//        entropisi>7, WX bolumler, kaynaklar>dosya, RICH header checksum
//        dogrulamasi + @comp.id ithalat tutarliligi), PE-LiteScan (EP son
//        bolumde, .text yoksa, kuyruk entropisi>7.5, PUSHAD@EP, ozel DOS
//        stub, ithalat tablosu yoksa, garip bolum adlari), packerscope (EP
//        stub desenleri, SUSPICIOUS_APIS kumesi), PE-LiteScan KnownSections
//   S11  OBFUS.H DERIN BLOGU (v8 YENI) — ObfusHunter 17 deseni (junk code,
//        anti-debug, VM dispatch, obfh veri blogu) + ObfusFake sahte imza
//        desenleri (Enigma/Denuvo/Nuitka/Screen2EXE) + sahte dongle dizgileri
//   S12  OYUN DRM / TICARI PROTECTOR DIZGILERI (v8 YENI) — DRMDetector
//        listesi: Denuvo/Arxan/SteamStub/... dosya-geneli tarama
//
// GUVENLIK: dedektorun KENDI binary'si temiz gecmelidir; tum aramalar bolge
// kisitli; EP imzalari yalniz GIRIS NOKTASI ofsetinde eslesir; entropi ve
// yapisal bulgular KANIT uretir, asil aile karari imza/bolum kaynaklidir.
// ============================================================================
#pragma once
#include <string>
#include <vector>
#include <cstring>
#include <cstdint>
#include <cmath>
#include <algorithm>
#include "universal_db.h"
#include "peid_db.h"
#include "die_db.h"
#include "bolum_db.h"
#include "algoritma_db.h"

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
    // ---- v8 eklentileri
    uint32_t e_lfanew = 0;                 // DOS->PE gecis ofseti (RICH kontrolu)
    uint32_t ithalat_toplam = 0;           // toplam ithal edilen fonksiyon
    bool net_mscoree = false;              // mscoree.dll!_CorExeMain (.NET muafiyeti)
    uint32_t kaynak_boy = 0;               // kaynak toplam boyu (veri_dizin[2][1])
    uint32_t reloc_rva = 0;                // veri_dizin[5][0]
    std::vector<std::string> ithalat_fonksiyonlar; // "dll!func" (sinirli)
    std::vector<std::string> ithalat_dll;         // ithal edilen DLL ADLARI (DIE kosullari)
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
    // ---- v8: entropi motoru (S9)
    double ent_dosya = 0.0;                   // dosya-geneli Shannon entropisi
    double ent_ort = 0.0;                     // bintropy blok-ortalamasi (256B)
    double ent_en_yuksek = 0.0;               // bintropy en-yuksek blok
    bool bintropy_packed = false;             // IEEE 4140989 karari
    double ent_ep_bolum = -1.0;               // EP bolumu entropisi (-1 = yok)
    double ent_kuyruk = -1.0;                 // overlay/kuyruk entropisi
    uint32_t kuyruk_boy = 0;                  // overlay boyu
    // ---- v8: yapisal bulgular (S10)
    std::vector<std::string> yapisal;         // yapisal sezgisel bulgular
    bool rich_header_gecersiz = false;        // RICH checksum uyusmazligi
    int ithalat_sayisi = -1;                  // -1 = hesaplanmadi
    // ---- v8: obfus derin bulgular (S11)
    std::vector<std::string> obfus_bulgular;  // ObfusHunter desen vuruslari
    bool obfus_sahte_imza = false;            // ObfusFake deseni bulundu
    bool obfus_sahte_dongle = false;          // sahte dongle dizgisi bulundu
    // ---- v8: DRM bulgulari (S12)
    std::vector<std::string> drm_bulgular;    // DRMDetector dizgi vuruslari
    // ---- v8: bolum atlasi (S1 genisletme)
    std::vector<std::string> bolum_atlasi;    // bolumdb eslesmeleri
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

// v8: DIE kosulu — ithal DLL listesinde bu kutuphane var mi? (buyuk/kucuk harf duyarsiz)
inline bool girdi_kutuphane_var(const std::vector<std::string>& dller, const char* hedef) {
    if (!hedef || !hedef[0]) return true;
    size_t n = strlen(hedef);
    for (auto& d : dller) {
        if (d.size() != n) continue;
        bool tamam = true;
        for (size_t i = 0; i < n; i++) {
            char a = d[i] >= 'A' && d[i] <= 'Z' ? d[i] + 32 : d[i];
            char b = hedef[i] >= 'A' && hedef[i] <= 'Z' ? hedef[i] + 32 : hedef[i];
            if (a != b) { tamam = false; break; }
        }
        if (tamam) return true;
    }
    return false;
}

// ---------- v8: rol32 + Shannon entropi yardimcilari ----------
inline uint32_t rol32_v8(uint32_t x, uint32_t n) {
    n = n % 32;
    return (x << n) | (x >> (-n & 31));
}

// Shannon entropisi [0..8] — bintropy/packerscope ile ayni formül
inline double shannon_entropi(const uint8_t* v, size_t n) {
    if (n <= 1) return 0.0;
    uint32_t freq[256] = {0};
    for (size_t i = 0; i < n; i++) freq[v[i]]++;
    double h = 0.0;
    for (int b = 0; b < 256; b++) {
        if (!freq[b]) continue;
        double p = (double)freq[b] / (double)n;
        h -= p * (log(p) / log(2.0));
    }
    return h;
}

// bintropy blok entropisi (IEEE 4140989): 256-bayt bloklar; yari-sifir bloklar
// yok sayilir; (blok entropileri, ortalama) doner — packing-box/bintropy bintropy()
inline void bintropy_bloklar(const uint8_t* v, size_t n, size_t blok = 256,
                              std::vector<double>* cikti = nullptr,
                              double* ortalama = nullptr) {
    std::vector<double> ent;
    size_t say = 0;
    double top = 0.0;
    for (size_t i = 0; i < n; i += blok) {
        size_t k = (n - i < blok) ? (n - i) : blok;
        // yari-sifir kontrolu
        uint32_t sifir = 0;
        for (size_t j = 0; j < k; j++) if (!v[i + j]) sifir++;
        if (sifir > k / 2) { ent.push_back(-1.0); continue; }   // yok sayilan blok
        double h = shannon_entropi(&v[i], k);
        ent.push_back(h);
        top += h;
        say++;
    }
    if (cikti) *cikti = ent;
    if (ortalama) *ortalama = say ? top / say : 0.0;
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

    // --- S1b (v8): BOLUM ATLASI — bolumdb (hexacorn 92 + PE-LiteScan + Manalyze +
    //     packpeek); aile karari DEGIL, guclu destek kaniti + sahte-obfus isareti
    {
        int atlas_vurus = 0;
        std::string en_iyi_atlas;
        for (auto* b : eslesme_listesi) {
            bool tabloda = false;      // bu ad GERCEK aile kaniti olarak atlasta var mi?
            for (auto& kayit : bolumdb::TABLO) {
                if (!dizgi_esit_mi_kucuk(b->ad, kayit.ad)) continue;
                char tampon[288];
                snprintf(tampon, sizeof tampon, "bolum atlasi: '%s' -> %s (%s)",
                         b->ad.c_str(), kayit.aile, kayit.not_);
                e.bolum_atlasi.push_back(tampon);
                e.kanitlar.push_back({std::string("bolum adi '") + b->ad + "' — " + kayit.aile +
                                      " (K3: bolum atlasi: " + kayit.not_ + ")", 2});
                if (en_iyi_atlas.empty()) en_iyi_atlas = kayit.aile;
                atlas_vurus++;
                tabloda = true;
                break;
            }
            // obfus.h SAHTE bolum adi tablosu (ObfusFake-Remover): yalniz ATLASTA
            // OLMAYAN adlar sahte adayidir (.vmp0/.enigma1/UPX0 gibi adlar hem gercek
            // aile bolumu hem obfus sahtesi olabilir — gercek kanit atlastan gelirse
            // sahte isaretleme YAPILMAZ; 'logicoma'/'30cm'/'.dsstext' gibi ATLASTA
            // OLMAYAN adlar obfus fake-protection adayi sayilir)
            if (!tabloda)
                for (auto& sahte : bolumdb::SAHTE_TABLO) {
                    if (!dizgi_esit_mi_kucuk(b->ad, sahte.ad)) continue;
                    e.sahte_bolumler.push_back(b->ad);
                    e.kanitlar.push_back({std::string("bolum adi '") + b->ad + "' obfus.h sahte-listesinde (fake-protection adayi)", 1});
                    break;
                }
        }
        (void)atlas_vurus; (void)en_iyi_atlas;
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
            // v8: DIE kosullari — kutuphane importu + minimum boyut (orijinal .sg mantigi)
            if (imza.kutuphane[0] && !girdi_kutuphane_var(g.ithalat_dll, imza.kutuphane)) continue;
            if (imza.min_boyut && dosya_boyu <= imza.min_boyut) continue;
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

    // --- S4b (v8): MODERN (2025-2026) GERCEK CIKTI EP DESENLERI — Wine hatti
    //     kaniti: klasik userdb'ler 7.8x Enigma'yi bilmiyordu (BILINMEYEN KORUYUCU)
    if (ep_ofset && ep_ofset < dosya_boyu) {
        for (auto& me : algdb::MODERN_EP_TABLO) {
            if (desen_ep_eslestir(&pe_veri[ep_ofset], dosya_boyu - ep_ofset, me.desen) >= 0) {
                char t2[256];
                snprintf(t2, sizeof t2, "MODERN EP imzasi: %s %s @EP (%s)", me.aile, me.surum, me.kaynak);
                e.kanitlar.push_back({t2, 3});
                if (e.aile.empty()) {
                    e.aile = me.aile;
                    e.kategori = "protector";
                    e.kanit_seviyesi = "K1";         // gercek ciktidan olculmus
                    e.tespit_edildi = true;
                    e.ep_aile = me.aile; e.ep_surum = me.surum; e.ep_tablo = "MODERN(Wine)";
                    e.ep_kararli = true;
                }
            }
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

    // --- S9 (v8): BINTROPY ENTROPI MOTORU — IEEE 4140989
    //     esikler: ort >= 6.677 VE en-yuksek >= 7.199 (packing-box/bintropy THRESHOLDS)
    {
        e.ent_dosya = shannon_entropi(&pe_veri[0], dosya_boyu);
        std::vector<double> bloklar;
        double ort = 0.0;
        bintropy_bloklar(&pe_veri[0], dosya_boyu, 256, &bloklar, &ort);
        e.ent_ort = ort;
        double en_yuksek = 0.0;
        for (double d : bloklar) if (d > en_yuksek) en_yuksek = d;
        e.ent_en_yuksek = en_yuksek;
        e.bintropy_packed = (e.ent_ort >= 6.677 && e.ent_en_yuksek >= 7.199);
        char tampon[192];
        snprintf(tampon, sizeof tampon, "bintropy: dosya %.3f | blok-ort %.3f | en-yuksek %.3f %s",
                 e.ent_dosya, e.ent_ort, e.ent_en_yuksek,
                 e.bintropy_packed ? "-> PAKETLENMIS (IEEE 4140989)" : "");
        e.kanitlar.push_back({std::string(tampon), e.bintropy_packed ? 2 : 1});
        if (e.bintropy_packed)
            e.yapisal.push_back("bintropy: yuksek blok entropisi (ort>=6.677, en-yuksek>=7.199) — SIkISTIRILMIS/ENKRIPTE icerik");
        // EP bolumu entropisi (Manalyze esigi > 7.0)
        if (ep_bolumu && ep_bolumu->rsz && ep_bolumu->ro + (size_t)ep_bolumu->rsz <= dosya_boyu) {
            e.ent_ep_bolum = shannon_entropi(&pe_veri[ep_bolumu->ro], ep_bolumu->rsz);
            if (e.ent_ep_bolum > 7.0) {
                char t2[160];
                snprintf(t2, sizeof t2, "EP bolumu '%s' entropisi %.3f > 7.0 (Manalyze)", ep_bolumu->ad.c_str(), e.ent_ep_bolum);
                e.kanitlar.push_back({t2, 2});
                e.yapisal.push_back(std::string("bolum '") + ep_bolumu->ad.c_str() + "' entropisi > 7 — sikistirilmis (Manalyze)");
            }
        }
        // bolum-bazli entropi > 7.0 (Manalyze) — en yuksek 3 bolum raporlanir
        for (auto* b : tum) {
            if (!b->rsz || !b->ro || (size_t)b->ro + b->rsz > dosya_boyu) continue;
            double h = shannon_entropi(&pe_veri[b->ro], b->rsz);
            if (h > 7.0) {
                char t2[192];
                snprintf(t2, sizeof t2, "bolum '%s' entropisi %.3f > 7 (sikistirilmis/kriptolu)", b->ad.c_str(), h);
                e.kanitlar.push_back({t2, 2});
                if (e.yapisal.size() < 24)
                    e.yapisal.push_back(std::string("bolum '") + b->ad.c_str() + "' entropisi > 7 (Manalyze)");
            }
        }
        // kuyruk (overlay) analizi — PE-LiteScan: entropi > 7.5 = STRANGE_OVERLAY
        {
            uint32_t son_raw = 0;
            for (auto& b : bolumler) {
                uint32_t bitis = b.ro + b.rsz;
                if (bitis > son_raw && bitis <= dosya_boyu) son_raw = bitis;
            }
            if (dosya_boyu > son_raw + 64) {
                e.kuyruk_boy = (uint32_t)(dosya_boyu - son_raw);
                e.ent_kuyruk = shannon_entropi(&pe_veri[son_raw], e.kuyruk_boy);
                char t2[192];
                snprintf(t2, sizeof t2, "overlay/kuyruk: %u bayt, entropi %.3f%s",
                         e.kuyruk_boy, e.ent_kuyruk,
                         e.ent_kuyruk > 7.5 ? " > 7.5 — SIKISTIRILMIS VERI (PE-LiteScan STRANGE_OVERLAY)" : "");
                e.kanitlar.push_back({t2, e.ent_kuyruk > 7.5 ? 2 : 1});
                if (e.ent_kuyruk > 7.5)
                    e.yapisal.push_back("overlay entropisi > 7.5 — kuyrukta sikistirilmis veri (PE-LiteScan)");
            }
        }
    }

    // --- S10 (v8): YAPISAL SEZGISEL MOTOR — 5 aractan birlesik
    {
        // (a) EP konumu: null EP (pypackerdetect), EP hicbir bolumde degil,
        //     EP son bolumde (PE-LiteScan), EP bolumu duzensiz (pypackerdetect
        //     acceptable/alternative/delphi/driver siniflandirmasi)
        if (g.giris_rva == 0) {
            e.yapisal.push_back("giris noktasi NULL (pypackerdetect: 'Null entry point')");
            e.kanitlar.push_back({"EP RVA=0 — null giris noktasi (pypackerdetect)", 2});
        } else if (!ep_bolumu) {
            e.yapisal.push_back("EP hicbir bolume dusmuyor (pypackerdetect: 'EP does not fall in any section')");
            e.kanitlar.push_back({"EP hicbir bolume dusmuyor — kirilmis/bozuk PE ya da packer (pypackerdetect 'EP does not fall in any section')", 2});
        } else {
            // EP hangi bolumde? (ad, son-bolum-mi?)
            bool ep_son_bolumde = (ep_bolumu == &bolumler.back());
            if (ep_son_bolumde && bolumler.size() > 1) {
                char t2[160];
                snprintf(t2, sizeof t2, "EP son bolumde ('%s') — packer aliskanligi (PE-LiteScan LAST_SECTION_ENTRYPOINT)",
                         ep_bolumu->ad.c_str());
                e.kanitlar.push_back({t2, 2});
                e.yapisal.push_back(std::string("EP son bolumde: '") + ep_bolumu->ad.c_str() + "' (PE-LiteScan)");
            }
            // pypackerdetect EP-bolum sinifi
            static const char* const KABUL[] = {".text", ""};
            static const char* const ALTER[] = {".code", "text", ".text0", ".text1", ".text2", ".text3", ""};
            static const char* const DELPHI_BSS[] = {".BSS", "BSS", ".bss", ""};
            static const char* const DELPHI[] = {".itext", "CODE", ""};
            static const char* const SURUCU[] = {"INIT", ""};
            bool kabul = false, alter = false, dbss = false, delphi = false, surucu = false, dbss_var = false;
            for (auto& b : bolumler) for (int i = 0; DELPHI_BSS[i][0]; i++) if (dizgi_esit_mi_kucuk(b.ad, DELPHI_BSS[i])) { dbss_var = true; break; }
            for (int i = 0; KABUL[i][0]; i++) if (dizgi_esit_mi_kucuk(ep_bolumu->ad, KABUL[i])) { kabul = true; break; }
            for (int i = 0; ALTER[i][0]; i++) if (dizgi_esit_mi_kucuk(ep_bolumu->ad, ALTER[i])) { alter = true; break; }
            for (int i = 0; DELPHI[i][0]; i++) if (dizgi_esit_mi_kucuk(ep_bolumu->ad, DELPHI[i])) { delphi = true; break; }
            for (int i = 0; SURUCU[i][0]; i++) if (dizgi_esit_mi_kucuk(ep_bolumu->ad, SURUCU[i])) { surucu = true; break; }
            bool duzensiz = false;
            if (kabul) duzensiz = false;
            else if (dbss_var && delphi) duzensiz = false;      // Delphi BSS -> .itext/CODE EP
            else if (alter) duzensiz = false;
            else if (surucu) duzensiz = false;                  // surucu INIT bolumu
            else duzensiz = true;
            if (duzensiz) {
                char t2[192];
                snprintf(t2, sizeof t2, "EP bolumu '%s' duzensiz — kabul/alter/Delphi/surucu disi (pypackerdetect 'irregular EP section')",
                         ep_bolumu->ad.c_str());
                e.kanitlar.push_back({t2, 2});
                e.yapisal.push_back(std::string("EP bolumu duzensiz: '") + ep_bolumu->ad.c_str() + "' (pypackerdetect)");
            }
            // EP ilk bayt stub taramasi (packerscope EntryPointDetector + PE-LiteScan PUSHAD)
            if (ep_ofset && ep_ofset < dosya_boyu) {
                for (auto& st : algdb::EP_STUB) {
                    if (desen_ep_eslestir(&pe_veri[ep_ofset], dosya_boyu - ep_ofset, st.desen) >= 0) {
                        char t2[192];
                        snprintf(t2, sizeof t2, "EP stub %s @EP: %s (packerscope/PE-LiteScan)", st.kod, st.aciklama);
                        e.kanitlar.push_back({t2, 2});
                        e.yapisal.push_back(std::string("EP stub: ") + st.kod + " (" + st.aciklama + ")");
                        break;   // yalniz en spesifik ilk vurus
                    }
                }
            }
        }
        // (b) .text yoklugu (PE-LiteScan NO_TEXT_SECTION) — Delphi (CODE) ve .NET muaf
        {
            bool text_var = false;
            for (auto& b : bolumler) if (dizgi_esit_mi_kucuk(b.ad, ".text")) { text_var = true; break; }
            bool delphi = false;
            for (auto& b : bolumler) {
                if (dizgi_esit_mi_kucuk(b.ad, "CODE") || dizgi_esit_mi_kucuk(b.ad, ".itext")) { delphi = true; break; }
            }
            if (!text_var && !delphi && !nc.gecerli) {
                e.yapisal.push_back(".text bolumu yok (PE-LiteScan NO_TEXT_SECTION)");
                e.kanitlar.push_back({".text bolumu yok — packer/yabanci uretici (PE-LiteScan)", 2});
            }
        }
        // (c) ithalat analizi (pypackerdetect 'Too few imports' + Manalyze < 10;
        //     .NET mscoree muafiyeti her ikisinde de)
        e.ithalat_sayisi = (int)g.ithalat_toplam;
        if (!g.net_mscoree && g.ithalat_toplam < 10) {
            char t2[160];
            snprintf(t2, sizeof t2, "ithalat sayisi %u < 10 — packer aliskanligi (pypackerdetect/Manalyze 'low imports')",
                     (unsigned)g.ithalat_toplam);
            e.kanitlar.push_back({t2, 2});
            e.yapisal.push_back(std::string("ithalat < 10: ") + std::to_string(g.ithalat_toplam) + " (pypackerdetect/Manalyze)");
        }
        // (d) ithalat tablosu tamamen yoksa (PE-LiteScan IMPORT_TABLE_MISSING)
        if (g.ithalat_toplam == 0 && !nc.gecerli) {
            e.yapisal.push_back("ithalat tablosu yok (PE-LiteScan IMPORT_TABLE_MISSING)");
            e.kanitlar.push_back({"ithalat tablosu hic yok — bozuk/agresif packer (PE-LiteScan)", 2});
        }
        // (e) dinamik-yukleme IAT'i (packerscope IATDetector): yalniz
        //     LoadLibrary/GetProcAddress/VirtualAlloc kumesi
        if (!g.ithalat_fonksiyonlar.empty()) {
            int dinamik = 0, toplam_fn = 0;
            static const char* const DYNA[] = {"LoadLibraryA","LoadLibraryW","LoadLibraryExA","LoadLibraryExW",
                "GetProcAddress","GetModuleHandleA","GetModuleHandleW","VirtualAlloc","VirtualAllocEx",
                "VirtualProtect","VirtualProtectEx","NtProtectVirtualMemory","NtAllocateVirtualMemory",
                "IsDebuggerPresent","CheckRemoteDebuggerPresent","NtQueryInformationProcess",
                "RtlDecompressBuffer","WriteProcessMemory","CreateRemoteThread", ""};
            for (auto& f : g.ithalat_fonksiyonlar) {
                size_t un = f.find('!');
                if (un == std::string::npos) continue;
                std::string fn = f.substr(un + 1);
                toplam_fn++;
                for (int i = 0; DYNA[i][0]; i++)
                    if (fn == DYNA[i]) { dinamik++; break; }
            }
            if (toplam_fn >= 4 && dinamik * 100 >= toplam_fn * 80) {
                char t2[192];
                snprintf(t2, sizeof t2, "IAT neredeyse yalniz dinamik-yukleme API'leri (%d/%d) — packer stub (packerscope IATDetector)",
                         dinamik, toplam_fn);
                e.kanitlar.push_back({t2, 2});
                e.yapisal.push_back("IAT yalniz LoadLibrary/GetProcAddress turu — packer stub (packerscope)");
            }
        }
        // (f) WX/RWX bolumler (Manalyze 'writable and executable' + ObfusHunter RWX)
        for (auto* b : tum) {
            const uint32_t X = 0x20000000, W = 0x80000000, R = 0x40000000;
            if ((b->oz & X) && (b->oz & W)) {
                char t2[160];
                snprintf(t2, sizeof t2, "bolum '%s' yazilabilir+calistirilabilir (W%X) — Manalyze/ObfusHunter",
                         b->ad.c_str(), (b->oz & R) ? 3 : 2);
                e.kanitlar.push_back({t2, 2});
                e.yapisal.push_back(std::string("WX bolum: '") + b->ad.c_str() + "' (Manalyze)");
            }
        }
        // (g) kaynaklar dosyadan buyuk (Manalyze 'resources bigger than file')
        if (g.kaynak_boy && g.kaynak_boy > dosya_boyu) {
            char t2[160];
            snprintf(t2, sizeof t2, "kaynak toplami %u > dosya %zu — Manalyze", g.kaynak_boy, dosya_boyu);
            e.kanitlar.push_back({t2, 2});
            e.yapisal.push_back("kaynaklar dosyadan buyuk (Manalyze)");
        }
        // (h) VirtualSize >> SizeOfRawData (packer izi: bosaltma alani)
        for (auto* b : tum) {
            if (b->vsz && b->rsz && b->vsz > b->rsz * 4 + 0x1000 && b->vsz > 0x10000) {
                char t2[192];
                snprintf(t2, sizeof t2, "bolum '%s' VirtualSize 0x%X >> Raw 0x%X — packer bosaltma alani",
                         b->ad.c_str(), b->vsz, b->rsz);
                e.kanitlar.push_back({t2, 2});
                e.yapisal.push_back(std::string("bolum '") + b->ad.c_str() + "' vsz>>raw (packer bosaltma alani)");
            }
        }
        // (i) garip bolum adlari (PE-LiteScan WEIRD: ozel karakterler)
        for (auto* b : tum) {
            for (char c : b->ad) {
                if (c && (strchr("=+~!@#$%^&*()%:;\\|'`<> ", c) || (unsigned char)c < 0x20)) {
                    e.yapisal.push_back(std::string("garip bolum adi: '") + b->ad.c_str() + "' (PE-LiteScan WEIRD)");
                    e.kanitlar.push_back({std::string("bolum adi '") + b->ad.c_str() + "' garip karakter tasiyor (PE-LiteScan)", 1});
                    break;
                }
            }
        }
        // (i2) v8: BOS bolum adlari — gercek Enigma 7.8x ciktisi 7 bolumden 6-7'sini
        //      bosa birakir (Wine hatti kaniti); meşru PE'ler bolumlerini adlandirir
        {
            int bos_ad = 0;
            for (auto& b : bolumler)
                if (b.ad.empty() || b.ad.find_first_not_of('\0') == std::string::npos ||
                    b.ad.find_first_not_of(" \t") == std::string::npos) bos_ad++;
            if (bos_ad >= 5) {
                char t2[192];
                snprintf(t2, sizeof t2, "%d/%zu bolum adi BOS — modern Enigma 7.x / anti-analiz deseni (v8 Wine hatti)",
                         bos_ad, bolumler.size());
                e.yapisal.push_back(t2);
                e.kanitlar.push_back({t2, 2});
            }
        }
        // (j) ozel DOS stub (PE-LiteScan CUSTOM_DOS_STUB) — 4 standart dizgi disinda
        {
            if (dosya_boyu > 350 && g.e_lfanew >= 0x40 && g.e_lfanew <= 0x400) {
                static const char* const STUBLAR[] = {
                    "This program cannot be run in DOS mode.",
                    "This program must be run under Win32",
                    "This program must be run under Win64",
                    "This program requires Win32", ""};
                bool standart = false;
                for (int i = 0; STUBLAR[i][0]; i++)
                    if (bayt_icinde(pe_veri, 0x40, std::min<size_t>(0x200, dosya_boyu), STUBLAR[i])) { standart = true; break; }
                if (!standart) {
                    e.yapisal.push_back("standart-disi DOS stub (PE-LiteScan CUSTOM_DOS_STUB)");
                    e.kanitlar.push_back({"DOS stub standart degil — ozel uretici/packer (PE-LiteScan)", 1});
                }
            }
        }
        // (k) RICH header checksum dogrulamasi (Manalyze rich_header_tests)
        {
            uint32_t tarama_son = g.e_lfanew ? std::min<uint32_t>(g.e_lfanew, (uint32_t)dosya_boyu)
                                             : std::min<uint32_t>(0x400, (uint32_t)dosya_boyu);
            for (uint32_t i = 0; i + 8 <= tarama_son; i += 4) {
                uint32_t sozcuk = 0;
                memcpy(&sozcuk, &pe_veri[i], 4);
                if (sozcuk != 0x68636952) continue;          // "Rich"
                uint32_t xor_anahtari = 0;
                memcpy(&xor_anahtari, &pe_veri[i + 4], 4);
                // geriye dogru 8-bayt adimlarla DanS ara
                std::vector<std::tuple<uint16_t, uint16_t, uint32_t>> degerler;
                uint32_t dans_ofset = 0;
                uint32_t imlec = i;
                while (imlec >= 8) {
                    imlec -= 8;
                    uint64_t kodlanmis = 0;
                    memcpy(&kodlanmis, &pe_veri[imlec], 8);
                    uint32_t sayim = (uint32_t)(kodlanmis >> 32) ^ xor_anahtari;
                    uint32_t kimlik = (uint32_t)kodlanmis ^ xor_anahtari;
                    if (kimlik == 0x536E6144) { dans_ofset = imlec; goto dans_bulundu; }
                    degerler.push_back({(uint16_t)(kimlik >> 16), (uint16_t)kimlik, sayim});
                    if (degerler.size() > 64) break;
                }
                break;   // Rich bulundu ama DanS yok — gecersiz, kontrol bitir
            dans_bulundu:
                if (dans_ofset) {
                    // checksum = DanS_ofset + DOS-stub rol32 toplami (e_lfanew istisnasi) + comp.id'ler
                    uint32_t checksum = dans_ofset;
                    for (uint32_t k = 0; k < dans_ofset; k++) {
                        if (k >= 0x3c && k < 0x40) continue;   // e_lfanew
                        checksum += rol32_v8(pe_veri[k], k);
                    }
                    for (auto& d : degerler)
                        checksum += rol32_v8(((uint32_t)std::get<0>(d) << 16) | (uint32_t)std::get<1>(d),
                                             std::get<2>(d));
                    if (checksum != xor_anahtari) {
                        e.rich_header_gecersiz = true;
                        e.yapisal.push_back("RICH header checksum GECERSIZ — baslik ile oynanmis (Manalyze MALICIOUS)");
                        e.kanitlar.push_back({"RICH checksum uyusmuyor — DOS stub elle degistirilmis/packer (Manalyze: 'The file headers were tampered with')", 3});
                    }
                    // @comp.id 'Total imports' tutarliligi (Manalyze) — prodid==1
                    for (auto& d : degerler) {
                        if (std::get<0>(d) == 1 && !e.rich_header_gecersiz) {
                            if (std::get<2>(d) < (uint32_t)g.ithalat_toplam) {
                                e.yapisal.push_back("RICH @comp.id ithalat sayisi uyumsuz (Manalyze 'inconsistent imports')");
                                e.kanitlar.push_back({"RICH basligin bildirdigi ithalat sayisi gercekten az — packer (Manalyze)", 2});
                            }
                            break;
                        }
                    }
                }
                break;
            }
        }
        // (l) .NET SuppressIldasmAttribute (PE-LiteScan NET_ANTI_ILDASM)
        if (nc.gecerli) {
            if (bayt_icinde(pe_veri, nc.meta_kok,
                            std::min<size_t>((size_t)nc.meta_boy, dosya_boyu - nc.meta_kok),
                            "SuppressIldasmAttribute")) {
                e.yapisal.push_back(".NET SuppressIldasmAttribute (PE-LiteScan NET_ANTI_ILDASM)");
                e.kanitlar.push_back({"SuppressIldasmAttribute — ILDASM engelleme (PE-LiteScan)", 2});
            }
        }
    }

    // --- S11 (v8): OBFUS.H DERIN BLOGU — ObfusHunter + ObfusFake
    {
        int obfus_vurus = 0;
        for (auto* b : tum) {
            if (!b->rsz || !b->ro || (size_t)b->ro + b->rsz > dosya_boyu) continue;
            for (auto& des : algdb::OBFUS_TABLO) {
                // bolum icinde ara (ilk 256KB) — obfus desenleri bolum baslarina yiginlasir
                size_t sinir = std::min<size_t>((size_t)b->rsz, 0x40000);
                for (size_t i = 0; i + strlen(des.desen) / 2 <= sinir; i++) {
                    if (desen_ep_eslestir(&pe_veri[b->ro + i], dosya_boyu - b->ro - i, des.desen) >= 0) {
                        char t2[224];
                        snprintf(t2, sizeof t2, "obfus.h deseni %s @'%s'+0x%zX (%s)",
                                 des.kod, b->ad.c_str(), i, des.kategori);
                        e.obfus_bulgular.push_back(t2);
                        e.kanitlar.push_back({std::string("obfus deseni: ") + des.kod + " (" + des.kategori + ") — ObfusHunter", 2});
                        obfus_vurus++;
                        break;
                    }
                }
            }
        }
        // sahte imza desenleri (ObfusFake): bunlar obfus.h fake-protection modunun
        // gomdugu SAHTE filigranlardir — gercek aile adi DEGIL, sahtecilik kanitidir
        for (auto& sa : algdb::SAHTE_TABLO) {
            size_t n = strlen(sa.desen) / 2;
            if (dosya_boyu < n) continue;
            std::vector<uint8_t> desen_bayt(n);
            for (size_t k = 0; k < n; k++) {
                char h = sa.desen[k * 2], l = sa.desen[k * 2 + 1];
                desen_bayt[k] = (uint8_t)((h <= '9' ? h - '0' : (h | 32) - 'a' + 10) << 4 |
                                          (l <= '9' ? l - '0' : (l | 32) - 'a' + 10));
            }
            for (size_t i = 0; i + n <= dosya_boyu; i++) {
                if (memcmp(&pe_veri[i], &desen_bayt[0], n) == 0) {
                    e.obfus_sahte_imza = true;
                    e.kanitlar.push_back({std::string("SAHTE imza filigrani: \"") + sa.aciklama + "\" (ObfusFake-Remover: obfus.h fake-protection)", 2});
                    break;
                }
            }
        }
        // sahte dongle dizgileri (ObfusFake: skeydrv/HASPDOSDRV/WIBUKEY...)
        for (auto& d : algdb::SAHTE_DONGLE) {
            if (bayt_icinde(pe_veri, 0, dosya_boyu, d.dizgi)) {
                e.obfus_sahte_dongle = true;
                e.kanitlar.push_back({std::string("sahte dongle izi: \"") + d.dizgi + "\" (ObfusFake: obfus.h fake-protection Sentinel/HASP/WIBU taklidi)", 2});
                break;
            }
        }
        // obfus.h karar: desen vuruslari + sahte bolum adi kombinasyonu
        // v8 duzeltme: S5 bolum-icerik imzasi (ep_aile) ZATEN bir aile bulmussa,
        // obfus heuristiği ONA DEGILIR — imza > heuristik (ACProtect compress2 vakasi:
        // ACProtect junk-code kullandigi icin obfus desenleri yasiyordu)
        if (obfus_vurus >= 3 && !e.aile.empty() && e.aile.rfind("obfus", 0) != 0) {
            // baska aile adayi var ama obfus desenleri yogun — katman bilgisi
            e.kanitlar.push_back({"obfus.h desenleri yogun (" + std::to_string(obfus_vurus) + ") — obfusheader.h katmani olabilir", 1});
        }
        if (obfus_vurus >= 3 && e.aile.empty() && e.ep_aile.empty()) {
            e.aile = "obfus.h / obfusheader.h";
            e.kategori = "obfuscator";
            e.kanit_seviyesi = "K2";
            e.tespit_edildi = true;
            e.kanitlar.push_back({std::to_string(obfus_vurus) + " obfus.h deseni (junk/anti-debug/VM dispatch) — ObfusHunter", 3});
        }
    }

    // --- S12 (v8): OYUN DRM / TICARI PROTECTOR DIZGILERI (DRMDetector)
    {
        for (auto& d : algdb::DRM_TABLO) {
            if (bayt_icinde(pe_veri, 0, dosya_boyu, d.dizgi)) {
                char t2[192];
                snprintf(t2, sizeof t2, "DRM/protector izi: \"%s\" — %s (DRMDetector)", d.dizgi, d.aile);
                e.drm_bulgular.push_back(t2);
                // kanit olarak ekle; aile karari yalniz BOŞSA ve guclu ise
                e.kanitlar.push_back({std::string("dizgi izi: \"") + d.dizgi + "\" — " + d.aile + " (DRMDetector)", 2});
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

    // v8: S5 bolum-icerik imzasi (PEiD ep_only=false) veya S4b MODERN tablo bir
    // aile bulmussa ve hâlâ aile karari yoksa — o imza aile olur (ACProtect 1.4x
    // .perplex icinde bulundu; obfus heuristigi ezdi — bu duzeltme onu geri alir)
    if (e.aile.empty() && !e.ep_aile.empty()) {
        e.aile = e.ep_aile;
        if (!e.ep_surum.empty()) e.aile += " " + e.ep_surum;
        e.kategori = "packer/protector (bolum-icerik imzasi)";
        e.kanit_seviyesi = "K3";
        e.tespit_edildi = true;
        e.kanitlar.push_back({"aile karari: bolum-icerik imzasi " + e.ep_aile + " [" + e.ep_tablo + "]", 3});
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
