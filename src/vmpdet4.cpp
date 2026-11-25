// ============================================================================
//  VMDETECT v4 — GOD SSS TIER EDITION (MILITARY TUI)
//  Surum + ozellik + KATMAN + paketleyici + RUNTIME analizi
//
//  YENI (v4):
//   [P] PAKETLEYICI IMZA MOTORU — UPX/Themida/Enigma/ASProtect/MPRESS/... +
//       "VMProtect DEGIL" kesin olumsuz karari (negatif tespit)
//   [C] OZEL YAPI SINIFLANDIRMASI — bolum adlari degistirilmis (script/mod)
//       ciktilar ve BILINMEYEN VMProtect varyanti (modlanmis motor) raporu
//   [L] COK KATMAN ANALIZI — cift .vmp0 (double-protect), UPX-dis-katman,
//       baska koruyucuyla birlikte katman yigini
//   [R] RUNTIME MODU (--sim / --live) — i4MConsoleLoader mantiginda Windows
//       loader emulasyonu (map/reloc/import/TLS/koruma raporu + dump) ve
//       canli surec bellek doku mu + dump'i yeniden analiz
//   [K4'] goreli marj — buyuk bolumlerde daha keskin surum ayrimi
//
//  Kullananim:
//    vmpdet <dosya.exe>              tek hedef (askeri TUI raporu)
//    vmpdet --dir <klasor>           batch tarama
//    vmpdet --json <out.json> ...    JSON cikti
//    vmpdet --sim <dosya>            loader emulasyonu (i4M tarzi, kod CALISTIRMAZ)
//    vmpdet --sim --dump <o.bin>     + bellek goruntusunu dosyaya yaz
//    vmpdet --live <dosya.exe>       calistir + bellek dump + otomatik yeniden analiz
//                                     (--wait ms, --dump <o.bin>)
// ============================================================================
#include "detektor_db.h"
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>

#ifdef _WIN32
#include <io.h>
#define ISATTU _isatty
#include <filesystem>
#include <windows.h>
#include <psapi.h>
namespace fs = std::filesystem;
#else
#include <unistd.h>
#define ISATTU isatty
#include <dirent.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#endif

// ---------------------------------------------------------------- renkler
static bool g_renk = true;
static const char* R(const char* k) { return g_renk ? k : ""; }
#define SIFIRLA "\x1b[0m"
#define SARI    "\x1b[33m"
#define YESIL   "\x1b[32m"
#define KIRMIZI "\x1b[31m"
#define GRAY    "\x1b[90m"
#define BEYAZ   "\x1b[97m"
#define CIAN    "\x1b[36m"
#define MAGENTA "\x1b[95m"

// ---------------------------------------------------------------- PE ayristirici
struct Bolum { std::string ad; uint32_t vsz, va, rsz, ro, oz; };
struct PE {
    std::vector<uint8_t> veri;
    uint16_t makine = 0, bolum_sayisi = 0;
    uint32_t giris_rva = 0, dll_oz = 0, opt_sihir = 0, resim_boyu = 0;
    uint64_t resim_taban = 0;
    uint32_t e_lfanew = 0, opt_ofset = 0;
    uint32_t veri_dizin[16][2] = {};
    std::vector<Bolum> bolumler;
    std::vector<std::pair<std::string,int>> importlar;
    std::vector<std::string> import_fonksiyonlar;
    bool tamam = false;
    std::string hata;
};

static bool pe_ac(const char* yol, PE& p) {
    FILE* f = fopen(yol, "rb");
    if (!f) { p.hata = "dosya acilamadi"; return false; }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    if (n < 0x400) { fclose(f); p.hata = "cok kucuk dosya"; return false; }
    p.veri.resize(n);
    if (fread(p.veri.data(), 1, n, f) != (size_t)n) { fclose(f); p.hata = "okuma hatasi"; return false; }
    fclose(f);
    const auto& d = p.veri;
    if (d[0] != 'M' || d[1] != 'Z') { p.hata = "MZ imzasi yok"; return false; }
    uint32_t e = 0;
    memcpy(&e, &d[0x3C], 4);
    p.e_lfanew = e;
    if (e + 24 > n || memcmp(&d[e], "PE\0\0", 4) != 0) { p.hata = "PE imzasi yok"; return false; }
    memcpy(&p.makine, &d[e + 4], 2);
    memcpy(&p.bolum_sayisi, &d[e + 6], 2);
    uint16_t opt_boyut = 0;
    memcpy(&opt_boyut, &d[e + 20], 2);
    size_t opt = e + 24;
    p.opt_ofset = (uint32_t)opt;
    memcpy(&p.opt_sihir, &d[opt], 2);
    memcpy(&p.giris_rva, &d[opt + 16], 4);
    memcpy(&p.dll_oz, &d[opt + 70], 2);
    if (p.opt_sihir == 0x20B) {
        memcpy(&p.resim_taban, &d[opt + 24], 8);
        memcpy(&p.resim_boyu, &d[opt + 56], 4);
    } else {
        uint32_t tb = 0;
        memcpy(&tb, &d[opt + 28], 4); p.resim_taban = tb;
        memcpy(&p.resim_boyu, &d[opt + 56], 4);
    }
    uint32_t nd = 0; size_t dd = 0;
    if (p.opt_sihir == 0x20B) { memcpy(&nd, &d[opt + 108], 4); dd = opt + 112; }
    else { memcpy(&nd, &d[opt + 92], 4); dd = opt + 96; }
    if (nd > 16) nd = 16;
    for (uint32_t i = 0; i < nd; i++) {
        memcpy(&p.veri_dizin[i][0], &d[dd + 8*i], 4);
        memcpy(&p.veri_dizin[i][1], &d[dd + 8*i + 4], 4);
    }
    if (p.bolum_sayisi > 96) { p.hata = "bolum sayisi asiri"; return false; }
    for (int i = 0; i < p.bolum_sayisi && opt + opt_boyut + 40 * (size_t)(i + 1) <= n; i++) {
        size_t o = opt + opt_boyut + 40 * i;
        Bolum b;
        char buf[9] = {0};
        memcpy(buf, &d[o], 8);
        b.ad = buf;
        memcpy(&b.vsz, &d[o + 8], 4);
        memcpy(&b.va, &d[o + 12], 4);
        memcpy(&b.rsz, &d[o + 16], 4);
        memcpy(&b.ro, &d[o + 20], 4);
        memcpy(&b.oz, &d[o + 36], 4);
        // dump/bellek goruntusu guvenligi: ro+rsz dosya sinirini asarsa kistir
        if (b.ro >= (uint32_t)n) { b.rsz = 0; }
        else if (b.ro + b.rsz > (uint32_t)n) b.rsz = (uint32_t)n - b.ro;
        p.bolumler.push_back(b);
    }
    if (nd > 1) {
        uint32_t imp_rva = p.veri_dizin[1][0];
        auto r2o = [&](uint32_t rva) -> long {
            for (auto& b : p.bolumler)
                if (b.va <= rva && rva < b.va + (b.vsz > b.rsz ? b.vsz : b.rsz))
                    return (long)b.ro + (rva - b.va);
            return -1;
        };
        if (imp_rva) {
            long of = r2o(imp_rva);
            if (of > 0 && of + 20 <= (long)n) {
                for (int i = 0; i < 256; i++) {
                    uint32_t oft = 0, ad_rva = 0, ft = 0;
                    memcpy(&oft, &d[of + 20 * i], 4);
                    memcpy(&ad_rva, &d[of + 20 * i + 12], 4);
                    memcpy(&ft, &d[of + 20 * i + 16], 4);
                    if (!oft && !ad_rva && !ft) break;
                    long ao = r2o(ad_rva);
                    if (ao < 0 || ao >= (long)n) { p.importlar.push_back({"?", 0}); continue; }
                    std::string ad;
                    for (long j = ao; j < (long)n && d[j]; j++) ad += (char)d[j];
                    long t = r2o(oft ? oft : ft);
                    int say = 0;
                    if (t >= 0)
                        while (say < 4096 && t + 8 * (say + 1) < (long)n) {
                            uint64_t v = 0;
                            memcpy(&v, &d[t + 8 * say], 8);
                            if (!v) break;
                            say++;
                        }
                    p.importlar.push_back({ad, say});
                    // ilk N fonksiyon adini coz (sim raporu icin)
                    if (t >= 0 && p.import_fonksiyonlar.size() < 48) {
                        int k = 0;
                        while (k < say && t + 8 * k + 8 < (long)n &&
                               p.import_fonksiyonlar.size() < 48) {
                            uint64_t v = 0;
                            memcpy(&v, &d[t + 8 * k], 8);
                            if (!v) break;
                            if (!(v & 0x8000000000000000ULL) && p.opt_sihir == 0x20B) {
                                long ho = r2o((uint32_t)v);
                                if (ho >= 2 && ho + 2 < (long)n) {
                                    std::string fn;
                                    for (long j = ho + 2; j < (long)n && d[j] && fn.size() < 64; j++)
                                        fn += (char)d[j];
                                    if (!fn.empty()) p.import_fonksiyonlar.push_back(ad + "!" + fn);
                                }
                            } else if (!(v & 0x80000000UL) && p.opt_sihir != 0x20B) {
                                long ho = r2o((uint32_t)v);
                                if (ho >= 2 && ho + 2 < (long)n) {
                                    std::string fn;
                                    for (long j = ho + 2; j < (long)n && d[j] && fn.size() < 64; j++)
                                        fn += (char)d[j];
                                    if (!fn.empty()) p.import_fonksiyonlar.push_back(ad + "!" + fn);
                                }
                            }
                            k++;
                        }
                    }
                }
            }
        }
    }
    p.tamam = true;
    return true;
}

// ---------------------------------------------------------------- yardimcilar
static bool standart_ad(const std::string& ad) {
    static const char* S[] = {".text",".rdata",".data",".pdata",".tls",".rsrc",".reloc",
        ".edata",".idata",".bss",".gfids",".qtmetad","_RDATA",".xdata",".CRT",
        ".UPX0",".UPX1",".UPX2","UPX0","UPX1","UPX2",".didat",".xc",".clr",".sdata",
        ".00cfg",".textbss",".eh_fram",".eh_frame",".gcc_except_table",
        ".debug_a",".debug_i",".debug_l",".debug_f",".debug_s",".debug_r",".debug_p",
        ".debug_t",".drectve",".idata$4",".idata$5", nullptr};
    for (int i = 0; S[i]; i++) if (ad == S[i]) return true;
    if (ad.rfind(".rdata$", 0) == 0 || ad.rfind(".text$", 0) == 0 ||
        ad.rfind(".data$", 0) == 0 || ad.rfind(".CRT$", 0) == 0 ||
        ad.rfind(".debug", 0) == 0 || ad.rfind(".idata$", 0) == 0)
        return true;
    // MinGW uzun debug bolumleri: "/4", "/19" ... (string-tablo indeksi)
    if (ad.size() > 1 && ad[0] == '/') {
        bool rakam = true;
        for (size_t i = 1; i < ad.size(); i++)
            if (!isdigit((unsigned char)ad[i])) { rakam = false; break; }
        if (rakam) return true;
    }
    return false;
}

static std::string kucuk(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(), ::tolower);
    return r;
}

static bool hex2bayt(const char* h, uint8_t* out, int n) {
    for (int i = 0; i < n; i++) {
        int v = 0;
        for (int j = 0; j < 2; j++) {
            char c = h[i * 2 + j];
            v <<= 4;
            if (c >= '0' && c <= '9') v += c - '0';
            else if (c >= 'a' && c <= 'f') v += c - 'a' + 10;
            else return false;
        }
        out[i] = (uint8_t)v;
    }
    return true;
}

static bool dosyada_ara(const std::vector<uint8_t>& v, const char* dizgi,
                        size_t sinir) {
    size_t ilen = strlen(dizgi);
    if (v.size() < ilen) return false;
    size_t in = std::min(v.size(), sinir);
    for (size_t i = 0; i + ilen <= in; i++)
        if (memcmp(v.data() + i, dizgi, ilen) == 0) return true;
    return false;
}

// ---------------------------------------------------------------- [P] paketleyici imzalari
struct PackerImza {
    const char* ad;
    const char* bolumler[4];   // bolum adlari (buyuk/kucuk harf duyarsiz, nokta opsiyonel)
    const char* dizgi[3];      // dosya icinde aranacak dizgiler
    const char* not_;
};

static const PackerImza PACKER_TABLO[] = {
    { "Themida / WinLicense", {".themida",".boom",".taz",".tsuarch"},
      {"Themida","WinLicense","Oreans"}, "Themida ailesi izleri" },
    { "Enigma Protector", {".enigma1",".enigma2"},
      {"Enigma protector","EnigmaVirtualBox","enigma_"}, "" },
    { "ASProtect / ASPack", {".aspack",".adata"},
      {"ASPack","ASProtect","aSPack"}, "" },
    { "MPRESS", {".mpress1",".mpress2"}, {"MPRESS","mpress1"}, "" },
    { "PECompact", {"pecompact2","PECompact2"}, {"PECompact2","PECompact2 2"}, "" },
    { "Obsidium", {".obsidium"}, {"Obsidium","obsidium"}, "" },
    { "ExeCryptor", {".ecode",".edata"}, {"ExeCryptor","ECRYPT"}, "" },
    { "nSpack", {".nsp0",".nsp1","nsp0"}, {"nSpack","NsPack"}, "" },
    { "Petite", {"petite"}, {"Petite","petite"}, "" },
    { "FSG", {".fsg","fsg"}, {"FSG"}, "" },
    { "MEW", {".mew","mew"}, {"MEW11 SE","MEW."}, "" },
    { "Nullsoft NSIS (kurulum)", {".ndata","ndata"}, {"Nullsoft","NSIS Error"}, "kurulum paketi" },
    { "Inno Setup (kurulum)", {}, {"Inno Setup","JR.Inno.Setup"}, "kurulum paketi" },
    { "ConfuserEx (.NET)", {}, {"ConfuserEx","confuser"}, ".NET obfuscator" },
    { "VMProtect (eski isim izi)", {}, {"VMProtect begin","VMProtect end","VMProtectEnd"},
      "kaynak isaretleri — motor KANITI DEGIL (girdiden kalma olabilir)" },
};

// UPX bolum adı mı (nokta opsiyonel, harf duyarsiz)
static bool upx_bolum_ad_mi(const std::string& ad_orig) {
    std::string ad = kucuk(ad_orig);
    for (const char* p : {".upx0",".upx1",".upx2","upx0","upx1","upx2"})
        if (ad == p) return true;
    return false;
}

struct PackerTarama {
    bool upx_bolum_var = false;
    bool upx_gercek = false;       // UPX! sihri ya da $Info dizgisi bulundu
    bool upx_bilgi_dizgisi = false;
    const PackerImza* vurus = nullptr;
    bool vmp_isaret_dizgisi = false; // "VMProtect begin/end" kaynak isareti
    bool dotnet = false;
    bool nsis_kurulum = false;
};

static PackerTarama packer_tara(const PE& p, const std::vector<const Bolum*>& korp) {
    PackerTarama pt;
    for (auto* b : korp)
        if (upx_bolum_ad_mi(b->ad)) { pt.upx_bolum_var = true; break; }
    pt.upx_gercek = dosyada_ara(p.veri, "UPX!", p.veri.size()) ||
                    dosyada_ara(p.veri, "$Info: This file is packed with the UPX", p.veri.size());
    pt.upx_bilgi_dizgisi = dosyada_ara(p.veri, "$Info: This file is packed", p.veri.size());
    // .NET: veri dizini 14 (CLR)
    pt.dotnet = (p.veri_dizin[14][0] != 0 && p.veri_dizin[14][1] != 0);
    for (auto& imza : PACKER_TABLO) {
        bool bolum_vur = false;
        for (auto* b : korp)
            for (const char* bn : imza.bolumler)
                if (bn && kucuk(b->ad) == kucuk(bn)) { bolum_vur = true; break; }
        bool dizgi_vur = false;
        for (const char* sg : imza.dizgi)
            if (sg && dosyada_ara(p.veri, sg, std::min(p.veri.size(), (size_t)4<<20)))
                { dizgi_vur = true; break; }
        if (bolum_vur || dizgi_vur) {
            if (strstr(imza.ad, "NSIS")) { pt.nsis_kurulum = true; }
            if (strstr(imza.ad, "VMProtect (eski")) { pt.vmp_isaret_dizgisi = true; continue; }
            pt.vurus = &imza;
            break;  // tablo sirasi: en ozgunden en genele
        }
    }
    return pt;
}

// ---------------------------------------------------------------- yapi siniflari
enum SinifKod { S_PURE = 0, S_BIG1 = 1, S_SEC3 = 2, S_SEC2BIG = 3, S_SEC2K = 4, S_BILINMEYEN = 9 };
static const char* const SINIF_ADLARI[] = {"PURE", "BIG1", "SEC3", "SEC2BIG", "SEC2K", "?"};

struct KorBolum { std::string ad; uint32_t raw, vsz, kar; };

struct KatmanBilgi {
    bool cift_vmp_ad = false;      // ayni isimli .vmp bolumleri (double-protect)
    std::vector<std::string> notlar;
    struct KatmanKat { std::string bolum; std::string surum; std::string kaynak; };
    std::vector<KatmanKat> katmanlar;
};

struct Sonuc {
    bool vmp_tespit = false;
    std::string tespit_notu;
    std::string paketleyici;        // VMP disi paketleyici adi (varsa)
    bool olumsuz_karar = false;     // "VMProtect DEGIL" kesin karari
    std::string makine;
    size_t dosya_boyut = 0;
    std::vector<KorBolum> kor;
    int sinif = S_BILINMEYEN;
    std::string sinif_ad;
    bool upx_kamuflaj = false, text_yok = false, reloc_yok = false;
    uint32_t text_ham = 0;
    size_t import_dll = 0;
    struct Aday { int surum; uint64_t dist; };
    std::vector<Aday> adaylar;
    std::string guven;
    std::string esitlenen_profil;
    std::vector<std::pair<std::string,std::string>> ozellikler;
    std::string katman_karar;
    bool esitlik_sinifi = false;
    std::string desen_iz;
    // v4 yeni
    bool bolum_adlari_degisti = false;   // .vmp adlari yok ama yapi VMP
    bool ozel_varyant = false;           // bilinmeyen VMProtect varyanti (modlanmis)
    bool katmanli = false;               // cok katmanli koruma
    KatmanBilgi katman;
    bool sim_mod = false;                // runtime/sim ciktisi mi
};

static int sinif_bul(const std::vector<KorBolum>& kb) {
    if (kb.size() == 1) return kb[0].raw <= 8192 ? S_PURE : S_BIG1;
    if (kb.size() == 2) return kb[1].raw > 100000 ? S_SEC2BIG : S_SEC2K;
    if (kb.size() == 3) return S_SEC3;
    return S_BILINMEYEN;
}

// ---------------------------------------------------------------- K3: eski nesil n-gram
struct EskiNgKume { std::vector<std::vector<uint8_t>> pat; bool hazir = false; };
static EskiNgKume g_eski[2];

static void eski_ng_yukle() {
    struct { const char* const* hex; int sayi; } kaynak[2] = {
        { vmpdb::ESKING_Ultimate_309, vmpdb::ESKING_SAYI_Ultimate_309 },
        { vmpdb::ESKING_Ultimate_320, vmpdb::ESKING_SAYI_Ultimate_320 },
    };
    for (int k = 0; k < 2; k++) {
        g_eski[k].pat.reserve(kaynak[k].sayi);
        for (int i = 0; i < kaynak[k].sayi; i++) {
            uint8_t b[24];
            if (hex2bayt(kaynak[k].hex[i], b, 24))
                g_eski[k].pat.push_back(std::vector<uint8_t>(b, b + 24));
        }
        g_eski[k].hazir = !g_eski[k].pat.empty();
    }
}

static int eski_oy(const std::vector<uint8_t>& veri, int k) {
    if (!g_eski[k].hazir) return 0;
    int on = 0;
    for (int i = 0; i < 6 && i < (int)g_eski[k].pat.size(); i++)
        if (std::search(veri.begin(), veri.end(),
                        g_eski[k].pat[i].begin(), g_eski[k].pat[i].end()) != veri.end())
            on++;
    if (on == 0) return 0;
    int toplam = on;
    for (int i = 6; i < (int)g_eski[k].pat.size(); i++)
        if (std::search(veri.begin(), veri.end(),
                        g_eski[k].pat[i].begin(), g_eski[k].pat[i].end()) != veri.end())
            toplam++;
    return toplam;
}

// ---------------------------------------------------------------- K1: karakteristik filtre
static std::vector<int> k1_filtre(const std::vector<KorBolum>& kor) {
    int n = (int)kor.size();
    if (n < 1 || n > 3) return {};
    std::vector<int> aday;
    for (int sv = 0; sv < vmpdb::SURUM_SAYI; sv++) {
        int bas = vmpdb::KALIP_OFSET[sv];
        int son = bas + vmpdb::KALIP_SAYI[sv];
        for (int i = bas; i < son; i++) {
            const auto& k = vmpdb::KALIPLAR[i];
            bool uyum = (k.n == n);
            if (uyum)
                for (int j = 0; j < n; j++)
                    if (k.kar[j] != kor[j].kar) { uyum = false; break; }
            if (uyum) { aday.push_back(sv); break; }
        }
    }
    return aday;
}

static bool esitlik_uyesi(int sv) {
    for (int i = 0; i < vmpdb::ESDEGER_SAYI; i++)
        if (vmpdb::ESDEGER_UYE[i] == sv) return true;
    return false;
}

static void ozellik_cikar(Sonuc& s);  // ileri bildirim

// CAPA2: girdi-ailesi capa eslesmesi (isaret bolumu + surum bolumu cifti)
// donus: surum indeksi; esitlik sinifina dusurse adaylara 2 ve 8 eklenir
static bool capa2_dene(Sonuc& s) {
    for (int a = 0; a < vmpdb::CAPA2_SAYI; a++) {
        const auto& aile = vmpdb::CAPA2[a];
        bool isaret_var = false;
        for (auto& kb : s.kor)
            if (kb.raw == aile.isaret_raw && kb.vsz == aile.isaret_vsz)
                { isaret_var = true; break; }
        if (!isaret_var) continue;
        for (auto& kb : s.kor) {
            for (int kk = 0; kk < aile.kayit_sayi; kk++) {
                if (aile.kayit[kk].raw == kb.raw && aile.kayit[kk].vsz == kb.vsz) {
                    int sv = aile.kayit[kk].surum;
                    if (sv == 2 || sv == 8) {
                        s.adaylar.push_back({2, 0});
                        s.adaylar.push_back({8, 0});
                        s.esitlik_sinifi = true;
                        s.guven = "KESIN ESITLIK (capa2 aile cipi — 3.8.x motor sinifi)";
                    } else {
                        s.adaylar.push_back({sv, 0});
                        s.guven = "YUKSEK (capa2 aile cipi birebir)";
                    }
                    s.katman_karar = std::string("CAPA2: ") + aile.aile + " surum cipi";
                    s.esitlenen_profil = "wrapper (aile capa2)";
                    ozellik_cikar(s);
                    return true;
                }
            }
        }
    }
    return false;
}

// ---------------------------------------------------------------- ozellik cikarimi
static const char* const OZELLIKLER[] = {
    "DebugMode","CryptValues","RunnerCRC","EncryptRegs","Pack","ImportProtection",
    "CheckDebugger","CheckVirtualMachine","MemoryProtection","StripFixups",
    "ResourceProtection","CheckKernelDebugger","StripDebugInfo","VirtualFiles",
    "LoaderCRC","EncryptBytecode", nullptr
};

static void ozellik_cikar(Sonuc& s) {
    if (s.adaylar.empty()) return;
    std::string pr = s.esitlenen_profil;
    std::map<std::string,bool> acik;
    for (int i = 0; OZELLIKLER[i]; i++) acik[OZELLIKLER[i]] = false;
    bool fn_var = false;
    std::string fn_mod, fn_param;

    bool profil_gecerli = !pr.empty() && pr != "n-gram stub imzasi"
                && pr.rfind("PURE-wrapper", 0) != 0;
    if (profil_gecerli) {
        bool hepsi = pr.find("HEPSI") != std::string::npos;
        if (hepsi) {
            for (int i = 0; OZELLIKLER[i]; i++) acik[OZELLIKLER[i]] = true;
        } else if (pr.rfind("Move_", 0) != 0) {
            for (int i = 0; OZELLIKLER[i]; i++)
                acik[OZELLIKLER[i]] = (pr == OZELLIKLER[i]);
        }
        if (pr.rfind("Move_", 0) == 0) {
            fn_var = true;
            if (pr.rfind("Move_Ultra", 0) == 0) fn_mod = "ULTRA (virt+mutation)";
            else if (pr.rfind("Move_Mutation", 0) == 0) fn_mod = "MUTATION";
            else fn_mod = "VIRTUALIZATION";
            if (pr.find("_I1") != std::string::npos && pr.find("_I10") == std::string::npos)
                fn_param = "instances=1";
            else if (pr.find("_I10") != std::string::npos) fn_param = "instances=10";
            else if (pr.find("_C100") != std::string::npos) fn_param = "complexity=100 (max)";
            else if (pr.find("_C0") != std::string::npos) fn_param = "complexity=0 (min)";
            else if (pr.find("_VM2X") != std::string::npos) fn_param = "VM 2x";
            if (pr != "Move_Mutation" && pr != "Move_Virt" && pr != "Move_Ultra"
                && fn_param.empty()) {
                for (int i = 0; OZELLIKLER[i]; i++) {
                    std::string sfx = std::string("_") + OZELLIKLER[i];
                    if (pr.size() > sfx.size() &&
                        pr.compare(pr.size() - sfx.size(), sfx.size(), sfx) == 0)
                        acik[OZELLIKLER[i]] = true;
                }
            }
        }
    }
    if (s.text_yok) acik["Pack"] = true;
    if (s.reloc_yok) acik["StripFixups"] = true;

    std::string fn_satir = "none";
    if (fn_var) {
        fn_satir = "MOVE — " + fn_mod;
        if (!fn_param.empty()) fn_satir += " [" + fn_param + "]";
    }
    s.ozellikler.push_back({"VirtualizedFunction", fn_satir});
    if (profil_gecerli)
        s.ozellikler.push_back({"ImportProtection",
            acik["ImportProtection"] ? "ACIK (profil eslesmesi)" : "KAPALI"});
    else
        s.ozellikler.push_back({"ImportProtection",
            s.import_dll <= 1 ? "OLASI (imports sarili)" : "YOK"});
    for (int i = 0; OZELLIKLER[i]; i++) {
        std::string ad = OZELLIKLER[i];
        if (ad == "ImportProtection") continue;
        std::string durum;
        if (ad == "Pack" && s.text_yok) durum = "KESIN (.text birlestirildi)";
        else if (ad == "StripFixups" && s.reloc_yok) durum = "KESIN (.reloc striplendi)";
        else if (!profil_gecerli) durum = "BELIRSIZ (profil eslesmedi)";
        else durum = acik[ad] ? "ACIK (profil eslesmesi)" : "KAPALI";
        s.ozellikler.push_back({ad, durum});
    }
}

static void ozellik_cikar_katmanli(Sonuc& s, PE& p) {
    // cok katmanli dosyalarda ozellik cikimi dis katman uzerinden kisirdir;
    // bolum sayilari/yapilar karisik oldugu icin dürüst rapor
    s.ozellikler.push_back({"AnalizModu", "COKLU KATMAN — ozellik cikimi katman bazinda guvenilmez"});
    s.ozellikler.push_back({"Pack", s.text_yok ? "KESIN (.text birlestirildi)" : "KAPALI/yok"});
    s.ozellikler.push_back({"StripFixups", s.reloc_yok ? "KESIN (.reloc striplendi)" : "KAPALI/yok"});
    s.ozellikler.push_back({"ImportProtection", s.import_dll <= 1 ? "OLASI (imports sarili)" : "YOK"});
}

// ---------------------------------------------------------------- analiz (KATMANLI + v4)
static void analiz(const char* yol, Sonuc& s) {
    PE p;
    if (!pe_ac(yol, p)) { s.tespit_notu = p.hata; s.olumsuz_karar = true; return; }
    s.dosya_boyut = p.veri.size();
    s.makine = (p.makine == 0x8664) ? "x64" : (p.makine == 0x14c) ? "x86" : "?";
    s.import_dll = p.importlar.size();
    std::vector<const Bolum*> korp;
    for (auto& b : p.bolumler) {
        if (!standart_ad(b.ad) && b.rsz > 0) {
            korp.push_back(&b);
            s.kor.push_back({b.ad, b.rsz, b.vsz, b.oz});
        }
        if (b.ad == ".text") s.text_ham = b.rsz;
        if (upx_bolum_ad_mi(b.ad)) s.upx_kamuflaj = true;
    }
    s.reloc_yok = true;
    for (auto& b : p.bolumler) if (b.ad == ".reloc") s.reloc_yok = false;
    s.text_yok = (s.text_ham == 0);

    // ---- [P] paketleyici taramasi
    PackerTarama pt = packer_tara(p, korp);

    if (s.kor.empty()) {
        // koruyucu bolum yok → paketsiz ya da bolumsuz-paketleyici (kurulum/.NET)
        s.olumsuz_karar = true;
        if (pt.dotnet) { s.paketleyici = ".NET assembly (CLR basligi)"; s.tespit_notu = "yonetilen kod — VMProtect degil"; }
        else if (pt.nsis_kurulum) { s.paketleyici = "Nullsoft NSIS kurulumu"; s.tespit_notu = "kurulum paketi — VMProtect degil"; }
        else if (pt.upx_gercek && dosyada_ara(p.veri, "UPX!", p.veri.size())) {
            s.paketleyici = "UPX (bolum tablosu sikistirilmis)"; s.tespit_notu = "UPX! sihri"; }
        else if (pt.vurus) { s.paketleyici = pt.vurus->ad; s.tespit_notu = pt.vurus->not_; }
        else s.tespit_notu = "koruyucu bolum yok — PAKETSIZ / VMProtect degil";
        return;
    }

    // ---- VMP kapisina hazirlik
    bool vmp_ad = false;
    std::map<std::string,int> ad_sayaci;
    for (auto& b : s.kor) {
        std::string k = kucuk(b.ad);
        ad_sayaci[k]++;
        if (k.rfind(".vmp", 0) == 0 || k.rfind("vmp", 0) == 0) vmp_ad = true;
    }
    // ayni isimli .vmp bolumleri → cift katman (double-protect)
    for (auto& kv : ad_sayaci)
        if (kv.second > 1 && kv.first.rfind(".vmp", 0) == 0) {
            s.katman.cift_vmp_ad = true;
            s.katmanli = true;
        }
    bool vmp_str = dosyada_ara(p.veri, "VMProtect", 1 << 20);
    // koruyucu-tipik bolum bayraklari (isimden bagimsiz): R+X + DISCARDABLE/NOT_PAGED
    bool vmp_bayrak = false;
    for (auto* b : korp) {
        uint32_t oz = b->oz;
        if ((oz & 0x20000000) && (oz & 0x40000000) &&
            ((oz & 0x02000000) || (oz & 0x08000000)))
            vmp_bayrak = true;
    }

    // ---- [P] GERCEK UPX ayrimi (VMP-kamuflaj ile karistirmadan)
    if (s.upx_kamuflaj && pt.upx_gercek) {
        s.olumsuz_karar = true;
        s.paketleyici = "UPX";
        s.tespit_notu = "UPX! sihri + UPX bolumleri — GERCEK UPX, VMProtect degil";
        s.katman.notlar.push_back("UPX altinda gizli ic katman olabilir — runtime analizi: --live");
        // ic katman ipucu: UPX0 boyutu orijinal goruntunun boyutu
        for (auto* b : korp)
            if (upx_bolum_ad_mi(b->ad) && b->vsz > 0x10000)
                s.katman.notlar.push_back("UPX0 genis — ic katman gizli (runtime analizi onerilir: --live)");
        return;
    }

    // ---- VMP karari
    bool yapisal_vmp = vmp_bayrak;  // (bayrak deseni VMProtect tipi)
    if (vmp_ad) { s.vmp_tespit = true; s.tespit_notu = ".vmp bolum(leri)"; }
    else if (vmp_str && !pt.vurus) { s.vmp_tespit = true; s.tespit_notu = "VMProtect dizgisi + koruyucu bolum"; }
    else if (yapisal_vmp && !pt.vurus) { s.vmp_tespit = true; s.tespit_notu = "koruyucu bolum bayrak deseni (0x68000060 tipi)"; }

    if (!s.vmp_tespit) {
        // VMP DEGIL — ya baska paketleyici ya da bilinmeyen koruyucu
        s.olumsuz_karar = true;
        if (s.upx_kamuflaj && !pt.upx_gercek) {
            // UPX adli bolumler ama sihri yok → kamuflaj (VMP eski surum ya da baska arac)
            s.paketleyici = "UPX-adli bolumler (kamuflaj, UPX! sihri YOK)";
            s.tespit_notu = "UPX bolum adlari tasiyor ama gercek UPX kaniti yok — VMProtect eski-surum kamuflaji olabilir";
        } else if (pt.vurus) {
            s.paketleyici = pt.vurus->ad;
            s.tespit_notu = pt.vurus->not_ && pt.vurus->not_[0] ? pt.vurus->not_ : "baska paketleyici imzasi";
        } else {
            s.paketleyici = "BILINMEYEN KORUYUCU";
            s.tespit_notu = "standart-disi bolum(ler) var, VMProtect imzasi YOK";
        }
        return;
    }

    // ================= VMProtect YOLU =================
    if (!vmp_ad) {
        s.bolum_adlari_degisti = true;
        s.katman.notlar.push_back("bolum adlari .vmp degil — RASTGELE/OZEL adlar (script ya da modlanmis surum)");
    }

    // ---- cift katman: bolum-bazli surum atfi (capa + n-gram)
    if (s.katman.cift_vmp_ad) {
        for (size_t i = 0; i < s.kor.size(); i++) {
            std::vector<int> capa;
            for (int sv = 0; sv < vmpdb::SURUM_SAYI; sv++)
                for (int c = 0; c < 2; c++)
                    if (vmpdb::PURE_CAPA[sv][c].raw == s.kor[i].raw &&
                        vmpdb::PURE_CAPA[sv][c].vsz == s.kor[i].vsz && s.kor[i].raw > 0)
                        { capa.push_back(sv); break; }
            std::string surum_str = "?", kaynak = "";
            if (capa.size() == 1) {
                surum_str = vmpdb::SURUM[capa[0]];
                kaynak = "capa (bolum boyutu cipi)";
            } else if (capa.size() > 1) {
                surum_str = "{";
                for (size_t k = 0; k < capa.size(); k++)
                    surum_str += std::string(vmpdb::SURUM[capa[k]]) + (k + 1 < capa.size() ? "; " : "");
                surum_str += "}";
                kaynak = "capa coklu-aday";
            } else {
                // n-gram tara (eski nesil dis katman icin)
                std::vector<uint8_t> bvol;
                for (auto& b : p.bolumler)
                    if (kucuk(b.ad) == kucuk(s.kor[i].ad) && b.rsz == s.kor[i].raw) {
                        bvol.assign(p.veri.begin() + b.ro, p.veri.begin() + b.ro + (long)b.rsz);
                        break;
                    }
                int o0 = eski_oy(bvol, 0), o1 = eski_oy(bvol, 1);
                if ((int)g_eski[0].pat.size() && o0 >= (int)g_eski[0].pat.size() / 2) {
                    surum_str = vmpdb::SURUM[4]; kaynak = "n-gram (eski nesil stub)";
                } else if ((int)g_eski[1].pat.size() && o1 >= (int)g_eski[1].pat.size() / 2) {
                    surum_str = vmpdb::SURUM[5]; kaynak = "n-gram (eski nesil stub)";
                } else if (false) { }
                if (surum_str == "?") {
                    // CAPA2: girdi-ailesi capalari (isaret bolumu + surum bolumu)
                    for (int a = 0; a < vmpdb::CAPA2_SAYI; a++) {
                        const auto& aile = vmpdb::CAPA2[a];
                        bool isaret_var = false;
                        for (auto& kb : s.kor)
                            if (kb.raw == aile.isaret_raw && kb.vsz == aile.isaret_vsz)
                                { isaret_var = true; break; }
                        if (!isaret_var) continue;
                        for (int kk = 0; kk < aile.kayit_sayi; kk++) {
                            if (aile.kayit[kk].raw == s.kor[i].raw &&
                                aile.kayit[kk].vsz == s.kor[i].vsz) {
                                int sv2 = aile.kayit[kk].surum;
                                if (sv2 == 2 || sv2 == 8)
                                    surum_str = "{Professional 3.8.1; Ultimate 3.8.4} (3.8.x esitlik)",
                                    kaynak = "capa2 hello-ailesi";
                                else
                                    surum_str = vmpdb::SURUM[sv2],
                                    kaynak = "capa2 hello-ailesi";
                                break;
                            }
                        }
                        if (surum_str != "?") break;
                    }
                }
                if (surum_str == "?") {
                    surum_str = "bilinmeyen (runtime onerilir: --live)";
                    kaynak = "capa/n-gram eslesmedi";
                }
            }
            char bnum[32];
            snprintf(bnum, sizeof bnum, "%s(%u B)",
                     s.kor[i].ad.c_str()[0] ? s.kor[i].ad.c_str() : "bos-ad", s.kor[i].raw);
            s.katman.katmanlar.push_back({bnum, surum_str, kaynak});
        }
        s.guven = "COKLU KATMAN — bolum bazli surum atfi";
        s.katman_karar = "L: cift .vmp bolumu — katman katman surum atfi";
        ozellik_cikar_katmanli(s, p);
        return;
    }

    s.sinif = sinif_bul(s.kor);

    // ---- KATMAN 1: karakteristik desen sert filtresi
    std::vector<int> k1 = k1_filtre(s.kor);
    {
        char buf[96];
        std::string dz;
        for (size_t i = 0; i < s.kor.size(); i++) {
            snprintf(buf, sizeof buf, "%s%s:0x%X", i ? "+" : "",
                     s.kor[i].ad.c_str(), s.kor[i].kar);
            dz += buf;
        }
        s.desen_iz = dz;
    }
    bool k1_aktif = !k1.empty() && (int)k1.size() < vmpdb::SURUM_SAYI;

    // ---- KATMAN 3: eski nesil n-gram
    std::vector<uint8_t> kor_veri;
    for (auto* b : korp)
        kor_veri.insert(kor_veri.end(), p.veri.begin() + b->ro,
                        p.veri.begin() + b->ro + (long)b->rsz);
    int oy0 = eski_oy(kor_veri, 0);
    int oy1 = eski_oy(kor_veri, 1);
    int top0 = (int)g_eski[0].pat.size();
    int top1 = (int)g_eski[1].pat.size();
    int eski_kazanan = -1;
    if (top0 && oy0 >= top0 / 2) eski_kazanan = 4;
    else if (top1 && oy1 >= top1 / 2) eski_kazanan = 5;
    if (eski_kazanan >= 0 && (!k1_aktif ||
        std::find(k1.begin(), k1.end(), eski_kazanan) != k1.end())) {
        s.adaylar.push_back({eski_kazanan, 0});
        s.guven = "YUKSEK (n-gram imza birebir oylandi)";
        s.sinif_ad = std::string("OLD2-NG ") + SINIF_ADLARI[std::min(s.sinif, 5)];
        s.katman_karar = "K3: eski nesil .vmp1 n-gram imzasi";
        s.esitlenen_profil = "n-gram stub imzasi";
        if (s.sinif <= 4) {
            for (int i = 0; i < vmpdb::PROFIL_SAYI; i++) {
                const auto& pr = vmpdb::PROFILLER[i];
                if ((int)pr.surum != eski_kazanan) continue;
                if ((int)pr.sinif != s.sinif) continue;
                if ((int)pr.bolum_sayi != (int)s.kor.size()) continue;
                uint64_t d = 0;
                for (int j = 0; j < (int)s.kor.size(); j++) {
                    d += (uint64_t)llabs((long long)s.kor[j].raw - (long long)pr.raw[j]);
                    d += (uint64_t)llabs((long long)s.kor[j].vsz - (long long)pr.vsz[j]);
                }
                if (d == 0) { s.esitlenen_profil = pr.build; break; }
            }
        }
        ozellik_cikar(s);
        return;
    }

    // ---- KATMAN 2: PURE cipa
    if (s.sinif == S_PURE && !s.kor.empty()) {
        uint32_t raw = s.kor[0].raw, vsz = s.kor[0].vsz;
        std::vector<int> capa_uyan;
        for (int sv = 0; sv < vmpdb::SURUM_SAYI; sv++) {
            if (k1_aktif && std::find(k1.begin(), k1.end(), sv) == k1.end()) continue;
            for (int c = 0; c < 2; c++) {
                if (vmpdb::PURE_CAPA[sv][c].raw == raw &&
                    vmpdb::PURE_CAPA[sv][c].vsz == vsz &&
                    raw > 0) {
                    capa_uyan.push_back(sv);
                    break;
                }
            }
        }
        bool esit_tam = capa_uyan.size() == (size_t)vmpdb::ESDEGER_SAYI;
        if (esit_tam)
            for (int i = 0; i < vmpdb::ESDEGER_SAYI && esit_tam; i++)
                if (std::find(capa_uyan.begin(), capa_uyan.end(),
                              vmpdb::ESDEGER_UYE[i]) == capa_uyan.end())
                    esit_tam = false;
        if (esit_tam) {
            for (int i = 0; i < vmpdb::ESDEGER_SAYI; i++)
                s.adaylar.push_back({vmpdb::ESDEGER_UYE[i], 0});
            s.esitlik_sinifi = true;
            s.guven = "KESIN ESITLIK (fiziksel sinir — wrapper bayt-ozdest)";
            s.sinif_ad = "PURE";
            s.katman_karar = "K2: PURE cipa + esitlik sinifi";
            s.esitlenen_profil = "PURE-wrapper (kripto-bit secenekleri ayristirilamaz)";
            ozellik_cikar(s);
            return;
        }
        if (capa_uyan.size() == 1) {
            s.adaylar.push_back({capa_uyan[0], 0});
            s.guven = "YUKSEK (PURE cipa birebir)";
            s.sinif_ad = "PURE";
            s.katman_karar = "K2: PURE cipa birebir eslesme";
            s.esitlenen_profil = "PURE-wrapper (kripto-bit secenekleri ayristirilamaz)";
            ozellik_cikar(s);
            return;
        }
        // cipa yok ama yapi PURE → ozel varyant kontrolu
        if (capa_uyan.empty() && s.bolum_adlari_degisti) {
            // adlar degismis olabilir; capalari (raw,vsz) yine de dene — isim etkisiz
            // (yukarida zaten denendi; buraya dusemisse bilinmeyen capa)
            s.ozel_varyant = true;
        }
    }

    // ---- KATMAN 4: yapisal profil (GORELI marj ile)
    if (s.sinif > 4) {
        if (capa2_dene(s)) { s.sinif_ad = SINIF_ADLARI[s.sinif]; return; }
        s.sinif_ad = "?"; s.guven = "YOK";
        // yine de aile bilgisi ver
        if (vmp_bayrak) { s.ozel_varyant = true; s.guven = "OZEL VARYANT (yapi tanimsiz)"; }
        return;
    }
    s.sinif_ad = SINIF_ADLARI[s.sinif];
    std::map<int, uint64_t> skor;
    std::map<int, uint64_t> skor_boy;   // profil toplam boyu (goreli marj icin)
    for (int i = 0; i < vmpdb::PROFIL_SAYI; i++) {
        const auto& pr = vmpdb::PROFILLER[i];
        if ((int)pr.sinif != s.sinif) continue;
        if ((int)pr.bolum_sayi != (int)s.kor.size()) continue;
        if (k1_aktif && std::find(k1.begin(), k1.end(), (int)pr.surum) == k1.end()) continue;
        uint64_t d = 0, tb = 0;
        if (s.sinif == S_PURE) {
            d = (uint64_t)llabs((long long)s.kor[0].vsz - (long long)pr.vsz[0]) * 8
              + (uint64_t)llabs((long long)s.kor[0].raw - (long long)pr.raw[0]);
            tb = pr.raw[0];
        } else {
            for (int j = 0; j < (int)s.kor.size(); j++) {
                d += (uint64_t)llabs((long long)s.kor[j].raw - (long long)pr.raw[j]);
                d += (uint64_t)llabs((long long)s.kor[j].vsz - (long long)pr.vsz[j]);
                tb += pr.raw[j];
            }
        }
        auto it = skor.find(pr.surum);
        if (it == skor.end() || d < it->second) {
            skor[pr.surum] = d;
            skor_boy[pr.surum] = tb;
        }
    }
    if (skor.empty()) {
        if (capa2_dene(s)) return;
        s.guven = vmp_bayrak ? "OZEL VARYANT (uyumlu surum profili yok — MODLANMIS motor olabilir)" : "YOK";
        if (vmp_bayrak) s.ozel_varyant = true;
        s.katman_karar = "K4: uyumlu profil yok";
        return;
    }
    std::vector<std::pair<uint64_t,int>> sirali;
    for (auto& kv : skor) sirali.push_back({kv.second, kv.first});
    std::sort(sirali.begin(), sirali.end());
    // v4: K4 eslesmesi anlamsiz uzakliktaysa (profil ailesi farkli girdi),
    // once capa2 aile cipini dene — girdi-ailesine ozgu kesin imza
    if (!sirali.empty() && sirali[0].first > 100000) {
        Sonuc dene = s;
        if (capa2_dene(dene)) { s = dene; s.sinif_ad = SINIF_ADLARI[s.sinif]; return; }
    }
    static const uint64_t MARGINLAR[] = {0, 24576, 32768, 24576, 8192};
    uint64_t marj = MARGINLAR[s.sinif];
    // v4: goreli marj — profil boyunun %3'unu asan marj uygulama
    uint64_t profil_boy = skor_boy[sirali[0].second];
    uint64_t goreli = profil_boy / 32;   // ~%3
    if (goreli < marj) marj = goreli < 256 ? 256 : goreli;
    s.adaylar.push_back({sirali[0].second, sirali[0].first});
    for (size_t i = 1; i < sirali.size(); i++) {
        if (sirali[i].first - sirali[0].first <= marj)
            s.adaylar.push_back({sirali[i].second, sirali[i].first});
        else break;
    }
    if (s.adaylar.size() == (size_t)vmpdb::ESDEGER_SAYI && s.sinif == S_PURE) {
        bool hepsi_esitlik = true;
        for (auto& a : s.adaylar)
            if (!esitlik_uyesi(a.surum)) { hepsi_esitlik = false; break; }
        if (hepsi_esitlik) {
            s.esitlik_sinifi = true;
            s.guven = "KESIN ESITLIK (fiziksel sinir — wrapper bayt-ozdest)";
            s.katman_karar = "K4+esitlik: PURE yakin profil, 3.8.x motor sinifi";
            s.esitlenen_profil = "PURE-wrapper (kripto-bit secenekleri ayristirilamaz)";
            ozellik_cikar(s);
            return;
        }
    }
    if (s.sinif == S_PURE) {
        s.esitlenen_profil = "PURE-wrapper (kripto-bit secenekleri ayristirilamaz)";
        s.katman_karar = "K4: PURE yakin profil";
        ozellik_cikar(s);
        return;
    }
    for (int i = 0; i < vmpdb::PROFIL_SAYI; i++) {
        const auto& pr = vmpdb::PROFILLER[i];
        if ((int)pr.surum != s.adaylar[0].surum) continue;
        if ((int)pr.sinif != s.sinif || (int)pr.bolum_sayi != (int)s.kor.size()) continue;
        uint64_t d = 0;
        for (int j = 0; j < (int)s.kor.size(); j++) {
            d += (uint64_t)llabs((long long)s.kor[j].raw - (long long)pr.raw[j]);
            d += (uint64_t)llabs((long long)s.kor[j].vsz - (long long)pr.vsz[j]);
        }
        if (d == 0) { s.esitlenen_profil = pr.build; break; }
    }
    s.katman_karar = "K4: yapisal profil eslestirme";
    if (s.adaylar.size() == 1)
        s.guven = s.adaylar[0].dist == 0 ? "YUKSEK (imza birebir)" : "ORTA (yakin profil)";
    else
        s.guven = "CIFT-ADAY (yakin profil)";
    ozellik_cikar(s);
}

// ---------------------------------------------------------------- dump duzeltici
// bellek goruntusunu (headers + bolumler va ofsetlerinde) analiz-edilebilir PE'ye cevirir
static bool dump_duzelt(std::vector<uint8_t>& v) {
    if (v.size() < 0x400 || v[0] != 'M' || v[1] != 'Z') return false;
    uint32_t e = 0;
    memcpy(&e, &v[0x3C], 4);
    if (e + 24 > v.size() || memcmp(&v[e], "PE\0\0", 4) != 0) return false;
    uint16_t n = 0, opt_boyut = 0;
    memcpy(&n, &v[e + 6], 2);
    memcpy(&opt_boyut, &v[e + 20], 2);
    size_t opt = e + 24;
    size_t bt = opt + opt_boyut;
    for (int i = 0; i < n && bt + 40 * (size_t)(i + 1) <= v.size(); i++) {
        size_t o = bt + 40 * i;
        uint32_t vsz = 0, va = 0;
        memcpy(&vsz, &v[o + 8], 4);
        memcpy(&va, &v[o + 12], 4);
        uint32_t yeni_ro = va;
        uint32_t yeni_rsz = (vsz + 0x1FF) & ~0x1FFu;
        if ((uint64_t)yeni_ro + yeni_rsz > v.size())
            yeni_rsz = v.size() > yeni_ro ? (uint32_t)(v.size() - yeni_ro) : 0;
        memcpy(&v[o + 20], &yeni_ro, 4);
        memcpy(&v[o + 16], &yeni_rsz, 4);
    }
    return true;
}

// ---------------------------------------------------------------- [R] --sim: loader emulasyonu
static void sim_rapor(const char* yol, const char* dump_yolu) {
    PE p;
    printf("\n");
    if (!pe_ac(yol, p)) {
        printf("  %s[SIM] HATA:%s %s\n", R(KIRMIZI), R(SIFIRLA), p.hata.c_str());
        return;
    }
    printf("  %s%s", R("\x1b[96m\x1b[1m"),
           "=================== LOADER EMULATION (i4M tarzi — kod CALISTIRILMAZ) ===================\n");
    printf("%s", R(SIFIRLA));
    printf("  [1/8] DOS/NT header dogrulama            : %sTAMAM%s (PE32%s, %u bolum)\n",
           R(YESIL), R(SIFIRLA), p.opt_sihir == 0x20B ? "+" : "", p.bolum_sayisi);
    printf("  [2/8] Tercih edilen ImageBase            : 0x%llX %s\n",
           (unsigned long long)p.resim_taban,
           (p.dll_oz & 0x40) ? R("(ASLR: DYNAMIC_BASE — taban kayabilir)") : R("(sabit)"));
    printf("  [3/8] Header kopyalama (SizeOfHeaders)   : tamam\n");
    printf("  [4/8] Bolum esleme (raw -> virtual)      : %zu bolum\n", p.bolumler.size());
    printf("  [5/8] Base relocation                    : ");
    {
        uint32_t rel_rva = p.veri_dizin[5][0], rel_boy = p.veri_dizin[5][1];
        if (!rel_rva || !rel_boy) printf("%sYOK (.reloc stripli — koruyucu izi)%s\n", R(SARI), R(SIFIRLA));
        else {
            long of = -1;
            for (auto& b : p.bolumler)
                if (b.va <= rel_rva && rel_rva < b.va + (b.vsz > b.rsz ? b.vsz : b.rsz))
                    { of = (long)b.ro + (rel_rva - b.va); break; }
            int blok = 0, giris = 0;
            if (of >= 0 && of + 8 < (long)p.veri.size()) {
                long son = of + rel_boy;
                while (of + 8 <= son && of + 8 < (long)p.veri.size() && blok < 4096) {
                    uint32_t rva = 0, boy = 0;
                    memcpy(&rva, &p.veri[of], 4);
                    memcpy(&boy, &p.veri[of + 4], 4);
                    if (boy < 8) break;
                    for (uint32_t j = of + 8; j + 2 <= of + boy && j + 2 < (long)p.veri.size(); j += 2) {
                        uint16_t e = 0;
                        memcpy(&e, &p.veri[j], 2);
                        if ((e & 0xF000) == 0x3000 || (e & 0xF000) == 0x0A00 || (e & 0xF000) == 0x0B00 || (e & 0xF000) == 0x0E00)
                            giris++;
                    }
                    of += boy;
                    blok++;
                }
            }
            printf("%d blok / %d giris (tablo mevcut, uygulanmasi gerekmez)\n", blok, giris);
        }
    }
    printf("  [6/8] Import cozumu                      : %zu DLL", p.importlar.size());
    if (!p.importlar.empty()) {
        printf(" (");
        for (size_t i = 0; i < p.importlar.size() && i < 6; i++)
            printf("%s%s x%d", i ? ", " : "", p.importlar[i].first.c_str(), p.importlar[i].second);
        printf(")");
    }
    printf("\n");
    if (!p.import_fonksiyonlar.empty()) {
        printf("        IAT ornekleri                     : ");
        for (size_t i = 0; i < p.import_fonksiyonlar.size() && i < 10; i++)
            printf("%s%s", i ? ", " : "", p.import_fonksiyonlar[i].c_str());
        printf("%s\n", p.import_fonksiyonlar.size() > 10 ? " ..." : "");
    }
    printf("  [7/8] Mapped ImageBase guncellemesi      : 0x%llX\n",
           (unsigned long long)p.resim_taban);
    printf("  [8/8] Bolum korumalari                   :\n");
    for (auto& b : p.bolumler) {
        const char* k = "PAGE_READONLY";
        if ((b.oz & 0x20000000) && (b.oz & 0x80000000)) k = "PAGE_EXECUTE_READWRITE";
        else if (b.oz & 0x20000000) k = "PAGE_EXECUTE_READ";
        else if (b.oz & 0x80000000) k = "PAGE_READWRITE";
        printf("        %-10s vsz=%-8u raw=%-8u %s%s%s\n", b.ad.c_str(), b.vsz, b.rsz,
               R(GRAY), k, R(SIFIRLA));
    }
    // TLS
    if (p.veri_dizin[9][0]) {
        long of = -1;
        for (auto& b : p.bolumler)
            if (b.va <= p.veri_dizin[9][0] && p.veri_dizin[9][0] < b.va + (b.vsz > b.rsz ? b.vsz : b.rsz))
                { of = (long)b.ro + (p.veri_dizin[9][0] - b.va); break; }
        printf("  TLS dizini mevcut (callback'lar CALISTIRILMAZ, yalniz raporlanir)\n");
        if (of >= 0 && of + 24 < (long)p.veri.size()) {
            uint64_t cb = 0;
            memcpy(&cb, &p.veri[of + 24], p.opt_sihir == 0x20B ? 8 : 4);
            if (cb) printf("        callback[0] = 0x%llX\n", (unsigned long long)cb);
        }
    }
    printf("  EP (giris noktasi)                       : RVA 0x%X → ", p.giris_rva);
    for (auto& b : p.bolumler)
        if (b.va <= p.giris_rva && p.giris_rva < b.va + (b.vsz ? b.vsz : b.rsz))
            { printf("bolum '%s'%s\n", b.ad.c_str(),
                     standart_ad(b.ad) ? "" : R("  ← KORUYUCU ICINDE (paketleyici davranisi)")); break; }
    printf("  Bellek goruntusu boyutu (SizeOfImage)    : %u bayt\n", p.resim_boyu);
    if (dump_yolu) {
        // bellek goruntusu olustur: headers + bolumler va ofsetlerinde
        std::vector<uint8_t> img(p.resim_boyu ? p.resim_boyu : (uint32_t)p.veri.size(), 0);
        size_t hdr = std::min((size_t)0x1000, img.size());
        memcpy(img.data(), p.veri.data(), hdr);
        for (auto& b : p.bolumler) {
            if (b.ro + b.rsz <= p.veri.size() && b.va + b.rsz <= img.size())
                memcpy(img.data() + b.va, p.veri.data() + b.ro, b.rsz);
            else if (b.va < img.size()) {
                size_t kopya = std::min({(size_t)b.rsz, p.veri.size() - (size_t)b.ro, img.size() - (size_t)b.va});
                if (b.ro < p.veri.size() && kopya)
                    memcpy(img.data() + b.va, p.veri.data() + b.ro, kopya);
            }
        }
        dump_duzelt(img);
        FILE* f = fopen(dump_yolu, "wb");
        if (f) {
            fwrite(img.data(), 1, img.size(), f);
            fclose(f);
            printf("  %s[SIM DUMP YAZILDI]%s %s (%zu bayt) — vmpdet ile yeniden taranabilir\n",
                   R(YESIL), R(SIFIRLA), dump_yolu, img.size());
        } else printf("  %s[SIM DUMP HATASI]%s yazilamadi: %s\n", R(KIRMIZI), R(SIFIRLA), dump_yolu);
    }
    printf("  %s======================================================================================%s\n",
           R("\x1b[96m\x1b[1m"), R(SIFIRLA));
}

// bellek dokumunden ic katman PE basliklarini geri kazan (UPX acilmis / sarmali imajlar)
static void ic_katman_geri_kazan(const std::vector<uint8_t>& v) {
    struct Bulgu { size_t ofset; std::vector<std::pair<std::string,uint32_t>> bolumler; };
    std::vector<Bulgu> bulgular;
    for (size_t i = 0x200; i + 4 < v.size(); i += 4) {
        if (memcmp(&v[i], "PE\0\0", 4) != 0) continue;
        // FileHeader: makine(2) bolum(2) ...
        uint16_t makine = 0, n = 0, opt_boyut = 0;
        memcpy(&makine, &v[i + 4], 2);
        memcpy(&n, &v[i + 6], 2);
        memcpy(&opt_boyut, &v[i + 20], 2);
        if (n < 1 || n > 96 || opt_boyut < 0xE0 || opt_boyut > 0xF0) continue;
        if (makine != 0x8664 && makine != 0x14c) continue;
        size_t bt = i + 24 + opt_boyut;
        if (bt + 40 * (size_t)n > v.size()) continue;
        Bulgu b; b.ofset = i;
        bool vmp_var = false;
        for (int k = 0; k < n; k++) {
            size_t o = bt + 40 * k;
            char ad[9] = {0};
            memcpy(ad, &v[o], 8);
            uint32_t vsz = 0, va = 0;
            memcpy(&vsz, &v[o + 8], 4);
            memcpy(&va, &v[o + 12], 4);
            std::string ads(ad);
            std::string kuc = kucuk(ads);
            if (kuc.rfind(".vmp", 0) == 0 || kuc.rfind("vmp", 0) == 0) vmp_var = true;
            if (va + vsz <= v.size() && vsz > 0)
                b.bolumler.push_back({ads, vsz});
        }
        if (vmp_var) bulgular.push_back(b);
        if (bulgular.size() >= 6) break;
    }
    if (bulgular.empty()) return;
    printf("  %sIC KATMAN GERI KAZANIMI (bellekte gömülü PE basliklari):%s\n",
           R(SARI), R(SIFIRLA));
    for (auto& b : bulgular) {
        printf("    PE@0x%zX bolumler:", b.ofset);
        for (auto& bb : b.bolumler) {
            if (kucuk(bb.first).rfind(".vmp", 0) == 0)
                printf(" %s(vsz=%u)", bb.first.c_str(), bb.second);
        }
        printf("\n");
        // capa2 vsz cipiyle surum atfi
        for (int a = 0; a < vmpdb::CAPA2_SAYI; a++) {
            const auto& aile = vmpdb::CAPA2[a];
            bool isaret = false;
            for (auto& bb : b.bolumler)
                if (bb.second == aile.isaret_vsz && kucuk(bb.first).rfind(".vmp",0)==0)
                    { isaret = true; break; }
            if (!isaret) continue;
            for (auto& bb : b.bolumler) {
                for (int kk = 0; kk < aile.kayit_sayi; kk++)
                    if (aile.kayit[kk].vsz == bb.second &&
                        !(bb.second == aile.isaret_vsz)) {
                        int sv = aile.kayit[kk].surum;
                        if (sv == 2 || sv == 8)
                            printf("      %s-> IC KATMAN SURUM: {Professional 3.8.1; Ultimate 3.8.4} (capa2 %s)%s\n",
                                   R(YESIL), aile.aile, R(SIFIRLA));
                        else
                            printf("      %s-> IC KATMAN SURUM: %s (capa2 %s)%s\n",
                                   R(YESIL), vmpdb::SURUM[sv], aile.aile, R(SIFIRLA));
                        break;
                    }
            }
        }
    }
}

// ---------------------------------------------------------------- [R] --live: canli surec dokumu
#ifndef _WIN32
static pid_t canli_baslat(const char* yol, const char* wine_komut) {
    pid_t pid = fork();
    if (pid == 0) {
        setpgid(0, 0);
        int devnull = open("/dev/null", 1);  // stdout'u bosalt (O_WRONLY=1)
        if (devnull >= 0) { dup2(devnull, 1); }
        execlp(wine_komut, wine_komut, yol, (char*)nullptr);
        _exit(127);
    }
    return pid;
}
static bool canli_bul(const char* yol, pid_t oncelikli, pid_t& bul, unsigned long& taban, unsigned long& boy) {
    // /proc/[pid]/maps icinde hedef dosyayi tasiyan sureci bul.
    // NOT: wine'da exe, baslatan surecin KENDI uzayina mmap edilir (wine64 preloader)
    // — once 'oncelikli' (cocuk) surecinin haritasi kontrol edilir.
    char hedef[512];
    snprintf(hedef, sizeof hedef, "%s", yol);
    const char* taban_ad = strrchr(hedef, '/');
    taban_ad = taban_ad ? taban_ad + 1 : hedef;
    for (int tur = 0; tur < 60; tur++) {
        // 1) once cocuk surecinin kendisi (wine preloader exe'yi burada tasiyor)
        {
            char mp[64], satir[1024];
            snprintf(mp, sizeof mp, "/proc/%d/maps", oncelikli);
            FILE* f = fopen(mp, "r");
            if (f) {
                unsigned long en_dusuk = ~0UL, en_yuksek = 0;
                bool bulundu = false;
                while (fgets(satir, sizeof satir, f)) {
                    if (strstr(satir, taban_ad)) {
                        unsigned long a = strtoul(satir, nullptr, 16);
                        char* kes = strchr(satir, '-');
                        unsigned long b = kes ? strtoul(kes + 1, nullptr, 16) : a;
                        if (a < en_dusuk) en_dusuk = a;
                        if (b > en_yuksek) en_yuksek = b;
                        bulundu = true;
                    }
                }
                fclose(f);
                if (bulundu && en_dusuk != ~0UL) {
                    bul = oncelikli; taban = en_dusuk; boy = en_yuksek - en_dusuk;
                    char memp[64];
                    snprintf(memp, sizeof memp, "/proc/%d/mem", oncelikli);
                    FILE* m = fopen(memp, "rb");
                    if (m) {
                        uint8_t hdr[0x400] = {};
                        if (fseek(m, (long)en_dusuk, SEEK_SET) == 0 &&
                            fread(hdr, 1, sizeof hdr, m) > 0x200 && hdr[0] == 'M' && hdr[1] == 'Z') {
                            uint32_t e2 = 0;
                            memcpy(&e2, &hdr[0x3C], 4);
                            if (e2 + 24 < sizeof hdr) {
                                size_t opt = e2 + 24;
                                uint32_t sb = 0;
                                memcpy(&sb, &hdr[opt + 56], 4);
                                if (sb > 0x1000 && sb < 0x40000000) boy = sb;
                            }
                        }
                        fclose(m);
                    }
                    return true;
                }
            }
        }
        // 2) genel tarama (exe ayri surece dusturse diye)
        DIR* d = opendir("/proc");
        if (d) {
            struct dirent* e;
            while ((e = readdir(d))) {
                if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
                pid_t pid = (pid_t)atoi(e->d_name);
                if (pid == getpid()) continue;
                char mp[64], satir[1024];
                snprintf(mp, sizeof mp, "/proc/%d/maps", pid);
                FILE* f = fopen(mp, "r");
                if (!f) continue;
                unsigned long en_dusuk = ~0UL;
                unsigned long en_yuksek = 0;
                bool bulundu = false;
                while (fgets(satir, sizeof satir, f)) {
                    if (strstr(satir, taban_ad)) {
                        unsigned long a = strtoul(satir, nullptr, 16);
                        char* kes = strchr(satir, '-');
                        unsigned long b = kes ? strtoul(kes + 1, nullptr, 16) : a;
                        if (a < en_dusuk) en_dusuk = a;
                        if (b > en_yuksek) en_yuksek = b;
                        bulundu = true;
                    }
                }
                fclose(f);
                if (bulundu && en_dusuk != ~0UL) {
                    bul = pid; taban = en_dusuk;
                    boy = en_yuksek - en_dusuk;
                    // PE header'dan SizeOfImage al
                    char memp[64];
                    snprintf(memp, sizeof memp, "/proc/%d/mem", pid);
                    FILE* m = fopen(memp, "rb");
                    if (m) {
                        uint8_t hdr[0x400] = {};
                        if (fseek(m, (long)en_dusuk, SEEK_SET) == 0 &&
                            fread(hdr, 1, sizeof hdr, m) > 0x200 && hdr[0] == 'M' && hdr[1] == 'Z') {
                            uint32_t e2 = 0;
                            memcpy(&e2, &hdr[0x3C], 4);
                            if (e2 + 24 < sizeof hdr) {
                                size_t opt = e2 + 24;
                                uint32_t sb = 0;
                                memcpy(&sb, &hdr[opt + 56], 4);
                                if (sb > 0x1000 && sb < 0x40000000) boy = sb;
                            }
                        }
                        fclose(m);
                    }
                    closedir(d);
                    return true;
                }
            }
            closedir(d);
        }
        usleep(500000);
    }
    return false;
}
#endif

static void canli_analiz(const char* yol, int bekle_ms, const char* dump_yolu) {
    printf("\n  %s[RUNTIME ANALIZ — CANLI SUREC]%s hedef: %s\n",
           R("\x1b[96m\x1b[1m"), R(SIFIRLA), yol);
#ifdef _WIN32
    // Windows: CreateProcess + ReadProcessMemory
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    wchar_t wcmd[1024];
    MultiByteToWideChar(CP_UTF8, 0, yol, -1, wcmd, 1024);
    if (!CreateProcessW(wcmd, nullptr, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        printf("  %s[HATA]%s surec baslatilamadi (%lu)\n", R(KIRMIZI), R(SIFIRLA), GetLastError());
        return;
    }
    Sleep(bekle_ms);
    // modul listesi
    HMODULE mods[256]; DWORD gerekli = 0;
    char dump_hedef[512];
    snprintf(dump_hedef, sizeof dump_hedef, "%s", dump_yolu ? dump_yolu : "vmpdump_live.bin");
    HANDLE hP = pi.hProcess;
    if (EnumProcessModules(hP, mods, sizeof(mods), &gerekli)) {
        MODULEINFO mi = {};
        if (GetModuleInformation(hP, mods[0], &mi, sizeof(mi)) && mi.lpBaseOfDll && mi.SizeOfImage) {
            std::vector<uint8_t> img(mi.SizeOfImage);
            SIZE_T okundu = 0;
            if (ReadProcessMemory(hP, mi.lpBaseOfDll, img.data(), img.size(), &okundu) && okundu > 0x400) {
                img.resize(okundu);
                dump_duzelt(img);
                FILE* f = fopen(dump_hedef, "wb");
                if (f) { fwrite(img.data(), 1, img.size(), f); fclose(f); }
                printf("  %s[DUMP OK]%s taban=%p boy=%zu → %s\n", R(YESIL), R(SIFIRLA),
                       mi.lpBaseOfDll, img.size(), dump_hedef);
            }
        }
    }
    TerminateProcess(hP, 0);
    WaitForSingleObject(hP, 5000);
    CloseHandle(hP); CloseHandle(pi.hThread);
#else
    // Linux: wine + /proc/pid/mem
    const char* wine_komut = getenv("VMPDET_WINE");
    if (!wine_komut || !wine_komut[0]) wine_komut = "wine";
    pid_t cocuk = canli_baslat(yol, wine_komut);
    if (cocuk < 0) { printf("  %s[HATA]%s fork basarisiz\n", R(KIRMIZI), R(SIFIRLA)); return; }
    printf("  surec baslatildi (pid=%d, wine=%s), %d ms bekleniyor...\n", cocuk, wine_komut, bekle_ms);
    pid_t hedef = 0; unsigned long taban = 0, boy = 0;
    if (!canli_bul(yol, cocuk, hedef, taban, boy)) {
        printf("  %s[HATA]%s hedef surec bellek haritasi bulunamadi (exe calisti mi?)\n",
               R(KIRMIZI), R(SIFIRLA));
        kill(-cocuk, SIGKILL); kill(cocuk, SIGKILL);
        return;
    }
    printf("  hedef bulundu: pid=%d taban=0x%lX boy=0x%lX\n", hedef, taban, boy);
    usleep(bekle_ms * 1000);
    char memp[64];
    snprintf(memp, sizeof memp, "/proc/%d/mem", hedef);
    FILE* m = fopen(memp, "rb");
    if (!m) {
        printf("  %s[HATA]%s /proc/%d/mem acilamadi: %s\n", R(KIRMIZI), R(SIFIRLA), hedef, strerror(errno));
        kill(-cocuk, SIGKILL); kill(cocuk, SIGKILL);
        return;
    }
    std::vector<uint8_t> img(boy);
    size_t okundu = 0;
    fseek(m, (long)taban, SEEK_SET);
    okundu = fread(img.data(), 1, boy, m);
    fclose(m);
    kill(-cocuk, SIGKILL); kill(cocuk, SIGKILL);
    waitpid(cocuk, nullptr, WNOHANG);
    if (okundu < 0x400) {
        printf("  %s[HATA]%s bellek okunamadi (%zu bayt)\n", R(KIRMIZI), R(SIFIRLA), okundu);
        return;
    }
    img.resize(okundu);
    dump_duzelt(img);
    char dump_hedef[512];
    snprintf(dump_hedef, sizeof dump_hedef, "%s", dump_yolu ? dump_yolu : "vmpdump_live.bin");
    FILE* f = fopen(dump_hedef, "wb");
    if (!f) { printf("  %s[HATA]%s dump yazilamadi\n", R(KIRMIZI), R(SIFIRLA)); return; }
    fwrite(img.data(), 1, img.size(), f);
    fclose(f);
    printf("  %s[DUMP OK]%s %zu bayt → %s\n", R(YESIL), R(SIFIRLA), img.size(), dump_hedef);
    ic_katman_geri_kazan(img);
#endif
    // dump'i yeniden analiz et
    if (!dump_yolu) dump_yolu = "vmpdump_live.bin";
    Sonuc s2;
    eski_ng_yukle();
    analiz(dump_yolu, s2);
    printf("\n  %s[RUNTIME SONUC — dump yeniden analiz]%s\n", R("\x1b[96m\x1b[1m"), R(SIFIRLA));
    bool upx_acilmis = false;
    {
        // dump'ta UPX bolumleri whitelisted -> kor bos olabilir; bellekte acilmis UPX imaji
        PE pd;
        if (pe_ac(dump_yolu, pd)) {
            int upx_say = 0;
            for (auto& b : pd.bolumler) if (upx_bolum_ad_mi(b.ad)) upx_say++;
            if (upx_say >= 2) upx_acilmis = true;
        }
    }
    if (upx_acilmis)
        printf("  dump karari: %sUPX bellekte ACILMIS goruntu%s — dis katman UPX'i calisma aninda cozmustur;\n"
               "  ic katmanlar yukaridaki GERI KAZANIM bloklarinda raporlandi\n",
               R("\x1b[93m\x1b[1m"), R(SIFIRLA));
    else if (s2.olumsuz_karar)
        printf("  dump karari: %s (%s) — %s\n", s2.paketleyici.c_str(), s2.tespit_notu.c_str(),
               "calisma aninda VMProtect koruması gorunmuyor");
    else if (s2.vmp_tespit) {
        printf("  dump karari: %sVMProtect tespit edildi%s (%s)\n", R(YESIL), R(SIFIRLA), s2.tespit_notu.c_str());
        if (!s2.adaylar.empty()) {
            if (s2.esitlik_sinifi)
                printf("  surum (dump): Professional 3.8.1 || Ultimate 3.8.4 [esitlik sinifi]\n");
            else
                printf("  surum (dump): %s (guven: %s)\n",
                       vmpdb::SURUM[s2.adaylar[0].surum], s2.guven.c_str());
        }
        printf("  bolumler (dump): ");
        for (auto& b : s2.kor) printf("%s(%u B) ", b.ad.c_str(), b.raw);
        printf("\n");
        if (s2.katmanli) {
            printf("  %sKATMAN KANITI (dump):%s", R(SARI), R(SIFIRLA));
            for (auto& n : s2.katman.notlar) printf(" %s;", n.c_str());
            if (s2.katman.cift_vmp_ad) printf(" cift .vmp bolum adi (double-protect);");
            printf("\n");
            for (auto& k : s2.katman.katmanlar)
                printf("  %sKATMAN (dump):%s %-18s -> %s (%s)\n", R(SARI), R(SIFIRLA),
                       k.bolum.c_str(), k.surum.c_str(), k.kaynak.c_str());
        }
    } else {
        printf("  dump karari: %s\n", s2.tespit_notu.c_str());
    }
}

// ---------------------------------------------------------------- TUI
static void cizgi(const char* bas, char c = '=') {
    printf("%s%s", R("\x1b[1m\x1b[96m"), "");
    fputs(bas, stdout);
    int n = 74 - (int)strlen(bas);
    for (int i = 0; i < n; i++) putchar(c);
    printf("%s\n", R(SIFIRLA));
}

static void rapor_tui(const char* yol, Sonuc& s) {
    printf("\n");
    cizgi(" VMDETECT v4 // GOD SSS TIER // TARGET ACQUISITION ");
    printf("%s  TARGET   :%s %s%s%s\n", R(SARI), R(SIFIRLA), R("\x1b[97m\x1b[1m"), yol, R(SIFIRLA));
    printf("%s  SIZE     :%s %zu bytes\n", R(SARI), R(SIFIRLA), s.dosya_boyut);
    printf("%s  ARCH     :%s %s%s%s\n", R(SARI), R(SIFIRLA),
           R(BEYAZ), s.makine.c_str(), R(SIFIRLA));
    if (s.olumsuz_karar && !s.vmp_tespit) {
        printf("%s  STATUS   :%s %sNOT VMProtect — NEGATIVE VERDICT%s\n",
               R(SARI), R(SIFIRLA), R("\x1b[91m\x1b[1m"), R(SIFIRLA));
        if (!s.paketleyici.empty())
            printf("%s  PACKER   :%s %s%s%s\n", R(SARI), R(SIFIRLA), R("\x1b[93m\x1b[1m"),
                   s.paketleyici.c_str(), R(SIFIRLA));
        if (!s.tespit_notu.empty())
            printf("%s  NOTE     :%s %s%s%s\n", R(SARI), R(SIFIRLA), R(GRAY), s.tespit_notu.c_str(), R(SIFIRLA));
        if (!s.kor.empty()) {
            printf("%s  SECTIONS :%s ", R(SARI), R(SIFIRLA));
            for (size_t i = 0; i < s.kor.size() && i < 8; i++)
                printf("%s%s(%u B) ", s.kor[i].ad.c_str()[0] ? s.kor[i].ad.c_str() : "(bos)",
                       s.kor[i].raw);
            printf("\n");
        }
        cizgi("");
        return;
    }
    if (!s.vmp_tespit) {
        printf("%s  STATUS   :%s %sNOT PROTECTED / NO VMProtect SIGNATURE%s\n",
               R(SARI), R(SIFIRLA), R("\x1b[91m\x1b[1m"), R(SIFIRLA));
        if (!s.tespit_notu.empty())
            printf("%s  NOTE     :%s %s%s%s\n", R(SARI), R(SIFIRLA), R(GRAY), s.tespit_notu.c_str(), R(SIFIRLA));
        cizgi("");
        return;
    }
    printf("%s  STATUS   :%s %sTARGET LOCKED — VMProtect SIGNATURE CONFIRMED%s\n",
           R(SARI), R(SIFIRLA), R("\x1b[92m\x1b[1m"), R(SIFIRLA));
    printf("%s  EVIDENCE :%s %s%s%s%s\n", R(SARI), R(SIFIRLA), R(BEYAZ), s.tespit_notu.c_str(),
           s.upx_kamuflaj ? R(" [UPX-CAMOUFLAGE]") : "", R(SIFIRLA));
    if (s.bolum_adlari_degisti) {
        printf("%s  WARNING  :%s %sSECTION NAMES MODIFIED%s — adlar .vmp degil, yapi VMProtect\n",
               R(SARI), R(SIFIRLA), R("\x1b[93m\x1b[1m"), R(SIFIRLA));
        printf("%s            %s(kaynagi: script/OnAfterSaveFile ya da modlanmis motor)\n",
               R(SARI), R(SIFIRLA));
    }
    if (s.katmanli) {
        printf("%s  LAYERS   :%s %sMULTI-LAYER PROTECTION DETECTED%s\n",
               R(SARI), R(SIFIRLA), R("\x1b[95m\x1b[1m"), R(SIFIRLA));
        if (s.katman.cift_vmp_ad)
            printf("%s            %scift ayni-adli .vmp bolumu → DOUBLE VMProtect (katman ustu katman)\n",
                   R(SARI), R(SIFIRLA));
        for (auto& k : s.katman.katmanlar)
            printf("%s            %s%-18s -> %s (%s)\n", R(SARI), R(BEYAZ),
                   k.bolum.c_str(), k.surum.c_str(), k.kaynak.c_str());
        for (auto& n : s.katman.notlar)
            printf("%s            %s%s\n", R(SARI), R(SIFIRLA), n.c_str());
    }
    printf("\n");
    cizgi(" STRUCTURAL INTELLIGENCE ", '-');
    printf("%s  Protector sections :%s %s%d%s  %s(",
           R(SARI), R(SIFIRLA), R(BEYAZ), (int)s.kor.size(), R(SIFIRLA), R(GRAY));
    for (size_t i = 0; i < s.kor.size(); i++)
        printf("%s%s(%u B)", i ? ", " : "",
               s.kor[i].ad.c_str()[0] ? s.kor[i].ad.c_str() : "(bos-ad)", s.kor[i].raw);
    printf(")%s\n", R(SIFIRLA));
    printf("%s  Layout class       :%s %s%s\n", R(SARI), R(SIFIRLA),
           R(BEYAZ), s.sinif_ad.c_str());
    printf("%s  Section flags      :%s %s%s%s\n", R(SARI), R(SIFIRLA), R(GRAY),
           s.desen_iz.c_str(), R(SIFIRLA));
    printf("%s  Imports  :%s %s%zu DLL%s\n", R(SARI), R(SIFIRLA),
           R(BEYAZ), s.import_dll, R(SIFIRLA));
    printf("%s  .reloc   :%s %s%s%s\n", R(SARI), R(SIFIRLA), R(BEYAZ),
           s.reloc_yok ? "STRIPPED" : "present", R(SIFIRLA));
    printf("\n");
    if (s.adaylar.empty() && s.ozellikler.empty()) {
        cizgi(" VERDICT ", '-');
        if (s.ozel_varyant)
            printf("  %s[OZEL VARYANT]%s yapi VMProtect ailesinde ama HICBIR bilinen\n"
                   "  surum profiline uymuyor → MODLANMIS/REBUILD MOTOR olabilir\n",
                   R("\x1b[93m\x1b[1m"), R(SIFIRLA));
        else
            printf("  %sYAPISAL ESLESME YOK%s — surum belirlenemedi (modlanmis/karma yapi)\n",
                   R("\x1b[93m\x1b[1m"), R(SIFIRLA));
        if (s.katmanli) {
            printf("  %sKATMANLAR (bolum bazli):%s\n", R(SARI), R(SIFIRLA));
            for (auto& k : s.katman.katmanlar)
                printf("    %-18s -> %s (%s)\n", k.bolum.c_str(), k.surum.c_str(), k.kaynak.c_str());
        }
        cizgi("");
        return;
    }
    cizgi(" VERSION IDENTIFICATION ", '-');
    if (s.ozel_varyant && s.adaylar.empty()) {
        printf("  %s[OZEL VARYANT]%s yapi VMProtect ailesinde ama HICBIR bilinen surum\n",
               R("\x1b[93m\x1b[1m"), R(SIFIRLA));
        printf("  %sprofiline uymuyor → MODLANMIS/REBUILD MOTOR olabilir (kaynak kopyasi)\n",
               R(GRAY));
    } else if (s.esitlik_sinifi) {
        printf("  %s[ESITLIK SINIFI]%s  %sProfessional 3.8.1  %s||%s  %sUltimate 3.8.4%s\n",
               R("\x1b[93m\x1b[1m"), R(SIFIRLA), R("\x1b[97m\x1b[1m"),
               R("\x1b[93m\x1b[1m"), R(SIFIRLA), R("\x1b[97m\x1b[1m"), R(SIFIRLA));
        printf("  %s3.8.x WRAPPER MOTORU — ciktilar bayt-duzeyinde OZDESTIR:%s\n",
               R(SARI), R(SIFIRLA));
        printf("  %s894 ortak invariant pozisyonda 0 fark; entropi parmak izi ayni;%s\n",
               R(GRAY), R(SIFIRLA));
        printf("  %simport/reloc/EP yamalari ayni. Tek dosyadan kesin ayristirma%s\n",
               R(GRAY), R(SIFIRLA));
        printf("  %sfiziksel olarak IMKANSIZ — dogru cevap bu esitlik sinifidir.%s\n",
               R(GRAY), R(SIFIRLA));
    } else {
        for (size_t i = 0; i < s.adaylar.size() && i < 4; i++) {
            auto& a = s.adaylar[i];
            int pct = a.dist == 0 ? 100 : (int)std::max(0.0, 100.0 - (double)a.dist / 512.0);
            printf("  %s#%d %-22s%s%s [", i == 0 ? R("\x1b[92m\x1b[1m") : R(GRAY), (int)i + 1,
                   vmpdb::SURUM[a.surum], R(SIFIRLA), i == 0 ? R(YESIL) : R(GRAY));
            int dolu = pct / 5;
            for (int j = 0; j < 20; j++) putchar(j < dolu ? (i == 0 ? '*' : '-') : ' ');
            printf("] %s%3d%%%s  %s(dist=%llu%s)%s\n", i == 0 ? R("\x1b[92m\x1b[1m") : R(GRAY), pct,
                   R(SIFIRLA), R(GRAY), (unsigned long long)a.dist,
                   a.dist == 0 ? " EXACT" : "", R(SIFIRLA));
        }
        if (s.adaylar.size() > 1)
            printf("\n%s  NOTE: %saday surumler yakin yapiyi paylasiyor%s\n",
                   R(SARI), R(BEYAZ), R(SIFIRLA));
    }
    if (!s.katman_karar.empty())
        printf("%s  DECISION PATH      :%s %s%s%s\n",
               R(SARI), R(SIFIRLA), R("\x1b[96m\x1b[1m"), s.katman_karar.c_str(), R(SIFIRLA));
    if (!s.esitlenen_profil.empty())
        printf("%s  MATCHED SIGNATURE  :%s %s%s%s\n",
               R(SARI), R(SIFIRLA), R("\x1b[96m\x1b[1m"), s.esitlenen_profil.c_str(), R(SIFIRLA));
    if (!s.ozellikler.empty()) {
        printf("\n");
        cizgi(" FEATURE ANALYSIS ", '-');
        for (auto& kv : s.ozellikler) {
            bool acik = kv.second.find("ACIK") != std::string::npos ||
                        kv.second.find("KESIN") != std::string::npos;
            bool belirsiz = kv.second.find("BELIRSIZ") != std::string::npos ||
                            kv.second.find("OLASI") != std::string::npos;
            printf("  %s[%s]%s %-22s%s : %s%s%s\n",
                   acik ? R(CIAN) : R(GRAY), acik ? "X" : (belirsiz ? "?" : " "), R(SIFIRLA),
                   kv.first.c_str(), R(GRAY),
                   acik ? R("\x1b[92m\x1b[1m") : (belirsiz ? R(SARI) : R(GRAY)),
                   kv.second.c_str(), R(SIFIRLA));
        }
    }
    cizgi("");
}

static void rapor_plain(const char* yol, Sonuc& s) {
    g_renk = false;
    printf("TARGET: %s\n", yol);
    if (s.olumsuz_karar && !s.vmp_tespit) {
        printf("VMProtect: HAYIR (NEGATIF KARAR)\n");
        if (!s.paketleyici.empty()) printf("Packer: %s\n", s.paketleyici.c_str());
        printf("Kanit: %s\n", s.tespit_notu.c_str());
        return;
    }
    printf("VMProtect: %s (%s)\n", s.vmp_tespit ? "DETECTED" : "NO", s.tespit_notu.c_str());
    if (s.bolum_adlari_degisti && s.vmp_tespit)
        printf("Uyari: bolum adlari degistirilmis (script/mod)\n");
    if (s.katmanli) {
        printf("Katman: COKLU (%s%s)\n", s.katman.cift_vmp_ad ? "cift .vmp bolumu" : "",
               s.katman.notlar.empty() ? "" : s.katman.notlar[0].c_str());
        for (auto& k : s.katman.katmanlar)
            printf("  katman-bolum %s -> surum: %s (%s)\n", k.bolum.c_str(), k.surum.c_str(), k.kaynak.c_str());
    }
    if (s.vmp_tespit && !s.adaylar.empty()) {
        if (s.esitlik_sinifi) {
            printf("Version (equivalence): Professional 3.8.1 / Ultimate 3.8.4 [3.8.x motor sinifi]\n");
            printf("Guven: %s\n", s.guven.c_str());
        } else {
            printf("Version (best match): %s [%s] dist=%llu guven=%s\n",
                   vmpdb::SURUM[s.adaylar[0].surum], vmpdb::EDISYON[s.adaylar[0].surum],
                   (unsigned long long)s.adaylar[0].dist, s.guven.c_str());
            for (size_t i = 1; i < s.adaylar.size(); i++)
                printf("  alt aday: %s dist=%llu\n", vmpdb::SURUM[s.adaylar[i].surum],
                       (unsigned long long)s.adaylar[i].dist);
        }
        if (s.ozel_varyant) printf("OZEL VARYANT: bilinmeyen VMProtect yapisı (modlanmis motor olabilir)\n");
        if (!s.katman_karar.empty()) printf("Karar katmani: %s\n", s.katman_karar.c_str());
        if (!s.esitlenen_profil.empty())
            printf("Matched profile: %s\n", s.esitlenen_profil.c_str());
        for (auto& kv : s.ozellikler)
            printf("FEATURE %-24s: %s\n", kv.first.c_str(), kv.second.c_str());
    } else if (s.vmp_tespit) {
        if (s.ozel_varyant) printf("OZEL VARYANT: bilinmeyen VMProtect yapisi (modlanmis motor olabilir)\n");
        if (!s.katman_karar.empty()) printf("Karar katmani: %s\n", s.katman_karar.c_str());
        for (auto& kv : s.ozellikler)
            printf("FEATURE %-24s: %s\n", kv.first.c_str(), kv.second.c_str());
    }
}

static void json_kacis(FILE* out, const char* s) {
    for (const char* c = s; *c; c++) {
        if (*c == '"' || *c == '\\') fprintf(out, "\\%c", *c);
        else if ((unsigned char)*c < 0x20) fprintf(out, "\\u%04x", *c);
        else fputc(*c, out);
    }
}

static void rapor_json(const char* yol, Sonuc& s, FILE* out) {
    fprintf(out, "  {\n    \"dosya\": \"");
    json_kacis(out, yol);
    fprintf(out, "\",\n    \"vmp\": %s,\n", s.vmp_tespit ? "true" : "false");
    fprintf(out, "    \"kanit\": \"");
    json_kacis(out, s.tespit_notu.c_str());
    fprintf(out, "\",\n");
    if (!s.vmp_tespit) {
        fprintf(out, "    \"olumsuz_karar\": true,\n    \"paketleyici\": \"");
        json_kacis(out, s.paketleyici.c_str());
        fprintf(out, "\",\n");
    }
    if (s.vmp_tespit && !s.adaylar.empty()) {
        if (s.esitlik_sinifi) {
            fprintf(out, "    \"surum\": \"Professional 3.8.1 / Ultimate 3.8.4\",\n");
            fprintf(out, "    \"esitlik_sinifi\": true,\n");
            fprintf(out, "    \"motor_grubu\": \"3.8.x\",\n");
        } else {
            fprintf(out, "    \"surum\": \"%s\",\n    \"edition\": \"%s\",\n",
                    vmpdb::SURUM[s.adaylar[0].surum], vmpdb::EDISYON[s.adaylar[0].surum]);
            fprintf(out, "    \"motor_grubu\": \"%s\",\n", vmpdb::MOTOR_GRUBU[s.adaylar[0].surum]);
            fprintf(out, "    \"esitlik_sinifi\": false,\n");
        }
        fprintf(out, "    \"bolum_adlari_degisti\": %s,\n", s.bolum_adlari_degisti ? "true" : "false");
        fprintf(out, "    \"ozel_varyant\": %s,\n", s.ozel_varyant ? "true" : "false");
        fprintf(out, "    \"katmanli\": %s,\n", s.katmanli ? "true" : "false");
        if (s.katman.cift_vmp_ad)
            fprintf(out, "    \"katman_kaniti\": \"cift .vmp bolum adi (double-protect)\",\n");
        fprintf(out, "    \"guven\": \"");
        json_kacis(out, s.guven.c_str());
        fprintf(out, "\",\n    \"sinif\": \"%s\",\n    \"karar_katmani\": \"",
                s.sinif_ad.c_str());
        json_kacis(out, s.katman_karar.c_str());
        fprintf(out, "\",\n    \"eslesen_profil\": \"");
        json_kacis(out, s.esitlenen_profil.c_str());
        fprintf(out, "\",\n    \"adaylar\": [");
        for (size_t i = 0; i < s.adaylar.size(); i++)
            fprintf(out, "%s{\"surum\": \"%s\", \"dist\": %llu}", i ? ", " : "",
                    vmpdb::SURUM[s.adaylar[i].surum],
                    (unsigned long long)s.adaylar[i].dist);
        fprintf(out, "],\n    \"ozellikler\": {\n");
        bool ilk = true;
        for (auto& kv : s.ozellikler) {
            fprintf(out, "%s      \"", ilk ? "" : ",");
            json_kacis(out, kv.first.c_str());
            fprintf(out, "\": \"");
            json_kacis(out, kv.second.c_str());
            fprintf(out, "\"\n");
            ilk = false;
        }
        fprintf(out, "    }\n");
    }
    fprintf(out, "  }");
}

// ---------------------------------------------------------------- dizin
#ifndef _WIN32
static void dizin_exe_ekle(const std::string& dzn, std::vector<std::string>& out) {
    DIR* d = opendir(dzn.c_str());
    if (!d) return;
    struct dirent* e;
    while ((e = readdir(d))) {
        std::string f = e->d_name;
        if (f.size() > 4 && f.compare(f.size() - 4, 4, ".exe") == 0)
            out.push_back(dzn + (dzn.back() == '/' ? "" : "/") + f);
    }
    closedir(d);
}
#else
static void dizin_exe_ekle(const std::string& dzn, std::vector<std::string>& out) {
    try {
        for (auto& e : fs::directory_iterator(dzn)) {
            std::string f = e.path().filename().string();
            if (f.size() > 4 && f.compare(f.size() - 4, 4, ".exe") == 0)
                out.push_back(e.path().string());
        }
    } catch (...) {}
}
#endif

// ---------------------------------------------------------------- main
int main(int argc, char** argv) {
    std::vector<std::string> hedefler;
    const char* json_yol = nullptr;
    const char* dump_yolu = nullptr;
    const char* sim_hedef = nullptr;
    const char* live_hedef = nullptr;
    int bekle_ms = 4000;
    bool plain = false;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--json" && i + 1 < argc) json_yol = argv[++i];
        else if (a == "--plain") plain = true;
        else if (a == "--no-color") g_renk = false;
        else if (a == "--dir" && i + 1 < argc) dizin_exe_ekle(argv[++i], hedefler);
        else if (a == "--sim") { if (i + 1 < argc) sim_hedef = argv[++i]; }
        else if (a == "--live") { if (i + 1 < argc) live_hedef = argv[++i]; }
        else if (a == "--dump" && i + 1 < argc) dump_yolu = argv[++i];
        else if (a == "--wait" && i + 1 < argc) bekle_ms = atoi(argv[++i]);
        else hedefler.push_back(a);
    }
    if (sim_hedef) {
        sim_rapor(sim_hedef, dump_yolu);
        return 0;
    }
    if (live_hedef) {
        canli_analiz(live_hedef, bekle_ms, dump_yolu);
        return 0;
    }
    if (hedefler.empty()) {
        printf("VMDETECT v4 — GOD SSS TIER VMProtect surum & ozellik & KATMAN dedektoru\n"
               "Katmanli deterministik mimari (ML yok) + paketleyici imza motoru + runtime modu\n"
               "  K1 bolum-karakteristik filtre / K2 PURE cipa / K3 eski-nesil n-gram / K4 yapisal profil (goreli marj)\n"
               "  [P] UPX/Themida/Enigma/... imzalari — 'VMProtect DEGIL' kesin olumsuz karari\n"
               "  [C] bolum-adi-degistirildi + OZEL VARYANT (modlanmis motor) tesbiti\n"
               "  [L] cok katman (cift .vmp bolumu, UPX dis katman)\n"
               "  [R] --sim loader emulasyonu / --live canli surec dump + otomatik yeniden analiz\n\n"
               "Kullanim:\n"
               "  %s <dosya.exe>       tek hedef (askeri TUI)\n"
               "  %s --dir <klasor>    batch tarama\n"
               "  %s --json o.json --dir <klasor>\n"
               "  %s --sim <dosya> [--dump cikis.bin]\n"
               "  %s --live <dosya.exe> [--wait 4000] [--dump cikis.bin]\n",
               argv[0], argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }
    eski_ng_yukle();
    if (!ISATTU(1) && !json_yol) plain = true;
    FILE* jf = nullptr;
    if (json_yol) { jf = fopen(json_yol, "w"); fprintf(jf, "[\n"); }
    int vmp_sayi = 0, esitlik_sayi = 0, olumsuz_sayi = 0, katman_sayi = 0;
    size_t idx = 0;
    for (auto& h : hedefler) {
        Sonuc s;
        analiz(h.c_str(), s);
        if (s.vmp_tespit) vmp_sayi++;
        if (s.esitlik_sinifi) esitlik_sayi++;
        if (s.olumsuz_karar && !s.vmp_tespit) olumsuz_sayi++;
        if (s.katmanli) katman_sayi++;
        if (jf) { if (idx) fprintf(jf, ",\n"); rapor_json(h.c_str(), s, jf); }
        else if (plain || hedefler.size() > 3) rapor_plain(h.c_str(), s);
        else rapor_tui(h.c_str(), s);
        idx++;
    }
    if (jf) { fprintf(jf, "\n]\n"); fclose(jf); printf("JSON yazildi: %s\n", json_yol); }
    if (hedefler.size() > 3 || plain)
        printf("\nOZET: %zu hedef | %d VMProtect | %d NEGATIF (VMP degil) | %d esitlik sinifi (3.8.x) | %d cok katmanli\n",
               hedefler.size(), vmp_sayi, olumsuz_sayi, esitlik_sayi, katman_sayi);
    return 0;
}
