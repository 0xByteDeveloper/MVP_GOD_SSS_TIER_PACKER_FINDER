// ============================================================================
//  VMDETECT v5 — GOD SSS TIER EDITION (MILITARY TUI)
//  Surum + ozellik + KATMAN + paketleyici + RUNTIME analizi
//  DORT AILE KORPUSU: 32-bit EXE / 32-bit DLL / 64-bit EXE / 64-bit DLL
//
//  YENI (v5):
//   [A] AILE KAPISI — makine (i386/AMD64) + DLL bayragi ile 4 girdi ailesi:
//       T32E / T32D / T64E / T64D — her aile icin ayri cipa korpusu
//   [K2] AILE CIPASI — (aile, surum, build-tipi) birebir boyut imzasi;
//       312 profil, 10 surum, kanitlanmis benzersizlik
//   [E] NCELLESTIRILMIS ESITLIK — Pro 3.8.1 ∥ Ult 3.8.4 bayt-ozdestligi
//       YALNIZ saf-wrapper (fn0) yapilarinda gecerli; Pack/Move/HEPSI
//       yapilarinda iki surum AYRIŞIR (cipa kanitiyla)
//   [D] DLL FARKINDALIGI — export tablosu analizi, --live DLL host
//       (rundll32), --sim DLL destegi
//   Korunan v4 yetenekleri:
//   [P] PAKETLEYICI IMZA MOTORU — UPX/Themida/Enigma/ASProtect/... +
//       "VMProtect DEGIL" kesin olumsuz karari (negatif tespit)
//   [C] OZEL YAPI — bolum adlari degistirilmis (script/mod) ciktilar ve
//       BILINMEYEN VMProtect varyanti (modlanmis motor) raporu
//   [L] COK KATMAN — cift .vmp0 (double-protect), UPX dis katman, katman yigini
//   [R] RUNTIME MODU (--sim / --live) — i4MConsoleLoader mantiginda loader
//       emulasyonu (kod CALISTIRMAZ) ve canli surec dump + yeniden analiz
//
//  Kullanim:
//    vmpdet <dosya>                  tek hedef (askeri TUI raporu)
//    vmpdet --dir <klasor>           batch tarama (.exe + .dll)
//    vmpdet --json <out.json> ...    JSON cikti
//    vmpdet --sim <dosya>            loader emulasyonu (kod CALISTIRMAZ)
//    vmpdet --sim --dump <o.bin>     + bellek goruntusunu yaz
//    vmpdet --live <dosya>           calistir + bellek dump + yeniden analiz
//                                    (DLL hedefi: rundll32 host otomatik)
// ============================================================================
#include "detektor_db5.h"
#include "host_gomulu.h"
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
    uint16_t makine = 0, bolum_sayisi = 0, dosya_oz = 0;
    uint32_t giris_rva = 0, dll_oz = 0, opt_sihir = 0, resim_boyu = 0;
    uint64_t resim_taban = 0;
    uint32_t e_lfanew = 0, opt_ofset = 0;
    uint32_t veri_dizin[16][2] = {};
    std::vector<Bolum> bolumler;
    std::vector<std::pair<std::string,int>> importlar;
    std::vector<std::string> import_fonksiyonlar;
    std::vector<std::string> export_adlar;      // v5: DLL/EXE export tablosu
    std::string export_dll_adi;
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
    memcpy(&p.dosya_oz, &d[e + 22], 2);           // v5: IMAGE_FILE_* (DLL bayragi 0x2000)
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
        if (b.ro >= (uint32_t)n) { b.rsz = 0; }
        else if (b.ro + b.rsz > (uint32_t)n) b.rsz = (uint32_t)n - b.ro;
        p.bolumler.push_back(b);
    }
    auto r2o = [&](uint32_t rva) -> long {
        for (auto& b : p.bolumler)
            if (b.va <= rva && rva < b.va + (b.vsz > b.rsz ? b.vsz : b.rsz))
                return (long)b.ro + (rva - b.va);
        return -1;
    };
    if (nd > 1) {
        uint32_t imp_rva = p.veri_dizin[1][0];
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
    // v5: export dizini (DLL analizi + --live host fonksiyonu icin)
    if (p.veri_dizin[0][0]) {
        long eo = r2o(p.veri_dizin[0][0]);
        if (eo > 0 && eo + 40 <= (long)n) {
            uint32_t name_rva = 0, atf = 0, npt = 0;
            memcpy(&name_rva, &d[eo + 12], 4);
            memcpy(&atf, &d[eo + 28], 4);     // AddressOfFunctions
            uint32_t nn = 0;
            memcpy(&nn, &d[eo + 24], 4);      // NumberOfNames
            memcpy(&npt, &d[eo + 32], 4);     // AddressOfNames
            long no = r2o(name_rva);
            if (no > 0 && no < (long)n) {
                std::string ad;
                for (long j = no; j < (long)n && d[j] && ad.size() < 64; j++) ad += (char)d[j];
                p.export_dll_adi = ad;
            }
            long np = r2o(npt);
            if (np > 0 && nn && nn < 4096)
                for (uint32_t i = 0; i < nn && p.export_adlar.size() < 64; i++) {
                    if (np + 4 * (long)i + 4 > (long)n) break;
                    uint32_t nrva = 0;
                    memcpy(&nrva, &d[np + 4 * i], 4);
                    long o2 = r2o(nrva);
                    if (o2 > 0 && o2 < (long)n) {
                        std::string fn;
                        for (long j = o2; j < (long)n && d[j] && fn.size() < 64; j++) fn += (char)d[j];
                        if (!fn.empty()) p.export_adlar.push_back(fn);
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
    const char* bolumler[4];
    const char* dizgi[3];
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

static bool upx_bolum_ad_mi(const std::string& ad_orig) {
    std::string ad = kucuk(ad_orig);
    for (const char* p : {".upx0",".upx1",".upx2","upx0","upx1","upx2"})
        if (ad == p) return true;
    return false;
}

struct PackerTarama {
    bool upx_bolum_var = false;
    bool upx_gercek = false;
    bool upx_bilgi_dizgisi = false;
    const PackerImza* vurus = nullptr;
    bool vmp_isaret_dizgisi = false;
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
            break;
        }
    }
    return pt;
}

// ---------------------------------------------------------------- yapi siniflari
enum SinifKod { S_PURE = 0, S_BIG1 = 1, S_SEC3 = 2, S_SEC2BIG = 3, S_SEC2K = 4, S_BILINMEYEN = 9 };
static const char* const SINIF_ADLARI[] = {"PURE", "BIG1", "SEC3", "SEC2BIG", "SEC2K", "?"};

struct KorBolum { std::string ad; uint32_t raw, vsz, kar; };

struct KatmanBilgi {
    bool cift_vmp_ad = false;
    std::vector<std::string> notlar;
    struct KatmanKat { std::string bolum; std::string surum; std::string kaynak; };
    std::vector<KatmanKat> katmanlar;
};

struct Sonuc {
    bool vmp_tespit = false;
    std::string tespit_notu;
    std::string paketleyici;
    bool olumsuz_karar = false;
    std::string makine;
    int aile = -1;                     // v5: 0=T32E 1=T32D 2=T64E 3=T64D, -1=bilinmeyen
    std::string aile_ad;
    size_t dosya_boyut = 0;
    std::vector<KorBolum> kor;
    int sinif = S_BILINMEYEN;
    std::string sinif_ad;
    bool upx_kamuflaj = false, text_yok = false, reloc_yok = false;
    uint32_t text_ham = 0;
    size_t import_dll = 0;
    size_t export_sayi = 0;            // v5: DLL/EXE export sayisi
    struct Aday { int surum; uint64_t dist; };
    std::vector<Aday> adaylar;
    std::string guven;
    std::string esitlenen_profil;
    std::vector<std::pair<std::string,std::string>> ozellikler;
    std::string katman_karar;
    bool esitlik_sinifi = false;
    std::string desen_iz;
    bool bolum_adlari_degisti = false;
    bool ozel_varyant = false;
    bool katmanli = false;
    KatmanBilgi katman;
    bool sim_mod = false;
};

static int sinif_bul(const std::vector<KorBolum>& kb) {
    if (kb.size() == 1) return kb[0].raw <= 8192 ? S_PURE : S_BIG1;
    if (kb.size() == 2) return kb[1].raw > 100000 ? S_SEC2BIG : S_SEC2K;
    if (kb.size() == 3) return S_SEC3;
    return S_BILINMEYEN;
}

// ---------------------------------------------------------------- v5: aile kapisi
static int aile_bul(const PE& p) {
    bool dll = (p.dosya_oz & 0x2000) != 0;
    if (p.makine == 0x14C)  return dll ? 1 : 0;   // i386: T32D / T32E
    if (p.makine == 0x8664) return dll ? 3 : 2;   // AMD64: T64D / T64E
    return -1;
}

static bool esitlik_uyesi(int sv) {
    for (int i = 0; i < vmpdb::ESDEGER_SAYI; i++)
        if (vmpdb::ESDEGER_UYE[i] == sv) return true;
    return false;
}

// CAPA2: hello girdi-ailesi capa eslesmesi (runtime demo katmanlari icin)
static bool capa2_dene(Sonuc& s);

// ---------------------------------------------------------------- v5: ozellik cikarimi (tip tabanli)
// Build tipleri: 0=fn0 1=Pack 2=ImportProtection 3=HEPSI 4=Move_Virt
//                5=Move_Mutation 6=Move_Ultra 7=Move_Ultra_HEPSI
static void ozellik_cikar(Sonuc& s, int tip = -1) {
    if (s.adaylar.empty()) return;
    static const char* const OZELLIKLER[] = {
        "DebugMode","CryptValues","RunnerCRC","EncryptRegs","Pack","ImportProtection",
        "CheckDebugger","CheckVirtualMachine","MemoryProtection","StripFixups",
        "ResourceProtection","CheckKernelDebugger","StripDebugInfo",
        "LoaderCRC","EncryptBytecode", nullptr
    };
    // yapiya etki eden (boyut kaniti verilebilen) secenekler
    auto yapisal = [](const char* ad) {
        return !strcmp(ad, "Pack") || !strcmp(ad, "ImportProtection");
    };
    bool hepsi = (tip == 3 || tip == 7);
    bool fn_var = (tip >= 4);
    std::string fn_mod;
    if (fn_var) {
        if (tip == 6 || tip == 7) fn_mod = "ULTRA (virt+mutation)";
        else if (tip == 5) fn_mod = "MUTATION";
        else fn_mod = "VIRTUALIZATION";
    }
    std::string fn_satir = "yok (saf wrapper)";
    if (fn_var) fn_satir = "MOVE — " + fn_mod;
    if (tip < 0) fn_satir = "belirsiz (profil eslesmedi)";
    s.ozellikler.push_back({"VirtualizedFunction", fn_satir});

    for (int i = 0; OZELLIKLER[i]; i++) {
        const char* ad = OZELLIKLER[i];
        std::string durum;
        if (hepsi)
            durum = "ACIK (derleme tarifi: HEPSI)";
        else if (tip == 1 && !strcmp(ad, "Pack"))
            durum = "ACIK (aile cipasi eslesmesi)";
        else if (tip == 2 && !strcmp(ad, "ImportProtection"))
            durum = "ACIK (aile cipasi eslesmesi)";
        else if (tip < 0)
            durum = "BELIRSIZ (profil eslesmedi)";
        else if (yapisal(ad))
            durum = "KAPALI (boyut kaniti — acik olsa cipa boyutu degisirdi)";
        else if (!strcmp(ad, "StripFixups"))
            durum = s.reloc_yok ? "KESIN (.reloc striplendi)" : "KAPALI/YOK (.reloc mevcut)";
        else
            durum = "AYRISTIRILAMAZ (yapiya etki etmeyen bit)";
        s.ozellikler.push_back({ad, durum});
    }
    // yapisal kanitlar (profilden bagimsiz)
    if (s.text_yok)
        for (auto& kv : s.ozellikler)
            if (kv.first == "Pack") kv.second = "KESIN (.text birlestirildi)";
    if (s.reloc_yok)
        for (auto& kv : s.ozellikler)
            if (kv.first == "StripFixups") kv.second = "KESIN (.reloc striplendi)";
}

static void ozellik_cikar_katmanli(Sonuc& s, PE& p) {
    (void)p;
    s.ozellikler.push_back({"AnalizModu", "COKLU KATMAN — ozellik cikimi katman bazinda guvenilmez"});
    s.ozellikler.push_back({"Pack", s.text_yok ? "KESIN (.text birlestirildi)" : "KAPALI/yok"});
    s.ozellikler.push_back({"StripFixups", s.reloc_yok ? "KESIN (.reloc striplendi)" : "KAPALI/yok"});
    s.ozellikler.push_back({"ImportProtection", s.import_dll <= 1 ? "OLASI (imports sarili)" : "YOK"});
}

// ---------------------------------------------------------------- analiz (v5: aile + cipa + mesafe)
static void analiz(const char* yol, Sonuc& s) {
    PE p;
    if (!pe_ac(yol, p)) { s.tespit_notu = p.hata; s.olumsuz_karar = true; return; }
    s.dosya_boyut = p.veri.size();
    s.makine = (p.makine == 0x8664) ? "x64" : (p.makine == 0x14c) ? "x86" : "?";
    s.aile = aile_bul(p);
    s.aile_ad = s.aile >= 0 ? vmpdb::AILE_TARIF[s.aile] : "bilinmeyen girdi ailesi";
    s.import_dll = p.importlar.size();
    s.export_sayi = p.export_adlar.size();
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
    for (auto& kv : ad_sayaci)
        if (kv.second > 1 && kv.first.rfind(".vmp", 0) == 0) {
            s.katman.cift_vmp_ad = true;
            s.katmanli = true;
        }
    bool vmp_str = dosyada_ara(p.veri, "VMProtect", 1 << 20);
    bool vmp_bayrak = false;
    for (auto* b : korp) {
        uint32_t oz = b->oz;
        if ((oz & 0x20000000) && (oz & 0x40000000) &&
            ((oz & 0x02000000) || (oz & 0x08000000)))
            vmp_bayrak = true;
    }

    // ---- [P] GERCEK UPX ayrimi
    if (s.upx_kamuflaj && pt.upx_gercek) {
        s.olumsuz_karar = true;
        s.paketleyici = "UPX";
        s.tespit_notu = "UPX! sihri + UPX bolumleri — GERCEK UPX, VMProtect degil";
        s.katman.notlar.push_back("UPX altinda gizli ic katman olabilir — runtime analizi: --live");
        for (auto* b : korp)
            if (upx_bolum_ad_mi(b->ad) && b->vsz > 0x10000)
                s.katman.notlar.push_back("UPX0 genis — ic katman gizli (runtime analizi onerilir: --live)");
        return;
    }

    // ---- VMP karari
    bool yapisal_vmp = vmp_bayrak;
    if (vmp_ad) { s.vmp_tespit = true; s.tespit_notu = ".vmp bolum(leri)"; }
    else if (vmp_str && !pt.vurus) { s.vmp_tespit = true; s.tespit_notu = "VMProtect dizgisi + koruyucu bolum"; }
    else if (yapisal_vmp && !pt.vurus) { s.vmp_tespit = true; s.tespit_notu = "koruyucu bolum bayrak deseni (0x68000060 tipi)"; }

    if (!s.vmp_tespit) {
        s.olumsuz_karar = true;
        if (s.upx_kamuflaj && !pt.upx_gercek) {
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

    // ---- cift katman: bolum-bazli surum atfi (PROFIL5 tek-bolum cipasi)
    if (s.katman.cift_vmp_ad) {
        for (size_t i = 0; i < s.kor.size(); i++) {
            std::set<int> capa;
            for (int pi = 0; pi < vmpdb::PROFIL5_SAYI; pi++) {
                const auto& pr = vmpdb::PROFIL5[pi];
                if (pr.bolum_sayi == 1 && pr.raw[0] == s.kor[i].raw &&
                    pr.vsz[0] == s.kor[i].vsz && s.kor[i].raw > 0)
                    capa.insert(pr.surum);
            }
            std::string surum_str = "?", kaynak = "";
            if (capa.size() == 1) {
                surum_str = vmpdb::SURUM[*capa.begin()];
                kaynak = "cipa (tek-bolum boyut imzasi)";
            } else if (capa.size() == 2 && esitlik_uyesi(2) && esitlik_uyesi(8) &&
                       capa.count(2) && capa.count(8)) {
                surum_str = "{Professional 3.8.1; Ultimate 3.8.4} (3.8.x esitlik)";
                kaynak = "cipa coklu-aday";
            } else if (capa.size() > 1) {
                surum_str = "{";
                for (int sv : capa) surum_str += std::string(vmpdb::SURUM[sv]) + "; ";
                surum_str += "}";
                kaynak = "cipa coklu-aday";
            } else {
                surum_str = "bilinmeyen (runtime onerilir: --live)";
                kaynak = "cipa eslesmedi";
            }
            char bnum[48];
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

    // ---- aile kapisi
    if (s.aile < 0) {
        // bilinmeyen girdi ailesi (4 korpus ailesi disindan bir girdi)
        if (capa2_dene(s)) { s.sinif_ad = SINIF_ADLARI[s.sinif]; return; }
        s.sinif_ad = SINIF_ADLARI[s.sinif];
        s.guven = "GIRDI AILESI KORPUS DISI — 32/64-bit exe+dll aileleri disindan girdi";
        s.katman_karar = "yapisal tespit (VMP: EVET); kesin surum atfi icin girdi-ailesi korpusu gerekir";
        s.ozellikler.push_back({"AnalizModu", "AILE DISI GIRDI — surum cipasi uygulanamaz"});
        ozellik_cikar(s, -1);
        return;
    }

    // ---- K2: aile cipasi (tam eslesme)
    std::vector<std::pair<int,int>> uyan;   // (surum, tip)
    for (int pi = 0; pi < vmpdb::PROFIL5_SAYI; pi++) {
        const auto& pr = vmpdb::PROFIL5[pi];
        if (pr.aile != s.aile || pr.bolum_sayi != (int)s.kor.size()) continue;
        bool ok = true;
        for (size_t j = 0; j < s.kor.size() && j < 3; j++)
            if (pr.raw[j] != s.kor[j].raw || pr.vsz[j] != s.kor[j].vsz) { ok = false; break; }
        if (ok) uyan.push_back({pr.surum, pr.tip});
    }
    std::vector<int> svler;
    for (auto& u : uyan)
        if (std::find(svler.begin(), svler.end(), u.first) == svler.end())
            svler.push_back(u.first);
    if (svler.size() == 1) {
        int sv = svler[0];
        int tip = uyan[0].second;
        s.adaylar.push_back({sv, 0});
        s.guven = "YUKSEK (aile cipasi birebir)";
        s.katman_karar = "K2: DORT-AILE korpus cipasi (tam eslesme)";
        s.esitlenen_profil = vmpdb::TIP_AD[tip];
        s.sinif_ad = SINIF_ADLARI[s.sinif];
        ozellik_cikar(s, tip);
        return;
    }
    if (svler.size() == 2) {
        // savunmaci: {2,8} esitligi — yalniz fn0 tipinde fiziksel
        bool hepsi_fn0 = true;
        for (auto& u : uyan) if (u.second != 0) { hepsi_fn0 = false; break; }
        bool cift_esitlik = (std::find(svler.begin(), svler.end(), 2) != svler.end() &&
                             std::find(svler.begin(), svler.end(), 8) != svler.end());
        if (cift_esitlik && hepsi_fn0) {
            for (int i = 0; i < vmpdb::ESDEGER_SAYI; i++)
                s.adaylar.push_back({vmpdb::ESDEGER_UYE[i], 0});
            s.esitlik_sinifi = true;
            s.guven = "KESIN ESITLIK (yalniz saf-wrapper fn0 yapisinda — bayt-ozdest)";
            s.sinif_ad = "PURE";
            s.katman_karar = "K2: fn0 cipasi + 3.8.x esitlik sinifi";
            s.esitlenen_profil = "fn0 (seçeneksiz saf wrapper)";
            ozellik_cikar(s, 0);
            return;
        }
        if (cift_esitlik) {
            // fn0-disi cip cakismasi (teori disi): her ikisini de raporla
            for (int sv : svler) s.adaylar.push_back({sv, 0});
            s.guven = "CIFT-ADAY (cip cakismasi — 3.8.x motorlari)";
            s.katman_karar = "K2: cipa cift-eslesme";
            ozellik_cikar(s, -1);
            return;
        }
        // baska surum cifti: mesafe asamasina dus
    }

    // ---- K4': profil mesafesi (ayni aile, ayni bolum sayisi)
    s.sinif_ad = SINIF_ADLARI[s.sinif];
    std::map<int, uint64_t> skor;
    std::map<int, uint64_t> skor_boy;
    std::map<int, int> skor_tip;
    for (int pi = 0; pi < vmpdb::PROFIL5_SAYI; pi++) {
        const auto& pr = vmpdb::PROFIL5[pi];
        if (pr.aile != s.aile || pr.bolum_sayi != (int)s.kor.size()) continue;
        uint64_t d = 0, tb = 0;
        for (size_t j = 0; j < s.kor.size() && j < 3; j++) {
            d += (uint64_t)llabs((long long)s.kor[j].raw - (long long)pr.raw[j]);
            d += (uint64_t)llabs((long long)s.kor[j].vsz - (long long)pr.vsz[j]);
            tb += pr.raw[j];
        }
        auto it = skor.find(pr.surum);
        if (it == skor.end() || d < it->second) {
            skor[pr.surum] = d;
            skor_boy[pr.surum] = tb;
            skor_tip[pr.surum] = pr.tip;
        }
    }
    if (skor.empty()) {
        // aile icinde bu bolum sayisina profil yok → katman/karma yapi
        if (capa2_dene(s)) return;
        s.guven = "OZEL VARYANT (aile icinde tanimli profil yapisi yok)";
        s.ozel_varyant = true;
        s.katman_karar = "K4: uyumlu profil yok (bolum sayisi bilinmiyor)";
        ozellik_cikar(s, -1);
        return;
    }
    std::vector<std::pair<uint64_t,int>> sirali;
    for (auto& kv : skor) sirali.push_back({kv.second, kv.first});
    std::sort(sirali.begin(), sirali.end());
    uint64_t profil_boy = skor_boy[sirali[0].second];
    uint64_t marj = profil_boy / 32;               // ~%3 goreli marj
    if (marj < 256) marj = 256;
    s.adaylar.push_back({sirali[0].second, sirali[0].first});
    for (size_t i = 1; i < sirali.size(); i++) {
        if (sirali[i].first - sirali[0].first <= marj)
            s.adaylar.push_back({sirali[i].second, sirali[i].first});
        else break;
    }
    // esitlik: yalniz fn0-tipi en iyi profilse
    if (s.adaylar.size() == (size_t)vmpdb::ESDEGER_SAYI) {
        bool hepsi_esitlik = true;
        for (auto& a : s.adaylar)
            if (!esitlik_uyesi(a.surum)) { hepsi_esitlik = false; break; }
        if (hepsi_esitlik && skor_tip[sirali[0].second] == 0) {
            s.esitlik_sinifi = true;
            s.guven = "KESIN ESITLIK (fn0 yakin profil — 3.8.x motor sinifi)";
            s.katman_karar = "K4+esitlik: fn0 yakin profil, 3.8.x motor sinifi";
            s.esitlenen_profil = "fn0 (seceneksiz saf wrapper)";
            ozellik_cikar(s, 0);
            return;
        }
    }
    int en_iyi_tip = skor_tip[sirali[0].second];
    s.esitlenen_profil = std::string(vmpdb::TIP_AD[en_iyi_tip]) + " (yakin profil)";
    s.katman_karar = "K4: aile-içi profil mesafesi (goreli marj)";
    s.guven = s.adaylar.size() > 1 ? "CIFT-ADAY (yakin profil)"
                                    : (sirali[0].first < 4096 ? "ORTA-YUKSEK (yakin profil)"
                                                              : "DUSUK (uzak profil — MODLANMIS olabilir)");
    if (sirali[0].first > profil_boy / 4) s.ozel_varyant = true;
    ozellik_cikar(s, en_iyi_tip);
}

// capa2: hello ailesi (v4 runtime demo'lari ile uyumluluk)
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
                    s.katman_karar = std::string("CAPA2: ") + aile.ad + " surum cipi";
                    s.esitlenen_profil = "wrapper (aile capa2)";
                    ozellik_cikar(s, -1);
                    return true;
                }
            }
        }
    }
    return false;
}

// ---------------------------------------------------------------- dump duzeltici
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
    printf("  [1/9] DOS/NT header dogrulama            : %sTAMAM%s (PE32%s, %u bolum)\n",
           R(YESIL), R(SIFIRLA), p.opt_sihir == 0x20B ? "+" : "", p.bolum_sayisi);
    printf("  [2/9] Tercih edilen ImageBase            : 0x%llX %s\n",
           (unsigned long long)p.resim_taban,
           (p.dll_oz & 0x40) ? R("(ASLR: DYNAMIC_BASE — taban kayabilir)") : R("(sabit)"));
    printf("  [3/9] Header kopyalama (SizeOfHeaders)   : tamam\n");
    printf("  [4/9] Bolum esleme (raw -> virtual)      : %zu bolum\n", p.bolumler.size());
    printf("  [5/9] Base relocation                    : ");
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
                        // PE32: HIGHLOW(0x3) / PE32+: DIR64(0xA) — 32/64-bit destegi
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
    printf("  [6/9] Import cozumu                      : %zu DLL", p.importlar.size());
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
    // v5: [7/9] export cozumu (DLL hedefleri)
    printf("  [7/9] Export cozumu (DLL/EXE)            : ");
    if (p.export_adlar.empty()) printf("yok\n");
    else {
        printf("%zu fonksiyon — %s (", p.export_adlar.size(),
               p.export_dll_adi.c_str());
        for (size_t i = 0; i < p.export_adlar.size() && i < 8; i++)
            printf("%s%s", i ? ", " : "", p.export_adlar[i].c_str());
        printf("%s)\n", p.export_adlar.size() > 8 ? ", ..." : "");
        printf("        DLL yukleme                       : LoadLibrary tarzi host gerekir (--live DLL host: rundll32)\n");
    }
    printf("  [8/9] Mapped ImageBase guncellemesi      : 0x%llX\n",
           (unsigned long long)p.resim_taban);
    printf("  [9/9] Bolum korumalari                   :\n");
    for (auto& b : p.bolumler) {
        const char* k = "PAGE_READONLY";
        if ((b.oz & 0x20000000) && (b.oz & 0x80000000)) k = "PAGE_EXECUTE_READWRITE";
        else if ((b.oz & 0x20000000) && (b.oz & 0x40000000)) k = "PAGE_EXECUTE_READ";
        else if (b.oz & 0x80000000) k = "PAGE_READWRITE";
        bool kor = !standart_ad(b.ad);
        printf("        %-10s VA=0x%06X boyut=0x%-6X %s%s%s\n",
               b.ad.c_str(), b.va, b.vsz ? b.vsz : b.rsz, k,
               kor ? R("  ← KORUYUCU BOLUMU") : "", kor ? R(SIFIRLA) : "");
    }
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

// bellek dokumunden ic katman PE basliklarini geri kazan
static void ic_katman_geri_kazan(const std::vector<uint8_t>& v) {
    struct Bulgu { size_t ofset; std::vector<std::pair<std::string,uint32_t>> bolumler; };
    std::vector<Bulgu> bulgular;
    for (size_t i = 0x200; i + 4 < v.size(); i += 4) {
        if (memcmp(&v[i], "PE\0\0", 4) != 0) continue;
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
    printf("  %sIC KATMAN GERI KAZANIMI (bellekte gomulu PE basliklari):%s\n",
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
                                   R(YESIL), aile.ad, R(SIFIRLA));
                        else
                            printf("      %s-> IC KATMAN SURUM: %s (capa2 %s)%s\n",
                                   R(YESIL), vmpdb::SURUM[sv], aile.ad, R(SIFIRLA));
                        break;
                    }
            }
        }
    }
}

// ---------------------------------------------------------------- [R] --live: canli surec dokumu
// v5: DLL hedefi mi? (IMAGE_FILE_DLL) — rundll32 host ile yuklenmeli
static bool dll_mi(const char* yol) {
    FILE* f = fopen(yol, "rb");
    if (!f) return false;
    uint8_t h[0x200] = {};
    size_t ok = fread(h, 1, sizeof h, f);
    fclose(f);
    if (ok < 0x200 || h[0] != 'M' || h[1] != 'Z') return false;
    uint32_t e = 0;
    memcpy(&e, &h[0x3C], 4);
    if (e + 24 > sizeof h) return false;
    uint16_t c = 0;
    memcpy(&c, &h[e + 22], 2);
    return (c & 0x2000) != 0;
}

// hedef PE makine tipi (0x14C/0x8664) — DLL host arch eşlemesi için
static uint16_t hedef_makine(const char* yol) {
    FILE* f = fopen(yol, "rb");
    if (!f) return 0;
    uint8_t h[0x200] = {};
    size_t ok = fread(h, 1, sizeof h, f);
    fclose(f);
    if (ok < 0x200 || h[0] != 'M' || h[1] != 'Z') return 0;
    uint32_t e = 0;
    memcpy(&e, &h[0x3C], 4);
    if (e + 24 > sizeof h) return 0;
    uint16_t m = 0;
    memcpy(&m, &h[e + 4], 2);
    return m;
}

// gömülü host'u (arch eşleşen) dosyaya yaz; dönüş: yazılan yol
static const char* host_yaz(const char* dll_yol) {
    static char yol[512];
    bool x64 = hedef_makine(dll_yol) != 0x14C;
    const unsigned char* veri = x64 ? HOST_X64 : HOST_X86;
    unsigned boy = x64 ? HOST_X64_BOY : HOST_X86_BOY;
#ifdef _WIN32
    char tmpd[300] = ".";
    GetTempPathA(300, tmpd);
    snprintf(yol, sizeof yol, "%svmpdet_host_%s.exe", tmpd, x64 ? "x64" : "x86");
#else
    snprintf(yol, sizeof yol, "/tmp/vmpdet_host_%s.exe", x64 ? "x64" : "x86");
#endif
    FILE* f = fopen(yol, "wb");
    if (!f) return nullptr;
    fwrite(veri, 1, boy, f);
    fclose(f);
    return yol;
}

#ifndef _WIN32
static int g_stdin_boru[2] = {-1, -1};   // çocuk stdin'i açık tutulur (EOF ile ölmesin)

static pid_t canli_baslat(const char* yol, const char* wine_komut) {
    if (g_stdin_boru[0] < 0) pipe(g_stdin_boru);
    pid_t pid = fork();
    if (pid == 0) {
        setpgid(0, 0);
        if (g_stdin_boru[0] >= 0) {
            dup2(g_stdin_boru[0], 0);       // okuma sonsuz bloke — süreç yaşar
            close(g_stdin_boru[1]);
        }
        int devnull = open("/dev/null", 1);
        if (devnull >= 0) { dup2(devnull, 1); }
        if (dll_mi(yol)) {
            // v5: DLL hedefi — gömülü host (LoadLibrary+Sleep), Z: yolları
            const char* host = host_yaz(yol);
            if (!host) _exit(126);
            std::string wd(yol);
            for (auto& ch : wd) if (ch == '/') ch = '\\';
            std::string dll_z = std::string("Z:") + wd;   // LoadLibraryA windows yolu ister
            execlp(wine_komut, wine_komut, host, dll_z.c_str(), (char*)nullptr);
        } else {
            execlp(wine_komut, wine_komut, yol, (char*)nullptr);
        }
        _exit(127);
    }
    return pid;
}
static bool canli_bul(const char* yol, pid_t oncelikli, pid_t& bul, unsigned long& taban, unsigned long& boy) {
    char hedef[512];
    snprintf(hedef, sizeof hedef, "%s", yol);
    const char* taban_ad = strrchr(hedef, '/');
    taban_ad = taban_ad ? taban_ad + 1 : hedef;
    for (int tur = 0; tur < 60; tur++) {
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
                    bul = pid; taban = en_dusuk; boy = en_yuksek - en_dusuk;
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
    // Windows: CreateProcess + ReadProcessMemory (DLL: rundll32 host)
    bool dll_hedef = dll_mi(yol);
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    wchar_t wcmd[1024];
    if (dll_hedef) {
        const char* host = host_yaz(yol);
        if (!host) {
            printf("  %s[HATA]%s host exe yazilamadi\n", R(KIRMIZI), R(SIFIRLA));
            return;
        }
        char cmd[1024];
        snprintf(cmd, sizeof cmd, "\"%s\" \"%s\"", host, yol);
        MultiByteToWideChar(CP_UTF8, 0, cmd, -1, wcmd, 1024);
        if (!CreateProcessW(nullptr, wcmd, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
            printf("  %s[HATA]%s DLL host baslatilamadi (%lu)\n", R(KIRMIZI), R(SIFIRLA), GetLastError());
            return;
        }
        printf("  DLL hedefi — gömülü host (LoadLibrary+Sleep) ile yukleniyor [%s]...\n",
               hedef_makine(yol) == 0x14C ? "x86" : "x64");
    } else {
        wchar_t wyol[1024];
        MultiByteToWideChar(CP_UTF8, 0, yol, -1, wyol, 1024);
        if (!CreateProcessW(wyol, nullptr, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
            printf("  %s[HATA]%s surec baslatilamadi (%lu)\n", R(KIRMIZI), R(SIFIRLA), GetLastError());
            return;
        }
    }
    Sleep(bekle_ms);
    HMODULE mods[256]; DWORD gerekli = 0;
    char dump_hedef[512];
    snprintf(dump_hedef, sizeof dump_hedef, "%s", dump_yolu ? dump_yolu : "vmpdump_live.bin");
    HANDLE hP = pi.hProcess;
    if (EnumProcessModules(hP, mods, sizeof(mods), &gerekli)) {
        int n = (int)(gerekli / sizeof(HMODULE));
        HMODULE hedef_mod = nullptr;
        MODULEINFO mi = {};
        if (dll_hedef) {
            // hedef DLL modulunu bul (host surecinde yuklu)
            char mod_ad[MAX_PATH];
            const char* taban_ad = strrchr(yol, '\\') ? strrchr(yol, '\\') + 1 : yol;
            for (int i = 0; i < n; i++) {
                mod_ad[0] = 0;
                GetModuleFileNameExA(hP, mods[i], mod_ad, MAX_PATH);
                if (strstr(mod_ad, taban_ad)) { hedef_mod = mods[i]; break; }
            }
        } else hedef_mod = mods[0];
        if (hedef_mod && GetModuleInformation(hP, hedef_mod, &mi, sizeof(mi)) && mi.lpBaseOfDll && mi.SizeOfImage) {
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
    // Linux: wine + /proc/pid/mem (DLL: rundll32 host otomatik)
    const char* wine_komut = getenv("VMPDET_WINE");
    if (!wine_komut || !wine_komut[0]) wine_komut = "wine";
    if (dll_mi(yol))
        printf("  DLL hedefi — gömülü host (LoadLibrary+Sleep) ile yukleniyor (wine)...\n");
    pid_t cocuk = canli_baslat(yol, wine_komut);
    if (cocuk < 0) { printf("  %s[HATA]%s fork basarisiz\n", R(KIRMIZI), R(SIFIRLA)); return; }
    printf("  surec baslatildi (pid=%d, wine=%s), %d ms bekleniyor...\n", cocuk, wine_komut, bekle_ms);
    pid_t hedef = 0; unsigned long taban = 0, boy = 0;
    if (!canli_bul(yol, cocuk, hedef, taban, boy)) {
        printf("  %s[HATA]%s hedef surec bellek haritasi bulunamadi (dosya yuklendi mi?)\n",
               R(KIRMIZI), R(SIFIRLA));
        kill(-cocuk, SIGKILL); kill(cocuk, SIGKILL);
        return;
    }
    printf("  hedef bulundu: pid=%d taban=0x%lX boy=0x%lX\n", hedef, taban, boy);
    fflush(stdout);
    char memp[64];
    snprintf(memp, sizeof memp, "/proc/%d/mem", hedef);
    FILE* m = fopen(memp, "rb");
    usleep(bekle_ms * 1000);
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
    analiz(dump_yolu, s2);
    printf("\n  %s[RUNTIME SONUC — dump yeniden analiz]%s\n", R("\x1b[96m\x1b[1m"), R(SIFIRLA));
    bool upx_acilmis = false;
    {
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
               "calisma aninda VMProtect korumasi gorunmuyor");
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
    cizgi(" VMDETECT v5 // GOD SSS TIER // TARGET ACQUISITION ");
    printf("%s  TARGET   :%s %s%s%s\n", R(SARI), R(SIFIRLA), R("\x1b[97m\x1b[1m"), yol, R(SIFIRLA));
    printf("%s  SIZE     :%s %zu bytes\n", R(SARI), R(SIFIRLA), s.dosya_boyut);
    printf("%s  ARCH     :%s %s%s%s\n", R(SARI), R(SIFIRLA),
           R(BEYAZ), s.makine.c_str(), R(SIFIRLA));
    printf("%s  FAMILY   :%s %s%s%s%s\n", R(SARI), R(SIFIRLA),
           s.aile >= 0 ? R("\x1b[92m\x1b[1m") : R(SARI),
           s.aile >= 0 ? vmpdb::AILE_AD[s.aile] : "?",
           s.aile >= 0 ? "" : "", R(SIFIRLA));
    printf("%s  DESC     :%s %s\n", R(SARI), R(SIFIRLA), s.aile_ad.c_str());
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
    printf("%s  Imports            :%s %s%zu DLL%s\n", R(SARI), R(SIFIRLA),
           R(BEYAZ), s.import_dll, R(SIFIRLA));
    if (s.export_sayi)
        printf("%s  Exports            :%s %s%zu fonksiyon%s (DLL hedefi — koruma sarmasi)\n",
               R(SARI), R(SIFIRLA), R(BEYAZ), s.export_sayi, R(SIFIRLA));
    printf("%s  .reloc             :%s %s%s%s\n", R(SARI), R(SIFIRLA), R(BEYAZ),
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
        printf("  %s[ESITLIK SINIFI — yalniz fn0 yapisinda]%s  %sProfessional 3.8.1  %s||%s  %sUltimate 3.8.4%s\n",
               R("\x1b[93m\x1b[1m"), R(SIFIRLA), R("\x1b[97m\x1b[1m"),
               R("\x1b[93m\x1b[1m"), R(SIFIRLA), R("\x1b[97m\x1b[1m"), R(SIFIRLA));
        printf("  %sSECENEKSIZ saf-wrapper (fn0) ciktilarinda iki motor bayt-ozdestrir.%s\n",
               R(SARI), R(SIFIRLA));
        printf("  %sPack / fonksiyon-koruma / HEPSI yapilarinda AYRIŞIRLAR (cipa kaniti).%s\n",
               R(GRAY), R(SIFIRLA));
        printf("  %sBu dosya fn0 yapisinda → kesin ayristirma fiziksel olarak imkansiz.%s\n",
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
                            kv.second.find("OLASI") != std::string::npos ||
                            kv.second.find("AYRISTIRILAMAZ") != std::string::npos;
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
    printf("Arch: %s | Family: %s\n", s.makine.c_str(),
           s.aile >= 0 ? vmpdb::AILE_AD[s.aile] : "?");
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
            printf("Version (equivalence): Professional 3.8.1 / Ultimate 3.8.4 [fn0 saf-wrapper esitlik sinifi]\n");
            printf("Guven: %s\n", s.guven.c_str());
        } else {
            printf("Version (best match): %s [%s] dist=%llu guven=%s\n",
                   vmpdb::SURUM[s.adaylar[0].surum], vmpdb::EDISYON[s.adaylar[0].surum],
                   (unsigned long long)s.adaylar[0].dist, s.guven.c_str());
            for (size_t i = 1; i < s.adaylar.size(); i++)
                printf("  alt aday: %s dist=%llu\n", vmpdb::SURUM[s.adaylar[i].surum],
                       (unsigned long long)s.adaylar[i].dist);
        }
        if (s.ozel_varyant) printf("OZEL VARYANT: bilinmeyen VMProtect yapisi (modlanmis motor olabilir)\n");
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
    fprintf(out, "    \"arch\": \"%s\",\n", s.makine.c_str());
    fprintf(out, "    \"aile\": \"%s\",\n", s.aile >= 0 ? vmpdb::AILE_AD[s.aile] : "?");
    fprintf(out, "    \"kanit\": \"");
    json_kacis(out, s.tespit_notu.c_str());
    fprintf(out, "\",\n");
    if (!s.vmp_tespit) {
        fprintf(out, "    \"olumsuz_karar\": true,\n    \"paketleyici\": \"");
        json_kacis(out, s.paketleyici.c_str());
        fprintf(out, "\"\n");
    }
    if (s.vmp_tespit && !s.adaylar.empty()) {
        if (s.esitlik_sinifi) {
            fprintf(out, "    \"surum\": \"Professional 3.8.1 / Ultimate 3.8.4\",\n");
            fprintf(out, "    \"esitlik_sinifi\": true,\n");
            fprintf(out, "    \"esitlik_kapsami\": \"yalniz fn0 (seceneksiz saf-wrapper)\",\n");
        } else {
            fprintf(out, "    \"surum\": \"%s\",\n    \"edition\": \"%s\",\n",
                    vmpdb::SURUM[s.adaylar[0].surum], vmpdb::EDISYON[s.adaylar[0].surum]);
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
static void dizin_hedef_ekle(const std::string& dzn, std::vector<std::string>& out) {
    DIR* d = opendir(dzn.c_str());
    if (!d) return;
    struct dirent* e;
    while ((e = readdir(d))) {
        std::string f = e->d_name;
        if (f.size() > 4) {
            std::string uz = kucuk(f.substr(f.size() - 4));
            if (uz == ".exe" || uz == ".dll")
                out.push_back(dzn + (dzn.back() == '/' ? "" : "/") + f);
        }
    }
    closedir(d);
}
#else
static void dizin_hedef_ekle(const std::string& dzn, std::vector<std::string>& out) {
    try {
        for (auto& e : fs::directory_iterator(dzn)) {
            std::string f = e.path().filename().string();
            if (f.size() > 4) {
                std::string uz = kucuk(f.substr(f.size() - 4));
                if (uz == ".exe" || uz == ".dll")
                    out.push_back(e.path().string());
            }
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
        else if (a == "--dir" && i + 1 < argc) dizin_hedef_ekle(argv[++i], hedefler);
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
        printf("VMDETECT v5 — GOD SSS TIER VMProtect surum & ozellik & KATMAN dedektoru\n"
               "DORT AILE korpusu: 32-bit EXE / 32-bit DLL / 64-bit EXE / 64-bit DLL (10 surum)\n"
               "  [A] aile kapisi (i386/AMD64 + DLL bayragi) → K2 aile cipasi (birebir) → K4' mesafe\n"
               "  [E] esitlik sinifi YALNIZ fn0 (saf wrapper): Pro 3.8.1 ∥ Ult 3.8.4; Pack/Move AYRIŞIR\n"
               "  [P] UPX/Themida/Enigma/... imzalari — 'VMProtect DEGIL' kesin olumsuz karari\n"
               "  [C] bolum-adi-degistirildi + OZEL VARYANT (modlanmis motor) tespiti\n"
               "  [L] cok katman (cift .vmp bolumu, UPX dis katman)\n"
               "  [R] --sim loader emulasyonu (kod CALISTIRMAZ) / --live canli surec dump (DLL: rundll32 host)\n\n"
               "Kullanim:\n"
               "  %s <dosya>          tek hedef (askeri TUI) — exe VEYA dll, 32/64-bit\n"
               "  %s --dir <klasor>   batch tarama (.exe + .dll)\n"
               "  %s --json o.json --dir <klasor>\n"
               "  %s --sim <dosya> [--dump cikis.bin]\n"
               "  %s --live <dosya> [--wait 4000] [--dump cikis.bin]\n",
               argv[0], argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }
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
        printf("\nOZET: %zu hedef | %d VMProtect | %d NEGATIF (VMP degil) | %d esitlik sinifi (fn0 3.8.x) | %d cok katmanli\n",
               hedefler.size(), vmp_sayi, olumsuz_sayi, esitlik_sayi, katman_sayi);
    return 0;
}

