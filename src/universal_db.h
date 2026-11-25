// ============================================================================
// universal_db.h — UNIVERSAL PACKER/PROTECTOR IMZA VERITABANI v6
// ============================================================================
// KAYNAK KODDAN BESLENEN deterministik imzalar (26.11.2026 derin arastirma):
//   - Her aile, acik kaynak deposunun KENDI KAYNAGINDAN cikarilan izlerle
//     tanimlanir (bolum adi, sihirli bayt, yapysal kural, EOF cookie).
//   - Kanit seviyeleri:
//       [K1] KAYNAKTAN — ilgili packer'in kendi kaynak kodunda satir kaniti var
//       [K2] GERCEK CIKTI — kaynaktan derlenip paketlenmis gercek ornekten alindi
//       [K3] MIRAS — kapali kaynak aileler; kamuya acik detektor mirasi (DIE/PEiD)
//            sozlukleriyle capraz dogrulanmis bolum/dizgi izleri
//   - SAHTE IMZA DEMETI kurali: obfus.h / obfusheader.h / yap gibi araclar
//     BASKA protector'lerin bolum adlarini sahte olarak enjekte eder
//     (kaynak: obfus.h include/obfus.h:329-402 "FAKE_SIGNATURES").
//     Farkli ureticilerin >=2 bolum adi ayni dosyada gorunurse bu DEMET
//     raporlanir, tek tek aile raporlanmaz.
// ============================================================================
#pragma once
#include <cstdint>

namespace universaldb {

// ------------------------------------------------------------------ kisaltmalar
// Bolge kodlari (bayt dizgisi imzalarinin NEREDE gecerli sayilacagi):
//   R_BASLIK : dosya basi 0..4KB (PE baslik damgasi alani)
//   R_KORU   : standart-disi (koruyucu) bolumlerin ham verisi
//   R_KUYRUK : dosya sonu 8KB (overlay / SFX / cookie)
//   R_TUM    : tum dosya (sadece guclu sihirli baytlar)
enum Bolge { R_YOK = 0, R_BASLIK = 1, R_KORU = 2, R_KUYRUK = 4, R_TUM = 7 };

struct BaytImza {
    const char* dizgi;     // 0-sonlandirmali (\\x kacli olarak on-islenmis degil, cagrıci halleder)
    uint8_t bolge;         // Bolge bitleri
    const char* not_;      // kanit / kaynak notu
};

// ---------------------------------------------------------------------------
// v7 GUVENLIK — OZ-REFERANS KALKANI
// R_TUM imza dizgileri ve TinyLoad anahtar blogu KARISTIRILMIS bayt dizileri
// olarak gomulur: dedektorun kendi binary'sinde bu bayt dizileri ACIK sekilde
// yer almaz (kaynakta da yok — Python on-hesaplamasiyla uretilmislerdir).
// (v6'da bulunan kusur: vmpdet kendi binary'sini 'TinyLoad/Enigma' saniyordu —
//  imza sabitleri .rodata'da durdugu icin tarama KENDI imzalarina carpiyordu.)
// karistirma: cozulmus[i] = karisik[i] ^ ((0x5A + 7*i) & 0xFF)
// ---------------------------------------------------------------------------
constexpr uint8_t sakli_anahtar(size_t i) { return (uint8_t)(0x5A + i * 7); }

struct SakliDizi {
    const uint8_t* b;
    size_t boy;
};
// "Enigma protector v" (18 bayt) karistirilmis:
static const uint8_t SKB_FAKE_ENIGMA[] = {
    0x1F, 0x0F, 0x01, 0x08, 0x1B, 0x1C, 0xA4, 0xFB, 0xE0, 0xF6, 0xD4, 0xC2,
    0xCD, 0xC1, 0xD3, 0xB1, 0xEA, 0xA7 };
// "denuvo_atd" (10 bayt) karistirilmis:
static const uint8_t SKB_FAKE_DENUVO[] = {
    0x3E, 0x04, 0x06, 0x1A, 0x00, 0x12, 0xDB, 0xEA, 0xE6, 0xFD };
// "NUITKA_ONEFILE_PARENT" (21 bayt) karistirilmis:
static const uint8_t SKB_FAKE_NUITKA[] = {
    0x14, 0x34, 0x21, 0x3B, 0x3D, 0x3C, 0xDB, 0xC4, 0xDC, 0xDC, 0xE6, 0xEE,
    0xE2, 0xF0, 0xE3, 0x93, 0x8B, 0x83, 0x9D, 0x91, 0xB2 };
// "Video created by SCREEN2EXE/SCREEN2SWF" (38 bayt) karistirilmis:
static const uint8_t SKB_FAKE_SCREEN2EXE[] = {
    0x0C, 0x08, 0x0C, 0x0A, 0x19, 0x5D, 0xE7, 0xF9, 0xF7, 0xF8, 0xD4, 0xC2,
    0xCA, 0x95, 0xDE, 0xBA, 0xEA, 0x82, 0x9B, 0x8D, 0xA3, 0xA8, 0xBA, 0xC9,
    0x47, 0x51, 0x55, 0x38, 0x4D, 0x66, 0x7E, 0x76, 0x7F, 0x0F, 0x7A, 0x1C,
    0x01, 0x1B };
// "The Enigma Protector" (20 bayt) karistirilmis:
static const uint8_t SKB_ENIGMA_TAM[] = {
    0x0E, 0x09, 0x0D, 0x4F, 0x33, 0x13, 0xED, 0xEC, 0xFF, 0xF8, 0x80, 0xF7,
    0xDC, 0xDA, 0xC8, 0xA6, 0xA9, 0xA5, 0xB7, 0xAD };
// TinyLoad .pxkey XXTEA anahtar blogu (24 bayt) karistirilmis:
static const uint8_t SKB_TINYLOAD[] = {
    0x6D, 0x72, 0xB6, 0xAF, 0x7B, 0x8D, 0x69, 0x75, 0x2C, 0x23, 0x5E, 0x6D,
    0x41, 0x0B, 0x11, 0x1D, 0xC7, 0x21, 0x75, 0x54, 0x4B, 0x33, 0xF3, 0x4B };

static const SakliDizi SK_FAKE_ENIGMA  = { SKB_FAKE_ENIGMA,  sizeof(SKB_FAKE_ENIGMA) };
static const SakliDizi SK_FAKE_DENUVO  = { SKB_FAKE_DENUVO,  sizeof(SKB_FAKE_DENUVO) };
static const SakliDizi SK_FAKE_NUITKA  = { SKB_FAKE_NUITKA,  sizeof(SKB_FAKE_NUITKA) };
static const SakliDizi SK_FAKE_SCREEN2EXE = { SKB_FAKE_SCREEN2EXE, sizeof(SKB_FAKE_SCREEN2EXE) };
static const SakliDizi SK_ENIGMA_TAM   = { SKB_ENIGMA_TAM,   sizeof(SKB_ENIGMA_TAM) };
static const SakliDizi SK_TINYLOAD     = { SKB_TINYLOAD,     sizeof(SKB_TINYLOAD) };

// karisik bayt dizisini cozup NUL-sonlandirmali dizgi uretir
inline size_t sakli_coz(const SakliDizi& s, char* cikis, size_t kapasite) {
    size_t n = std::min(s.boy, kapasite - 1);
    for (size_t i = 0; i < n; i++)
        cikis[i] = (char)(s.b[i] ^ sakli_anahtar(i));
    cikis[n] = 0;
    return n;
}
// karisik bayt dizisini cozup ham bayt yazar (TinyLoad anahtar blogu icin)
inline void sakli_coz_bayt(const SakliDizi& s, uint8_t* cikis) {
    for (size_t i = 0; i < s.boy; i++) cikis[i] = (uint8_t)(s.b[i] ^ sakli_anahtar(i));
}

// R_TUM (tam-dosya) imzalari — OZEL LISTE: karistirilmis gomulur, motor S3'te
// cozerek karsilastirir (oz-referans kalkani — detay yukarida)
// NOT: 'Enigma protector v' ve 'The Enigma Protector' BILINCLI olarak bu listede
// DEGIL: PEiD tablo adi 'Enigma protector v1.02 -> ...' bu dizgiyi ICERDIGINDEN
// dedektorun kendi .rodata'si (isim tablosu) kendine vururdu. Enigma ailesi
// bolum adi (.enigma1/.enigma2) + bolge-kisitli 'Enigma protector' dizgisiyle
// (R_BASLIK|R_KORU) tespit edilir — o taramalar isim tablosuna carpamaz.
struct SakliImza { const SakliDizi* dizgi; const char* not_; };
static const SakliImza SAKLI_TABLO[] = {
    { &SK_FAKE_DENUVO,    "K1: obfus.h FAKE_DENUVO .arch bolumu" },
    { &SK_FAKE_NUITKA,    "K1: obfus.h FAKE_NUITKA .rdata" },
    { &SK_FAKE_SCREEN2EXE,"K1: obfus.h FAKE_SCREEN2EXE .text" },
};
static const int SAKLI_TABLO_ADET = sizeof(SAKLI_TABLO) / sizeof(SAKLI_TABLO[0]);

// ---------------------------------------------------------------------------
// BOLUM-ADI IMZA TABLOSU — aile eslesmesi icin
// kurallar:
//   bolumler : eslesme icin aday bolum adlari (kucuk-harf duyarsiz, ILKI eslesirse aile vurur)
//   istenen  : kac bolum eslesmeli (0 = herhangi biri; >0 = en az o kadar)
//   satici   : sahte-imza demeti analizi icin uretici kodu (0 = demet disi)
// ---------------------------------------------------------------------------
struct BolumImza {
    const char* aile;
    const char* kategori;   // compressor / protector / obfuscator / crypter / installer / script / vm
    const char* kanit;      // K1/K2/K3 + kaynak
    const char* bolumler[8];
    int8_t istenen;         // gereken eslesme sayisi
    uint8_t satici;         // uretici kodu (sahte demet analizi)
};

enum : uint8_t {
    V_UPX = 1, V_OREANS = 2, V_ENIGMA = 3, V_ASProtect = 4, V_MPRESS = 5,
    V_VMP = 6, V_DOSX = 7, V_MOLEBOX = 8, V_WIBU = 9, V_OTHER = 250
};

static const BolumImza BOLUM_TABLO[] = {
    // ---- ACIK KAYNAK — kendi deposundan kanitli (K1) ----
    { "UPX", "compressor", "K1: upx src/pefile.cpp:2831-2840 strcpy UPX0/UPX1/UPX2",
      { "UPX0", "UPX1", "UPX2", ".UPX0", ".UPX1", ".UPX2" }, 2, V_UPX },
    { "es3n1n/obfuscator", "obfuscator", "K1: src/lib/util/sections.hpp:12-13 .s_code + .s_rel",
      { ".s_code", ".s_rel", 0 }, 2, V_OTHER },
    { "Ryujin Protector", "protector", "K1: RyujinObfuscationCore.cc:2123 '.Ryujin'",
      { ".Ryujin", 0 }, 1, V_OTHER },
    { "TinyLoad", "packer/vm", "K1: TinyLoad.cpp:255 '.pxkey' + XXTEA anahtar blogu",
      { ".pxkey", 0 }, 1, V_OTHER },
    { "rewolf-x86-virtualizer", "vm", "K1: src/protector/main.cpp:348 memmove '.VM'",
      { ".VM", ".vm", 0 }, 1, V_OTHER },
    { "GreyM", "vm", "K1: Interpreter/src/main.h:4-5 .dick (VM loader) + .dick2 (VM code)",
      { ".dick", ".dick2", 0 }, 1, V_OTHER },
    { "Kryptonite", "crypter", "K1: repo icinde .pcode bolumu (Delphi packer)",
      { ".pcode", 0 }, 1, V_OTHER },
    { "PEunion", "crypter/binder", "K1: SlnBin/Stub FASM stub + .peu kaynak izi",
      { ".peu", 0 }, 1, V_OTHER },
    { "Nocturne", "vm", "K1: bin2bin code virtualizer — .nctrn/.mark/.vmp/.vmpm bolumleri",
      { ".nctrn", ".vmpm", ".mark", 0 }, 1, V_OTHER },   // DIKKAT: .vmp tek basina VMProtect ile karisir
    { "wVmp (mikasaw)", "vm", "K1: .wvmp/.wvmpc bolumleri (arastirma protector)",
      { ".wvmp", ".wvmpc", ".far", 0 }, 1, V_OTHER },
    { "MoleBox (acik surum)", "packer", "K1: sudachen/Molebox — .xor/.xorC/.xorS",
      { ".xor", ".xorc", ".xors", 0 }, 1, V_OTHER },
    { "Nanomites (Fatmike)", "protector", "K1: .nano bolumu",
      { ".nano", 0 }, 1, V_OTHER },
    { "JitDecrypter (Fatmike)", "crypter", "K1: .prot bolumu",
      { ".prot", 0 }, 1, V_OTHER },
    { "Obsidian Protector", "protector", "K1: .nexus bolumu (ARM64+PyInstaller destekli)",
      { ".nexus", 0 }, 1, V_OTHER },
    { "PEP (private exe protector)", "protector", "K1: .pep bolumu (Delphi)",
      { ".pep", 0 }, 1, V_OTHER },
    { "AlushPacker", "packer", "K1: .packed bolumu",
      { ".packed", 0 }, 1, V_OTHER },
    { "NovaProtect", "protector", "K1: .nova/.np_data bolumleri",
      { ".nova", ".np_data", 0 }, 1, V_OTHER },
    { "obfus.h (DosX)", "obfuscator", "K1: include/obfus.h:402 '.obfh' bolumu (fake-signatures kapaliyken)",
      { ".obfh", 0 }, 1, V_DOSX },
    { "BatchToApp (DosX)", "bat-packer", "K1: .cmd bolumu (bat->exe)",
      { ".cmd", 0 }, 1, V_OTHER },
    { "KiteShield", "elf-packer", "K1: .rt_info bolumu (Linux x86-64 ELF)",
      { ".rt_info", 0 }, 1, V_OTHER },
    { "Tencent VM (TVM)", "vm", "K1: jz0/tvm-devirt README — '.tvm0' VM bolumu (dispatcher+handler); NeuroSaki987/tvm-recover '.tvm0' unpack + PE rewrite",
      { ".tvm0", ".tvm1", 0 }, 1, V_OTHER },
    { "zhidun (Android)", "apk-protector", "K1: .setting bolumu (DEX sifreleme)",
      { ".setting", 0 }, 1, V_OTHER },
    { "MoleBox (miras surum)", "packer", "K3: Molebox klasik bolumleri",
      { ".molebox", "molebox", 0 }, 1, V_OTHER },

    // ---- MIRAS / TICARI (K3) — DIE/PEiD sozluguyle capraz dogrulanmis ----
    { "Themida / WinLicense (Oreans)", "protector", "K3",
      { ".themida", ".boom", ".taz", ".tsuarch", ".tsustub", ".winlice", ".themidac", 0 }, 1, V_OREANS },
    { "Code Virtualizer (Oreans)", "vm", "K3",
      { ".vlizer", 0 }, 1, V_OREANS },
    { "Enigma Protector", "protector", "K3",
      { ".enigma1", ".enigma2", ".enigmap", 0 }, 1, V_ENIGMA },
    { "ASProtect", "protector", "K3",
      { ".asprotect", ".aspr", ".aspr1", ".aspr2", 0 }, 1, V_ASProtect },
    { "ASPack", "compressor", "K3",
      { ".aspack", ".adata", ".asdata", 0 }, 1, V_ASProtect },
    { "MPRESS", "compressor", "K3 (matcode LZMA)",
      { ".mpress1", ".mpress2", 0 }, 1, V_MPRESS },
    { "VMProtect", "protector/vm", "K1: core/pefile.cc:4800-4842 — bolum adi '<isim><N>' (3.5.1'de RASTGELE: core.cc:3561-3572)",
      { ".vmp0", ".vmp1", ".vmp2", "vmp0", "vmp1", "vmp2" }, 1, V_VMP },
    { "PECompact", "compressor", "K3",
      { "pecompact2", ".pec", ".pec1", ".pec2", 0 }, 1, V_OTHER },
    { "Obsidium", "protector", "K3",
      { ".obsidium", 0 }, 1, V_OTHER },
    { "ExeCryptor", "protector", "K3 (.edata STANDART bolum oldugundan dislandi — MinGW catismasi: vmp_ult_340_fn0 vakasi)",
      { ".ecode", ".ecry", 0 }, 1, V_OTHER },
    { "NSPack", "compressor", "K3",
      { ".nsp0", ".nsp1", ".nsp2", "nsp0", "nsp1", 0 }, 1, V_OTHER },
    { "Petite", "compressor", "K3",
      { ".petite", "petite", 0 }, 1, V_OTHER },
    { "FSG", "compressor", "K3",
      { ".fsg", "fsg", 0 }, 1, V_OTHER },
    { "MEW", "compressor", "K3",
      { ".mew", "mew", 0 }, 1, V_OTHER },
    { "UPack", "compressor", "K3",
      { ".upack", "upack", 0 }, 1, V_OTHER },
    { "RLPack", "compressor", "K3",
      { ".rlp", "rlpack", 0 }, 1, V_OTHER },
    { "StarForce", "protector", "K3",
      { ".sforce", ".pklst", 0 }, 1, V_OTHER },
    { "Safengine Shielden", "protector", "K3",
      { ".sedata", ".sense", 0 }, 1, V_OTHER },
    { "PELock", "protector", "K3",
      { ".pelock", 0 }, 1, V_OTHER },
    { "SVKP", "protector", "K3 (vanimir)",
      { ".psvkp", ".svkp", 0 }, 1, V_OTHER },
    { "Armadillo / SoftwarePassport", "protector", "K3",
      { ".textb", ".adata1", 0 }, 1, V_OTHER },
    { "Dyamar", "protector", "K3",
      { ".dyamar", ".dycrypt", 0 }, 1, V_OTHER },
    { "EXECryptor", "protector", "K3",
      { ".execrypt", ".securo", 0 }, 1, V_OTHER },
    { "CodeMeter / Wibu", "drm", "K3 (obfus.h sahte listesinde de geciyor: __wibu00/01)",
      { "__wibu00", "__wibu01", ".wibu", 0 }, 1, V_WIBU },
    { "nSpack (alternatif yazim)", "compressor", "K3",
      { "nsp0", "nsp1", 0 }, 1, V_OTHER },
    { "Nullsoft NSIS", "installer", "K3",
      { ".ndata", "ndata", 0 }, 1, V_OTHER },
    { "tElock", "packer", "K3 (2000'ler)",
      { ".tlock", "tlock", 0 }, 1, V_OTHER },
    { "Morphine", "protector", "K3",
      { ".mta1", ".mta2", 0 }, 1, V_OTHER },
    { "NeoLite", "compressor", "K3",
      { ".neolite", 0 }, 1, V_OTHER },
    { "PEBundle", "bundler", "K3",
      { ".pebundle", ".peres", ".pesect", 0 }, 1, V_OTHER },
    { "PESpin", "protector", "K3",
      { ".pespin", 0 }, 1, V_OTHER },
    { "PCKa / Perplex", "packer", "K3",
      { ".perplex", 0 }, 1, V_OTHER },
    { "BeRo XPack / spack", "packer", "K3",
      { ".spack", 0 }, 1, V_OTHER },
};

static const int BOLUM_TABLO_ADET = sizeof(BOLUM_TABLO) / sizeof(BOLUM_TABLO[0]);

// ---------------------------------------------------------------------------
// BAYT-DIZGISI IMZA TABLOSU (bolge kisitli)
// ---------------------------------------------------------------------------
static const BaytImza DIZGI_TABLO[] = {
    // UPX — gercek ciktilardan (K2): UPX! + 32B packheader baslikta; $Info kuyrukta
    { "UPX!", R_BASLIK | R_KUYRUK, "K2: UPX 5.3.1-git orneklerinde 0x1ed (win32) / 0x1fd (win64)" },
    { "$Info: This file is packed with the UPX", R_KUYRUK, "K1: identstr" },
    { "UPX 3.", R_KUYRUK, "K1: version banner (3.x)" },
    { "UPX 4.", R_KUYRUK, "K1: version banner (4.x)" },
    // VMProtect
    { "VMProtect", R_BASLIK | R_KORU, "K1: SDK isaretleri vmprotectsdk32/64.dll" },
    { "vmprotectsdk32.dll", R_KORU | R_KUYRUK, "K1: core/intel.cc:19576 import kontrolu" },
    { "vmprotectsdk64.dll", R_KORU | R_KUYRUK, "K1" },
    // (obfus.h FAKE_* izleri asagidaki SAKLI_TABLO'da — karistirilmis)
    // PyInstaller (K1: bootloader/src/pyi_utils.c:169 MAGIC_BASE)
    { "MEI\x0c\r\n\x0c\x0e", R_KUYRUK, "K1: MAGIC_BASE 'MEI\\0\\13\\12\\13\\16' + EOF cookie" },
    { "_MEIPASS", R_KUYRUK | R_KORU, "K1: pyi_main.c:1389" },
    { "pyi-windows-manifest-filename", R_KUYRUK, "K1: bootloader kaynak dizgisi" },
    // Nuitka / PyArmor
    { "__compiled__", R_KORU | R_KUYRUK, "K1: Nuitka onefile/standalone damgasi" },
    { "Pyarmor", R_KORU | R_KUYRUK, "K1: pyarmor cli damgasi" },
    { "__pyarmor__", R_KORU | R_KUYRUK, "K1" },
    { "pytransform", R_KORU | R_KUYRUK, "K1: pyarmor core modulu" },
    // .NET
    { "ConfusedByAttribute", R_KORU, "K1: ConfuserEx WatermarkingProtection.cs:51-53" },
    { "ConfuserEx", R_KORU, "K1" },
    { "KoiVM", R_KORU, "K1: ConfuserEx VM eklentisi" },
    { "BabelObfuscator", R_KORU, "K3: .NET obfuscator" },
    { "SmartAssembly", R_KORU, "K3: .NET obfuscator ({smartassembly})" },
    { "{smartassembly}", R_KORU, "K3" },
    // Kurulum paketleri / SFX
    { "Nullsoft", R_KUYRUK, "K3: NSIS" },
    { "NSIS Error", R_KUYRUK, "K3" },
    { "Inno Setup", R_KUYRUK, "K3" },
    { "RAR!", R_KUYRUK, "K3: WinRAR SFX (kuyrukta arsiv imzasi)" },
    { "7-Zip", R_KUYRUK, "K3: 7z SFX" },
    { "PK\x03\x04", R_KUYRUK, "K3: zip SFX / jar" },
    // TinyLoad XXTEA anahtar blogu (K1: TinyLoad.cpp:255-262)
    // (bayt deseni motor tarafinda ozel olarak aranir — asagida OZEL_TABLO)
    // Ticari protector dizgileri (K3)
    { "Enigma protector", R_KORU | R_BASLIK, "K3" },
    { "ASProtect", R_KORU | R_KUYRUK, "K3" },
    { "Obsidium", R_KORU | R_KUYRUK, "K3" },
    { "EXECryptor", R_KORU, "K3" },
    { "PECompact2", R_KORU | R_KUYRUK, "K3" },
    { "MPRESS", R_BASLIK | R_KORU | R_KUYRUK, "K3" },
    { "Themida", R_BASLIK | R_KORU, "K3" },
    { "WinLicense", R_BASLIK | R_KORU, "K3" },
    { "SecureEngine", R_KORU, "K3: Themida/WinLicense motoru" },
    { "StarForce", R_KORU, "K3" },
    { "SecuROM", R_KORU | R_KUYRUK, "K3" },
    { "SafeDisc", R_KORU | R_KUYRUK, "K3" },
    { "Denuvo", R_KORU, "K3 (anti-tamper)" },
    { "SteamAPI", R_KORU, "K3: Steam zarfi" },
    // Electron / Node / Go / Rust script-kabuklari
    { "electron", R_KUYRUK, "K3: Electron framework" },
    { "app.asar", R_KUYRUK, "K3: Electron paket" },
    { "snapshot_blob.bin", R_KUYRUK, "K3: Node.js pkg" },
};

static const int DIZGI_TABLO_ADET = sizeof(DIZGI_TABLO) / sizeof(DIZGI_TABLO[0]);

// ---------------------------------------------------------------------------
// OZEL BAYT DESENLERI (struct eslesme — motor ozel kod ile bakar)
// ---------------------------------------------------------------------------
// TinyLoad .pxkey XXTEA anahtar blogu (K1: TinyLoad.cpp:255-262)
//   guard1=0xC0DE1337 k0=0xFEEDF00D k1=0xCAFEBABE k2=0xDEADBEEF k3=0x8BADF00D guard2=0xB007DEAD
//   v7: acik baytlar yukarida SK_TINYLOAD icinde KARISTIRILMIS saklanir (oz-referans kalkani)
// XXTEA delta (TinyLoad + eski packer mirasi)
static const uint8_t XXTEA_DELTA[] = { 0xB9,0x79,0x37,0x9E };
// ChaCha20 "expand 32-byte k" (maya ELF protector — K1: chacha sabiti)
static const uint8_t CHACHA_SIG[] = "expand 32-byte k";
// LZMA alone basligi 5D 00 00 (bolge kisitli kullanilmali)
static const uint8_t LZMA_ALONE[] = { 0x5D, 0x00, 0x00 };
// UPX packheader (win32) — UPX! + version 13 + format 9 (K2 gercek cikti)
struct UpxBaslik {
    uint8_t sihir[4];    // 'U','P','X','!'
    uint8_t surum;       // 13 = UPX 5.x, 12 = 4.x, 11 = 3.x, ...
    uint8_t format;      // 9 = win32/pe, 10 = win64/pe? (K2: 32-bit=9; 64-bit=9..)
    uint8_t yontem;      // 2=NRV2B 5=NRV2D 8=NRV2E 14=LZMA
    uint8_t seviye;      // 1..10 (8 = --best)
};

// UPX yontem haritasi (K2: gercek ciktilardan dogrulandi)
inline const char* upx_yontem_adi(uint8_t m) {
    switch (m) {
        case 1: return "NRV2B_8";
        case 2: return "NRV2B_LE32";
        case 3: return "NRV2B_16";
        case 4: return "NRV2D_8";
        case 5: return "NRV2D_LE32";
        case 6: return "NRV2D_16";
        case 7: return "NRV2E_8";
        case 8: return "NRV2E_LE32";
        case 9: return "NRV2E_16";
        case 11: return "CL1B_LE32";
        case 12: return "CL1D_LE32";
        case 13: return "CL1E_LE32";
        case 14: return "LZMA";
        case 15: return "DEFLATE";
        case 16: return "ZSTD";
        default: return "?";
    }
}

// UPX surum haritasi (K2)
inline const char* upx_surum_adi(uint8_t v) {
    switch (v) {
        case 13: return "UPX 5.x";
        case 12: return "UPX 4.x";
        case 11: return "UPX 3.x";
        case 10: return "UPX 2.x";
        case 9:  return "UPX 1.x (1.25+)";
        default: return "UPX (eski)";
    }
}

// PyInstaller EOF cookie cozumu (K1: pyi_utils.c MAGIC_BASE + archive cookie)
// cookie (son 88 bayt): magic[8] paketUzunluk[4] tocOfs[4] tocLen[4] pyVers[4] pyLibAdi[64]
struct PyiCookie {
    uint8_t sihir[8];     // MEI 00 0b 0a 0b 0e — 4. bayt (index 3) SURUME GORE degisir!
    uint32_t paket_uzunluk;
    uint32_t toc_ofs;
    uint32_t toc_uzunluk;
    uint32_t py_surum;    // 27 = py2.7, 38 = 3.8, ...
    char py_kutuphane[64];
};

// ---------------------------------------------------------------------------
// SAHTE IMZA DEMETI KURALLARI
// ---------------------------------------------------------------------------
// obfus.h (include/obfus.h:329-402) ve obfusheader.h (satir 1858-1890) FAKE_SIGNATURES
// modunda su bolumleri ENJETE eder (hepsi bos/1-8 bayt):
static const char* const SAHTE_BOLUMLER[] = {
    ".enigma1", ".enigma2", ".vmp0", ".vmp1", ".vmp2", "UPX0", ".winlice",
    ".themida", ".petite", ".rlp", ".dsstext", "logicoma", ".aspack", ".adata",
    "__wibu00", "__wibu01", ".arch", ".srdata", ".xpdata", ".xtls",
    ".vlizer", ".alien", ".pwdprot", ".tw", "adr", "have", "30cm", "PETETRIS",
    ".mpress1", ".mpress2",
};
static const int SAHTE_BOLUMLER_ADET = sizeof(SAHTE_BOLUMLER) / sizeof(SAHTE_BOLUMLER[0]);

// Demet kurali: asagidaki FARKLI uretici ailelerinden >=2'si ayni dosyada
// bolum adi olarak gorunuyorsa => sahte imza demeti (obfus.h / obfusheader.h / yap)
struct SahteAile { uint8_t satici; const char* ad; };
static const SahteAile SAHTE_AILELER[] = {
    { V_UPX, "UPX" }, { V_OREANS, "Themida/WinLicense/CV" }, { V_ENIGMA, "Enigma" },
    { V_VMP, "VMProtect" }, { V_MPRESS, "MPRESS" }, { V_WIBU, "Wibu" },
    { V_ASProtect, "ASProtect/ASPack" },
};

// yap (undisassemble) README/kaynak notu: tespit mekanizmasini atlatmak icin
// bilinen protector bolumleri + dizgileri kopyalar (K1: repo taramasi)

// ---------------------------------------------------------------------------
// v7 — .NET METADATA ISARET TABLOSU (#Strings yigininda tip/ad-uzayi adlari)
// K1: de4dot kaynagi (de4dot.code/deobfuscators/*) — her obfuscator'in KENDI
//     dedektor kodundan; K3: DIE db/PE/protector_*.sg kurallarindan capraz
// ---------------------------------------------------------------------------
struct NetImza {
    const char* aile;
    const char* isaret;      // #Strings yigini / metadata bolgesinde aranir
    const char* not_;        // kaynak kaniti
};
static const NetImza NET_TABLO[] = {
    { "ConfuserEx (.NET)", "ConfusedByAttribute",
      "K1: ConfuserEx WatermarkingProtection.cs:51 + de4dot Confuser/Deobfuscator.cs:505" },
    { "KoiVM (ConfuserEx VM)", "KoiVM", "K3: DIE protector_KoiVM.2.sg — 'KoiVM' tip adi" },
    { "KoiVM (ConfuserEx VM)", "VMEntryRun", "K3: DIE protector_KoiVM.2.sg" },
    { ".NET Reactor", "NecroVM.Runtime", "K3: DIE protector_NetReactor.2.sg" },
    { ".NET Reactor", "$method0x", "K3: DIE — $method0x6000... metod adi deseni" },
    { "Agile.NET / CliSecure", "ObfuscatedByCliSecureAttribute", "K3: DIE protector_CliSecure.2.sg" },
    { "Agile.NET / CliSecure", "CliSecureRt", "K1: de4dot Agile_NET/CliSecureRtType.cs" },
    { "Babel .NET", "BabelAttribute", "K3: DIE protector_Babel_.NET.2.sg" },
    { "Babel .NET", "BabelObfuscatorAttribute", "K3: DIE protector_Babel_.NET.2.sg" },
    { "Dotfuscator", "DotfuscatorAttribute", "K3: DIE protector_Dotfuscator.2.sg" },
    { "SmartAssembly", "SmartAssembly.Attributes", "K3: DIE protector_Smart_Assembly.2.sg" },
    { "Spices.Net", "NineRays.Obfuscator", "K3: DIE protector_SpicesNet.2.sg" },
    { "Goliath.NET", "ObfuscatedByGoliath", "K3: DIE protector_Goliath.2.sg" },
    { "Goliath.NET", "Goliath.NET.CodeShield", "K3: DIE protector_Goliath.2.sg" },
    { "MaxtoCode", "MRuntime3.dll", "K3: DIE protector_Maxtocode.2.sg" },
    { "MaxtoCode", "Attick.dll", "K3: DIE protector_Maxtocode.2.sg" },
    { "DNGuard", "ZYXDNGuarder", "K3: DIE protector_DNGuard.2.sg" },
    { "DNGuard", "HVMRuntm.dll", "K3: DIE protector_DNGuard.2.sg" },
    { "ILProtector", "Protect32.dll", "K3: DIE protector_ILProtector.2.sg" },
    { "ILProtector", "Protect64.dll", "K3: DIE protector_ILProtector.2.sg" },
    { "Xenocode Postbuild", "Xenocode.Client.Attributes.AssemblyAttributes", "K3: DIE protector_Xenocode_Postbuild.2.sg" },
    { "CodeVeil", "____KILL", "K3: DIE protector_CodeVeil.2.sg" },
    { "XerinFuscator", "Xerin.Runtime", "K3: DIE protector_XerinFuscator.2.sg" },
    { "LDK .NET", "haspdnert.dll", "K3: DIE protector_LDK_.NET.2.sg" },
    { "ConfuserEx (Bed's mod)", "\xD0\xB2\xD0\xB5\xC9\x97\xD1\x81", "K3: DIE — 'вє∂ѕ' assembly adi (UTF-8)" },
};

// .NET surum su damgalari — ham metadata bolgesinde ASCII olarak aranir,
// izleyen karakterlerden surum cozulur (ConfuserEx v9.0.28 ...)
struct NetSuImza { const char* aile; const char* isaret; };
static const NetSuImza NET_SU_TABLO[] = {
    { "ConfuserEx (.NET)", "ConfuserEx v" },       // K1: ConfuserEx watermark
    { "ConfuserEx (.NET)", "Confuser.Core " },      // K1: mkaring/ConfuserEx core damgasi
    { "ConfuserEx (klasik)", "Confuser v" },        // K1: de4dot regex ^Confuser v\d+
};

// .NET Reactor UTF-16 anti-tamper mesaji (#US yigini) — motor ozel arar:
//   "is tampered."  (K3: DIE protector_NetReactor.2.sg UTF-16LE deseni)

} // namespace universaldb
