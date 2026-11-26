// ============================================================================
// algoritma_db.h — OTOMATIK URETIM (v8_uret.py) — DEGISTIRME
// ============================================================================
// IMZA OZTESI ALGORITMA DESENLERI
// KAYNAKLAR: ObfusHunter (junk/anti-debug/VM dispatch), ObfusFake (sahte imza),
//   packerscope EntryPointDetector (EP stub), DRMDetector (oyun DRM dizgileri)
// FORMAT: hex nibble; '.' = joker nibble
// ============================================================================
#pragma once
#include <cstdint>
namespace algdb {

struct Desen { const char* kod; const char* kategori; const char* aciklama; const char* desen; };
struct SahteImza { const char* kod; const char* aciklama; const char* desen; };
struct EpStub { const char* kod; const char* aciklama; const char* desen; };
struct DrmDizgi { const char* aile; const char* dizgi; };
struct ModernEp { const char* aile; const char* surum; const char* kaynak; const char* desen; };

// ---- MODERN (2025-2026) GERCEK CIKTI EP DESENLERI — Wine hattindan olculdu (v8: 26.11.2026)
//     Themida 3.2.4.34 demo + Enigma Protector 7.80 (build 20250205) demo;
//     qemu-wine32 hatti ile gercek paketleme yapildi, EP baytlari olculdu
static const ModernEp MODERN_EP_TABLO[] = {
    { "Enigma Protector", "7.8x", "Wine hatti: gercek cikti", "eb08................60e8000000005d81ed........81ed........e9" },
    { "Enigma Protector", "7.8x", "Wine hatti: gercek cikti", "eb08................5051525355565741504151415241534154415541564157489c4881ec........0fae1c24e8" },
    { "Themida / WinLicense", "2.3.x", "Wine hatti: gercek cikti", "565053e801000000cc5889c3402d" },
    { "ZProtect", "1.6", "Wine hatti: gercek cikti", "68..c3410068..c34100c3" },
    { "ZProtect", "1.6", "Wine hatti: gercek cikti", "68..d34100e9......" },
    { "ZProtect", "1.6", "Wine hatti: gercek cikti", "68..c34100e9......" },
    { "MoleBox", "4.3", "Wine hatti: gercek cikti", "5589e583ec08c7042401000000ff15........e8........908db42600000000" },
    { "Themida / WinLicense", "2.3.x", "Wine hatti: gercek cikti", "eb08................e900200000" },
    { "ZProtect", "1.6", "Wine hatti: gercek cikti", "68..d3410068..d34100c3" },
    { "Enigma Protector", "1.5x", "Wine hatti: gercek cikti", "558bec83c4f0b8........e8010000009a83c4108be55de9" },
};
static const int MODERN_EP_TABLO_ADET = sizeof(MODERN_EP_TABLO) / sizeof(MODERN_EP_TABLO[0]);

// ---- ObfusHunter desenleri — 18 adet
static const Desen OBFUS_TABLO[] = {
    { "BREAK_STACK_1", "Junk Code", "", "31c07401e80fa2" },
    { "BREAK_STACK_4", "Junk Code", "", "31db31d231da7406b804000000000fa2" },
    { "BREAK_STACK_5", "Junk Code", "", "31db31c089c389d331c27401200fa2" },
    { "BREAK_STACK_6", "Junk Code", "", "31d231c089c27401e80fa2" },
    { "BREAK_STACK_7", "Junk Code", "", "31d27401e80fa2" },
    { "BREAK_STACK_8", "Junk Code", "", "31c07401500fa2" },
    { "BREAK_STACK_9", "Junk Code", "", "31d2740200000fa2" },
    { "AD_DR_CLEAN", "Anti-Debug", "", "31..89..0089..0489..0889..0c" },
    { "AD_PATCH_V2", "Anti-Debug", "", "66c1e80500c3" },
    { "AD_EXIT_BLOCK", "Anti-Debug", "", "ed31c07401e80fa266c1e80500c3" },
    { "AD_CRASH_V2", "Anti-Debug", "", "cced00" },
    { "AD_RDTSCP", "Anti-Debug", "", "0f31......0fc7f8" },
    { "VM_DISPATCH_X64", "Virtualization", "", "4889c34831c848c1ea0848c1e004" },
    { "VM_DISPATCH_X86", "Virtualization", "", "89d801c829d3d3e1535bd3e909d04a" },
    { "BAD_JMP_X64", "Virtualization", "", "0fa24889c04889daff25" },
    { "RET_BY_VAR", "Internal Logic", "", "8b450805....8b0005....c3" },
    { "HIDE_STRING_ENTRY", "String Obf", "", "31c07401e80fa2......0fa24889c0" },
    { "OBFH_VERI_BLOGU", "Obfus.h veri blogu", "", "00010203040506070809" },
};
static const int OBFUS_TABLO_ADET = sizeof(OBFUS_TABLO) / sizeof(OBFUS_TABLO[0]);

// ---- sahte imza desenleri (ObfusFake-Remover) — 4 adet
static const SahteImza SAHTE_TABLO[] = {
    { "SAHTE_ENIGMA", "Enigma protector v\x01", "456e69676d612070726f746563746f72207601" },
    { "SAHTE_DENUVO", "denuvo_atd", "64656e75766f5f617464000000000000" },
    { "SAHTE_NUITKA", "NUITKA_ONEFILE_PARENT", "4e5549544b415f4f4e4546494c455f504152454e54" },
    { "SAHTE_SCREEN2EXE", "Video created by SCREEN2EXE/SCREEN2SWF", "566964656f20637265617465642062792053435245454e324558452f53435245454e32535746" },
};
static const int SAHTE_TABLO_ADET = sizeof(SAHTE_TABLO) / sizeof(SAHTE_TABLO[0]);

// ---- sahte dongle dizgileri (ObfusFake-Remover) — 12 adet
static const DrmDizgi SAHTE_DONGLE[] = {
    { "obfus.h sahte dongle", "skeydrv.dll" },
    { "obfus.h sahte dongle", "HASPDOSDRV" },
    { "obfus.h sahte dongle", "MARXDEV1.SYS" },
    { "obfus.h sahte dongle", "MxLPT_Sem" },
    { "obfus.h sahte dongle", "nethasp.ini" },
    { "obfus.h sahte dongle", "sense4.dll" },
    { "obfus.h sahte dongle", "SNTNLUSB" },
    { "obfus.h sahte dongle", "RNBOspro" },
    { "obfus.h sahte dongle", "SSIVDDP.DLL" },
    { "obfus.h sahte dongle", "WIBUKEY" },
    { "obfus.h sahte dongle", "\\\\.\\WIZZKEYRL" },
    { "obfus.h sahte dongle", "\\\\.\\NVKEY" },
};
static const int SAHTE_DONGLE_ADET = sizeof(SAHTE_DONGLE) / sizeof(SAHTE_DONGLE[0]);

// ---- EP stub desenleri (packerscope) — 8 adet
static const EpStub EP_STUB[] = {
    { "PUSHAD", "yaygin packer prologu", "60" },
    { "PUSHFD", "yaygin packer prologu", "9c" },
    { "PUSHAD_CALL", "UPX/ASPack tarzi", "60e8" },
    { "PUSHFD_PUSHAD", "packer prologu", "9c60" },
    { "OBSIDIUM_JMP", "Obsidium tarzi kisa JMP", "eb02" },
    { "CALL_DOLLAR5", "konum-bagimsiz stub", "e800000000" },
    { "UPX64_RBP", "UPX x64 giris stubu", "554157415641554154" },
    { "UPX64_RBX", "UPX x64 giris stubu", "53555657415441554156" },
};
static const int EP_STUB_ADET = sizeof(EP_STUB) / sizeof(EP_STUB[0]);

// ---- oyun DRM / ticari protector dizgileri (DRMDetector) — 26 adet
static const DrmDizgi DRM_TABLO[] = {
    { "Denuvo", "denuvo" },
    { "Arxan", "arxan.dll" },
    { "Arxan", "arxanapp.dll" },
    { "Arxan", "arxan_clr.dll" },
    { "SteamStub", "steamstub" },
    { "SteamStub", "steam_api" },
    { "SteamStub", "steam_api64.dll" },
    { "VMProtect", "vmprotect." },
    { "VMProtect", ".vmp0" },
    { "VMProtect", ".vmp1" },
    { "Themida", "themida.dll" },
    { "Themida", "themida.sys" },
    { "WinLicense", "winlicense.dll" },
    { "Themida", ".themida" },
    { "ASPack", ".aspack" },
    { "ASPack", ".adata" },
    { "UPX", ".upx0" },
    { "UPX", ".upx1" },
    { "UPX", "upx!" },
    { "PECompact", "pec2.exe" },
    { "PECompact", "pec1.exe" },
    { "PECompact", "pecompact" },
    { "Obsidium", "obsidium" },
    { "CodeVeil", "codeveil" },
    { "Enigma Protector", "Enigma Protector CA" },
    { "Enigma Protector", "EnigmaProtect" },
};
static const int DRM_TABLO_ADET = sizeof(DRM_TABLO) / sizeof(DRM_TABLO[0]);

} // namespace algdb
