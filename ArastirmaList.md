# ArastirmaList.md — Packer/Protector Araç Ekosistemi Araştırma Listesi

> **Amaç:** Listedeki HER packer için unpacker / devirtualizer / dumper / İAT-fixer / killer / deobfuscator repoları.
> **Metod:** GitHub REST API (`search/repositories` + `repos`) taraması — 60+ sorgu, 30+ yazar profilinin tamamı, web doğrulaması.
> **Tüm yıldız sayıları ve tarihler API'den alınmıştır: 26.11.2026.** (Yıldızlar canlıdır, ~günlük değişir.)
> Etiketler: **[UNPACK]** **[DEVIRT]** **[DUMP/İAT]** **[KILL]** **[DEOBF]** **[DETECT]** **[SRC]** **[ARAŞTIRMA]**
> Packer envanteri (1 satır = 1 packer) → **[KnowedAlgorithm.md](KnowedAlgorithm.md)**
> Yasal not: araçlar yalnızca kendi yazılımlarınız / yetkili güvenlik araştırması içindir.

---

## A1) VMProtect (2.x – 3.11) — ana sahamız

Güncel durum: VMProtect hâlâ **aktif** geliştiriliyor — 3.10 (Eyl 2025, ARM64 desteği) → **3.11 (24.11.2026)**.
Bizim dedektör kapsamı: **3.0.9 → 3.10.4** (11 sürüm, 310 build, %100 kör test).

### A1.1 — Devirtualizasyon (statik/devirt)

| Repo | Yıldız | Son aktivite | Not |
|---|---|---|---|
| [can1357/NoVmp](https://github.com/can1357/NoVmp) | 2237 | 2021-08 | Efsane: VTIL tabanlı **statik devirt**, VMP x64 3.x — klasik ama temel referans |
| [JonathanSalwan/VMProtect-devirtualization](https://github.com/JonathanSalwan/VMProtect-devirtualization) | 1556 | 2022-06 | Triton (sembolik yürütme) + LLVM ile saf fonksiyon devirt; blog yazısı repoda |
| [can1357/VTIL](https://github.com/can1357/VTIL) | 1630 | 2026-07 | NoVmp'nin çatısı: Virtual-machine Translation IR |
| [wallds/NoVmpy](https://github.com/wallds/NoVmpy) | 441 | 2025-01 | NoVmp'nin Python portu (arşiv) |
| [fjqisba/VmpHelper](https://github.com/fjqisba/VmpHelper) | 424 | 2026-07 | **IDA eklentisi — VMP'yi decompile etmeye yardımcı**; aktif |
| [eversinc33/MogVMP](https://github.com/eversinc33/MogVMP) | 322 | 2026-07 | Remill + LLVM ile **VMP 3.0–3.5 → LLVM IR** lifti |
| [archercreat/titan](https://github.com/archercreat/titan) | 166 | 2024-03 | VMProtect devirtualizer (aynı yazarın [vm_jit](https://github.com/archercreat/vm_jit) PoC'si 127 yıldız) |
| [sunwm518/VMProtect-3-5-DEvirt](https://github.com/sunwm518/VMProtect-3-5-DEvirt) | 121 | 2023-01 | VMP 3.5 devirt çalışması |
| [VMProtectResearch/vmp2-devirtualization](https://github.com/VMProtectResearch/vmp2-devirtualization) | 99 | 2024-11 | **VMP 2.x** devirt |
| [sexyiam/VMPLift](https://github.com/sexyiam/VMPLift) | 70 | 2026-08 | **VMP 3.8–3.10** handler map/lift → IDA/Ghidra'da okunur; yeni nesil |
| [sh4m2hwz/devirt_vmp](https://github.com/sh4m2hwz/devirt_vmp) | 71 | 2023-03 | Python devirt |
| [Rasetsuu/vmp-devirt](https://github.com/Rasetsuu/vmp-devirt) | 67 | 2026-10 | Yeni devirt çalışması |
| [banda59/VMP-devirtualize-project](https://github.com/banda59/VMP-devirtualize-project) | 35 | 2026-02 | Devirt laboratuvarı |
| [aftermathlabs/vmp2](https://github.com/aftermathlabs/vmp2) | 133 | 2025-11 | VMP2 deobf tooling; orijinali `_xeroxz` @ [git.back.engineering](https://git.back.engineering/_xeroxz/vmp2) (GitHub dışı); kardeş repo: [vmhook](https://github.com/aftermathlabs/vmhook) (VMP-2 VM kanca demo'su) |
| [xtremegamer1/vmprofiler](https://github.com/xtremegamer1/vmprofiler) | 6 | 2022-12 | `_xeroxz` vmprofiler'ın (VMP3 handler profilleme) gayriresmî fork'u |
| [LLVMParty/TicklingVMProtect](https://github.com/LLVMParty/TicklingVMProtect) | 176 | 2021-09 | "Tickling VMProtect with LLVM" blog serisinin assetleri |
| [ilyida/vmp3-demo-devirt](https://github.com/ilyida/vmp3-demo-devirt) | 0 | 2026-11 | VMP 3 demo VM analizi (eksik/araştırma aşamasında) — kullanıcının önerdiği |
| [etormadiv/devirtualizeme32_vmp_3.0.9_v2](https://github.com/etormadiv/devirtualizeme32_vmp_3.0.9_v2) | 17 | 2018-10 | devirt.me meydan okuması — **VMP 3.0.9** özel (32-bit) |
| [SecurityResearchStaff/vmp2.0.4](https://github.com/SecurityResearchStaff/vmp2.0.4) | 2 | 2017-06 | **VMP 2.0.4** handler/DispatchTable analiz notları (Çince; kaynak kod DEĞİL) |

### A1.2 — Unpacker / Dumper / İAT onarımı

| Repo | Yıldız | Son aktivite | Not |
|---|---|---|---|
| [colby57/vid](https://github.com/colby57/vid) | 598 | 2026-08 | x86/x64 **import kurtarma + PE yeniden inşa**; aktif, güçlü |
| [x86rc/vmp-lazy-unpack](https://github.com/x86rc/vmp-lazy-unpack) | 500 | 2026-11-17 | Son dönemin en popüler yeni VMP unpacker'ı (unthemidator yazarından) |
| [void-stack/VMUnprotect.Dumper](https://github.com/void-stack/VMUnprotect.Dumper) | 470 | 2022-08 | **.NET** VMProtect dumper (arşiv) |
| [mike1k/VMPImportFixer](https://github.com/mike1k/VMPImportFixer) | 389 | 2021-08 | Import Protection fix'leyici klasik |
| [notsnakesilent/VMPStatic](https://github.com/notsnakesilent/VMPStatic) | 180 | 2026-09 | **Go ile statik unpacker — VMP 1.x–3.x** + PE rebuild; aktif |
| [YuroGod/VMPStaticUnpacker](https://github.com/YuroGod/VMPStaticUnpacker) | 153 | 2026-07 | Statik unpacker — **VMP 3.9.5** desteği |
| [keowu/birosca](https://github.com/keowu/birosca) | 45 | 2023-07 | **VMP 1.x–1.9x** dinamik unpack toolkit (OEP, PE fix, İAT, anti-debug bypass) |
| [sudha2323/vmprotectunpacker](https://github.com/sudha2323/vmprotectunpacker) | 78 | 2025-07 | OEP kurtarma + orijinal binary restore |
| [ReverseSec/vmpmylove](https://github.com/ReverseSec/vmpmylove) | 49 | 2026-11-07 | **Hedefi çalıştırmadan** unpack edilmiş VMP binary analizi |
| [whowould/VMProtect-Unpacker](https://github.com/whowould/VMProtect-Unpacker) | 40 | 2026-10-06 | Statik + runtime unpacker (kullanıcının önerdiği) |
| [archercreat/vmpfix](https://github.com/archercreat/vmpfix) | 38 | 2021-12 | Evrensel x86/x64 **VMP 2.0–3.x import fixer** |
| [nelj14/vmprotect-dumper](https://github.com/nelj14/vmprotect-dumper) | 31 | 2026-04 | Payload çıkarıcı + İAT rekonstrüksiyonu; suspend-process tekniği |
| [crowbar-team/vmp-import-resolver](https://github.com/crowbar-team/vmp-import-resolver) | 34 | 2025-01 | **VMP 3.5+** dinamik import çözücü |
| [Shhoya/MutantKiller](https://github.com/Shhoya/MutantKiller) | 49 | 2022-02 | VMP **Mutation** API fix |
| [nblog/Vm2Import](https://github.com/nblog/Vm2Import) | 101 | 2023-04 | Unicorn emülasyonu ile İAT fix |
| [milk-analyzer/vmpunpack](https://github.com/milk-analyzer/vmpunpack) | 20 | 2026-08 | Generic VMP/packer unpacker — patched-Wine hattı, x64 malware odaklı |
| [plisskien/VMProtect-3.x-Emulator-Memory-Dumper](https://github.com/plisskien/VMProtect-3.x-Emulator-Memory-Dumper) | 11 | 2026-11-07 | **Qiling/Unicorn emülatörü + bellek dumper** — VMP 3.x, 3.10.4'te test |
| [whoamicrashh/VMProtectDumper](https://github.com/whoamicrashh/VMProtectDumper) | 2 | 2026-11-20 | Bellekten unpack: OEP yakalama + İAT (kullanıcının önerdiği; aktif) |
| [ghidrat/vmp-dumper](https://github.com/ghidrat/vmp-dumper) | 0 | 2026-11-01 | x64 import kurtarma + PE dumper — yeni |
| [Moosh43/destiny2-vmprotect-kit](https://github.com/Moosh43/destiny2-vmprotect-kit) | 8 | 2026-08 | VMP **de-mutate/de-thread** toolkit (Destiny 2 build özel) |
| [mizt0/vmp-iat-recovery-tool](https://github.com/mizt0/vmp-iat-recovery-tool) | 9 | 2023-07 | Rust İAT kurtarma |

### A1.3 — VMProtect .NET tarafı

| Repo | Yıldız | Son aktivite | Not |
|---|---|---|---|
| [void-stack/VMUnprotect.Dumper](https://github.com/void-stack/VMUnprotect.Dumper) | 470 | 2022-08 | Dinamik "untamper" (.NET) |
| [DarkBullNull/VMP.NET-Kill](https://github.com/DarkBullNull/VMP.NET-Kill) | 217 | 2021-04 | .NET VMP unpack yardımcısı (arşiv) |
| [void-stack/VMAttack](https://github.com/void-stack/VMAttack) | 227 | 2023-06 | .NET kod sanallaştırma araştırması |
| [chramiq/de4vmp](https://github.com/chramiq/de4vmp) | 90 | 2026-03 | **vmp .net devirtualizer** — yeni |
| [CodeCrackerSND/VMProtectNoDelegates-.NET-](https://github.com/CodeCrackerSND/VMProtectNoDelegates-.NET-) | 8 | 2026-06 | .NET delegate temizleme |

### A1.4 — KILL: anti-anti-debug / anti-anti-VM (VMP özel)

| Repo | Yıldız | Son aktivite | Not |
|---|---|---|---|
| [ivanpotatoes/KozDbg](https://github.com/ivanpotatoes/KozDbg) | 99 | 2026-11-17 | **x64dbg/x32dbg anti-anti-debug eklentisi — VMP 3.3.x–3.10.x profilleri**; kernel sürücü gerektirmez; çok yeni ve çok güçlü |
| [ivanpotatoes/KozVM](https://github.com/ivanpotatoes/KozVM) | 13 | 2026-11-17 | x64dbg **anti-anti-VM** eklentisi — aynı sürüm aralığı |
| [strivexjun/XAntiDebug](https://github.com/strivexjun/XAntiDebug) | 697 | 2019-05 | "VMProtect 3.x anti-debug method improved" |
| [KonBuku/VMDOG](https://github.com/KonBuku/VMDOG) | 64 | 2024-12 | VMware spoof — **tüm VMP sürümlerini** ve güncel anti-VM'leri geçer |
| [Ahora57/Unabomber](https://github.com/Ahora57/Unabomber) | 51 | 2023-06 | Anti-anti-debug araçlarını hata yoluyla tespit (VMP korumasına ilham) |
| [Ahora57/Baltica-29](https://github.com/Ahora57/Baltica-29) | 10 | 2023-06 | VMP anti-anti-VM geliştirilmiş |
| [Ahora57/VMP_UTIL](https://github.com/Ahora57/VMP_UTIL) | 31 | 2025-07 | VMP özellik PoC'leri |
| [Ahora57/troy_starr](https://github.com/Ahora57/troy_starr) | 9 | 2026-01 | ScyllaHide/SharpOD debugger PID sızıntısı |
| [Ahora57/import_wrapper_attack](https://github.com/Ahora57/import_wrapper_attack) | 4 | 2026-11-19 | **VMP 3.0–3.10.4 + Themida/WinLicense import mekanizmasına saldırı** PoC |
| [Ahora57/sexy_mead](https://github.com/Ahora57/sexy_mead) | 7 | 2024-08 | Oreans loader/SDK seçeneklerini bypass |
| [CatCaller/x64Dbg](https://github.com/CatCaller/x64Dbg) | 9 | 2026-03 | **VMP 3.10.3** anti-debug'ını geçecek şekilde modlanmış x64dbg |

### A1.5 — Kaynak / Araştırma / Koleksiyon

| Kaynak | Yıldız | Not |
|---|---|---|
| [MulanYueh/VMProtect3.5.1](https://github.com/MulanYueh/VMProtect3.5.1) | 44 (65 fork) | **3.5.1 TAM KAYNAK aynası** (Ağustos 2026'da yüklenmiş, canlı) |
| [WongHouLeong/VMProtect-Source-Code-LEAK](https://github.com/WongHouLeong/VMProtect-Source-Code-LEAK) | 1 | Alternatif leak aynası |
| [GitLab aynası](https://huihui.cat/mirrors/vmprotect-3.5.1) | — | vmprotect-3.5.1 mirror (GitLab) |
| jmpoep/vmprotect-3.5.1 | ~~44~~ | Orijinal popüler ayna — **DMCA/451, kaldırıldı** (API: HTTP 451) |
| [bold97/vmp35doc](https://github.com/bold97/vmp35doc) | 4 | VMP 3.5 mimarisi + kaynak mantığı analizi (2026-09) |
| [lmy375/awesome-vmp](https://github.com/lmy375/awesome-vmp) | 1096 | **VMP analiz kaynak koleksiyonu** (Çince; makale/tool/seri arşivi) |
| [wllightt/VMprotect-archive](https://github.com/wllightt/VMprotect-archive) | 11 | VMP arşivi (2026-10) |
| [join010255/VMProtect-Analysis-Files](https://github.com/join010255/VMProtect-Analysis-Files) | 7 | Analiz dosyaları |
| [github.com/topics/vmprotect](https://github.com/topics/vmprotect) | — | GitHub konu sayfası |
| `universalAllver.rar` (yerel) | — | Elimizde: 11 sürüm binary + **3.5.1 kaynak klasörü** |

**Diğer sürümlerin kaynağı yok:** API taraması (`vmprotect source`, `vmprotect 3.5 source`, `vmprotect 3.5.1`, `vmprotect in:name created:>2025-06-01`) yalnızca 3.5.1 aynaları buldu. 3.0.9–3.10.4 (3.5.1 hariç) için kaynak GitHub'da **mevcut değil**; crack dağıtan depolar kaynak içermez.

### A1.6 — Kendi altyapımız (bu proje)

| Repo | Not |
|---|---|
| [0xByteDeveloper/MVP_GOD_SSS_TIER_PACKER_FINDER](https://github.com/0xByteDeveloper/MVP_GOD_SSS_TIER_PACKER_FINDER) | Bu repo: VMP 3.0.9–3.10.4 sürüm+özellik+katman dedektörü (C++17, ML yok, %100 kör test) |
| [0xByteDeveloper/MVP_VMP_ALGORTIHM](https://github.com/0xByteDeveloper/MVP_VMP_ALGORTIHM) | VMProtect UI sürüm algoritması (html/json matrisleri) |
| [0xByteDeveloper/UniversalMVPUIAlgorithm_QT](https://github.com/0xByteDeveloper/UniversalMVPUIAlgorithm_QT) | QT tabanlı menü kontrol aracı (tüm sürümler) |

---

## A2) Themida / WinLicense / Code Virtualizer (Oreans)

| Repo | Yıldız | Son aktivite | Not |
|---|---|---|---|
| [ergrelet/unlicense](https://github.com/ergrelet/unlicense) | 1545 | 2023-08 | **Themida/WinLicense 2.x–3.x dinamik unpacker + import fixer** — standart referans |
| [Hendi48/Magicmida](https://github.com/Hendi48/Magicmida) | 766 | 2026-05 | Themida unpacker (Pascal; aktif) |
| [x86rc/unthemidator](https://github.com/x86rc/unthemidator) | 473 | 2026-11-11 | **Themida/CV/WinLicense v3.0–v4** otomatik unpacker + dump fixer; çok yeni |
| [ergrelet/themida-unmutate](https://github.com/ergrelet/themida-unmutate) | 416 | 2024-07 | T/WL/CV 3.x **mutation** obfuscation statik deobfuscator |
| [cg10036/Themida-Unpacker-for-.NET](https://github.com/cg10036/Themida-Unpacker-for-.NET) | 249 | 2025-02 | .NET Themida (arşiv) |
| [bobalkkagi/bobalkkagi](https://github.com/bobalkkagi/bobalkkagi) | 218 | 2023-03 | Themida 3.x unpack + unwrap + devirt (planlı) |
| [TopSoftdeveloper/UnpackThemida](https://github.com/TopSoftdeveloper/UnpackThemida) | 216 | 2026-08 | Dinamik unpacker + import fixer (unlicense hattı) |
| [aftermathlabs/themida-devirt](https://github.com/aftermathlabs/themida-devirt) | 128 | 2026-05 | Themida **devirt sonuçları** |
| [stuxnet147/Themida-Research](https://github.com/stuxnet147/Themida-Research) | 122 | 2025-02 | Themida 3.x araştırması |
| [ret2vibec/whatlicense](https://github.com/ret2vibec/whatlicense) | 116 | 2024-04 | **WinLicense key extraction** (Intel PIN) |
| [ergrelet/themida-spotter-bn](https://github.com/ergrelet/themida-spotter-bn) | 104 | 2024-07 | Binary Ninja: Themida obfuscate kod tespiti |
| [ergrelet/themida-unmutate-bn](https://github.com/ergrelet/themida-unmutate-bn) | 50 | 2024-07 | Binary Ninja: unmutate port |
| [RenardDev/OreansCrack](https://github.com/RenardDev/OreansCrack) | 56 | 2026-01 | Oreans ürünlerinde **lisans emülasyonu** PoC (WIP) |
| [nelj14/themida-dumper](https://github.com/nelj14/themida-dumper) | 42 | 2026-04 | Themida/WL payload çıkarıcı (suspend + dump) |
| [DimaReverse/nuitka-themida-unpacker](https://github.com/DimaReverse/nuitka-themida-unpacker) | 34 | 2026-09 | İki aşamalı pipeline: unlicense → Nuitka onefile |
| [guoxing2024/magicmida-rs](https://github.com/guoxing2024/magicmida-rs) | 27 | 2026-11-24 | **Magicmida'nın Rust portu** — Themida v3 x64 otomatik unpacker |
| [SohWeeKiat/Themida-3.x.x-CRC-Bypass](https://github.com/SohWeeKiat/Themida-3.x.x-CRC-Bypass) | 24 | 2023-07 | Themida 3.x CRC bypass PoC |
| [pakt/decv](https://github.com/pakt/decv) | 92 | 2012 | **Code Virtualizer 1.3.8 decompiler** (tarihi) |
| [67-6f-64/AntiOreans-CodeDevirtualizer](https://github.com/67-6f-64/AntiOreans-CodeDevirtualizer) | 82 | 2023-04 | Oreans code devirtualizer |
| [gavz/analysis.oreans](https://github.com/gavz/analysis.oreans) | 40 | 2020-08 | Themida/WL/CV içeriden analiz notları |
| [Marisa-Chan/GhidrOrean](https://github.com/Marisa-Chan/GhidrOrean) | 16 | 2025-06 | Ghidra ile Oreans devirt |
| [4IbWNsis3S/Oreans-Eagle-VM-decoder](https://github.com/4IbWNsis3S/Oreans-Eagle-VM-decoder) | 3 | 2025-12 | WL/Themida/CV **Eagle VM** handler decoder |
| [NohamR/Code-Virtualizer-Demo](https://github.com/NohamR/Code-Virtualizer-Demo) | 2 | 2026-03 | Code Virtualizer'ın **macOS ARM64**'te ObjC swizzling koruması demosu |
| [orange-cpp/secure_engine](https://github.com/orange-cpp/secure_engine) | 11 | 2024-11 | WinLicense/Themida/CV SDK wrapper |
| [Fl0sec/plutonium-devirt](https://github.com/Fl0sec/plutonium-devirt) | 0 | 2026-11-23 | Themida VM analizi + offline replay (yeni) |
| [abcSup/themida-devirt](https://github.com/abcSup/themida-devirt) | 0 | 2026-11-25 | Yeni devirt çalışması |
| [clovexx/unmutate-dump](https://github.com/clovexx/unmutate-dump) | 0 | 2026-11-24 | Dump + anonim packer bölge birleştirme → themida-unmutate hattı |

---

## A3) Enigma Protector / Enigma Virtual Box

| Repo | Yıldız | Son aktivite | Not |
|---|---|---|---|
| [mos9527/evbunpack](https://github.com/mos9527/evbunpack) | 335 | 2025-11 | **Enigma Virtual Box unpacker** — en olgun araç |
| [EVBExtractor/evb-extractor](https://github.com/EVBExtractor/evb-extractor) | 24 | 2013 | EVB konteyner çıkarıcı (tarihi) |
| [ofkarosia/evbunpack](https://github.com/ofkarosia/evbunpack) | 3 | 2025-12 | evbunpack Rust portu |
| [vrdons/evbunpack-rs](https://github.com/vrdons/evbunpack-rs) | 2 | 2026-11-25 | evbunpack Rust portu (yeni, aktif) |
| [ashduino101/EnigmaUnprotector](https://github.com/ashduino101/EnigmaUnprotector) | 6 | 2026-09 | Enigma Protector obfuscation'ından kod/veri kurtarma |
| [eybee/EnigmaDevirtualizer](https://github.com/eybee/EnigmaDevirtualizer) | 1 | 2018 | Enigma VM (v2.x–3.x) devirt denemesi |
| [Hintay/py-enigma](https://github.com/Hintay/py-enigma) | 2 | 2022-09 | Enigma API Python bağlaması |
| [Selennoid/enigma-dll-loader](https://github.com/Selennoid/enigma-dll-loader) | 1 | 2025-10 | Enigma eklentisi: harici DLL yükleme |

**Not:** Enigma Protector (tam ürün, v8.10 / 30.09.2026) için hazır uçtan-uca açık kaynak unpacker **yok**; pratik yol: x64dbg + OEP takibi + Scylla/pe-sieve dump + evbunpack (yalnız EVB paketleri).

---

## A4) Diğer ticari protectorlar + klasik packer'lar

**ASProtect:** [Hendi48/ASpirin](https://github.com/Hendi48/ASpirin) (28 yıldız, 2026-04, hedef özelinde unpacker) · [pstolarz/asprext](https://github.com/pstolarz/asprext) (24, arşiv, WinDbg eklentisi) · [e-gleba/airstrike3d-tools](https://github.com/e-gleba/airstrike3d-tools) (26, oyun özelinde ASProtect araç seti)
**Safengine Shielden:** [sctnightcore/UnSafengine64](https://github.com/sctnightcore/UnSafengine64) (33) · [holycall/UnSafengine64](https://github.com/holycall/UnSafengine64) (32, C++) — bilimsel makale: [UnSafengine64, MDPI Sensors 2024](https://www.mdpi.com/1424-8220/24/3/840)
**StarForce:** [vdisasm/SFFS-Unpacker](https://github.com/vdisasm/SFFS-Unpacker) (19, Pascal, SFFS) · [King Kong Signature Edition fix](https://github.com/WIFIDarthMaul/Peter-Jackson-s-King-Kong-Signature-Edition-Fix) (50, 2026, oyun özelinde StarForce kaldırma)
**PELock:** resmî [SDK deposu](https://github.com/PELock/PELock-Software-Protection-and-Licensing-SDK) açık (233 yıldız) · [pelock_unpack_lab](https://github.com/aaarrti/pelock_unpack_lab) (2026-02)
**MoleBox:** [sudachen/Molebox](https://github.com/sudachen/Molebox) (182, eski sürümün kaynağı açık) · [molebox-oep-finder](https://github.com/extremecoders-re/molebox-oep-finder) (3)
**EXECryptor / Obsidium / Armadillo:** hazır açık kaynak araç yok — forum tutorial'ları miras.
**UPX & klasikler (ASPack, PECompact, MPRESS, NSPack, FSG, MEW, Petite, Upack, tElock):**
- [upx/upx](https://github.com/upx/upx) — 18.032 yıldız; `upx -d` resmî çözüm
- [orca-zhang/unpack](https://github.com/orca-zhang/unpack) — 98 yıldız, Rust, 2026-11-25'te aktif; UPX/ASPack vb. otomatik tanı+dök
- [anpa1200/Unpacker](https://github.com/anpa1200/Unpacker) — 46 yıldız, 2026-10; UPX/ASPack/Themida/VMP tespit+unpack iş akışı
- [c3rb3ru5d3d53c/karton-unpacker](https://github.com/c3rb3ru5d3d53c/karton-unpacker) — 58 yıldız; Karton servis entegrasyonu
- [kn0wl3dge/mozitools](https://github.com/kn0wl3dge/mozitools) — 52 yıldız; Mozi botnet unpack/config
- [DosX-dev/UPX-Patcher](https://github.com/DosX-dev/UPX-Patcher) — 197 yıldız; `upx -d`'yi **imkânsız kılan** yama (savunma tarafı)
- [ElvisBlue/Imprect-PeCompact](https://github.com/ElvisBlue/Imprect-PeCompact) — Imprect eklentisi, PECompact İAT yönlendirme fix

---

## A5) .NET protector'ları (ConfuserEx / KoiVM / Reactor / Eazfuscator / Agile.NET)

**Evrensel:** [de4dot/de4dot](https://github.com/de4dot/de4dot) (7426, arşiv — 30+ obfuscator tanır) · [ViRb3/de4dot-cex](https://github.com/ViRb3/de4dot-cex) (573, ConfuserEx tam destek) · [NotPrab/.NET-Deobfuscator](https://github.com/NotPrab/.NET-Deobfuscator) (1531 — **protector başına araç listesi**) · [dnSpyEx/dnSpy](https://github.com/dnSpyEx/dnSpy) (11.533, aktif dnSpy) · [icsharpcode/ILSpy](https://github.com/icsharpcode/ILSpy) (27.160) · [0xd4d/dnlib](https://github.com/0xd4d/dnlib) (2506) · [Washi1337/AsmResolver](https://github.com/Washi1337/AsmResolver) (1140)

**ConfuserEx:** [mkaring/ConfuserEx](https://github.com/mkaring/ConfuserEx) (2915, aktif fork) · [yck1509/ConfuserEx](https://github.com/yck1509/ConfuserEx) (3761, orijinal, arşiv) · [undebel/NoFuserEx](https://github.com/undebel/NoFuserEx) (430) · [wwh1004/ConfuserExTools](https://github.com/wwh1004/ConfuserExTools) (208) · [Dump-GUY/ConfuserEx2_String_Decryptor](https://github.com/Dump-GUY/ConfuserEx2_String_Decryptor) (107) · [dr4k0nia/Unscrambler](https://github.com/dr4k0nia/Unscrambler) (106, modded ConfuserEx) · [landoncrabtree/UnconfuserExTools](https://github.com/landoncrabtree/UnconfuserExTools) (85) · [uvbs/ConfuserEx-Unpacker](https://github.com/uvbs/ConfuserEx-Unpacker) (46, emülasyon) · [CusDec-dev/ConfuserEx2-Unpacker](https://github.com/CusDec-dev/ConfuserEx2-Unpacker) (3, 2026-10)
**KoiVM:** [Washi1337/OldRod](https://github.com/Washi1337/OldRod) (389 — **otomatik KoiVM devirt**) · [yck1509/KoiVM](https://github.com/yck1509/KoiVM) (119) · [0x25bit/KoiVM-modded](https://github.com/0x25bit/KoiVM-modded) (DarksVM, 40) · [AxDSan/Venturi77CallHijacker](https://github.com/AxDSan/Venturi77CallHijacker) (18, KoiVM/EazVM/AgileVM patcher)
**.NET Reactor:** [SychicBoy/NETReactorSlayer](https://github.com/SychicBoy/NETReactorSlayer) (1286, 2026-09'da aktif) · [dawwinci/krypton-devirtualizer](https://github.com/dawwinci/krypton-devirtualizer) (26, 2026-08) · [0301091405/autoreaktor](https://github.com/0301091405/autoreaktor) (6, 2026-10, toplu pipeline)
**Eazfuscator:** [holly-hacker/EazFixer](https://github.com/holly-hacker/EazFixer) (459, 2026-01) · [puff/EazyDevirt](https://github.com/puff/EazyDevirt) (183, VM→IL, 2026-01) · [saneki/eazdevirt](https://github.com/saneki/eazdevirt) (180) · [ldstr/EazTrialRemover](https://github.com/ldstr/EazTrialRemover) (83) · [JacksonOnly/EazUnpacker](https://github.com/JacksonOnly/EazUnpacker) (40, 2026-11-14 — C# kaynak kurtarma)
**Agile.NET/CliSecure:** [SychicBoy/AgileDotNetSlayer](https://github.com/SychicBoy/AgileDotNetSlayer) (125) · [dawwinci/agile-net-devirtualizer](https://github.com/dawwinci/agile-net-devirtualizer) (47, 2026-08)
**Diğer:** [lckt0/DotKill-Unpacker](https://github.com/lckt0/DotKill-Unpacker) (155 — anti-de4dot/junk/CFF temizleme) · [advanced-threat-research/DotDumper](https://github.com/advanced-threat-research/DotDumper) (266, otomatik .NET unpacker+logger) · [jgajek/cilantro](https://github.com/jgajek/cilantro) (6, 2026-11-20 — yeni nesil .NET deobf+devirt)

---

## A6) JavaScript (obfuscator.io / javascript-obfuscator)

- [j4k0xb/webcrack](https://github.com/j4k0xb/webcrack) — 3086 yıldız, 2026-11'de aktif; obfuscator.io çıktısını deobfuscate + unminify + unbundler
- [relative/synchrony](https://github.com/relative/synchrony) — 1269 yıldız; javascript-obfuscator temizleyici
- [ben-sb/javascript-deobfuscator](https://github.com/ben-sb/javascript-deobfuscator) — 1162 yıldız; genel amaçlı
- [ben-sb/obfuscator-io-deobfuscator](https://github.com/ben-sb/obfuscator-io-deobfuscator) — 812 yıldız
- [HumanSecurity/restringer](https://github.com/HumanSecurity/restringer) — 621 yıldız; JS deobfuscator
- [0xsdeo/AntiDebug_Breaker](https://github.com/0xsdeo/AntiDebug_Breaker) — 2266 yıldız [KILL]; JS anti-debug/anti-devtools kırıcı
- [lolcaken/javascript-deobfuscator](https://github.com/lolcaken/javascript-deobfuscator) — 9 yıldız (2026-10); javascript-obfuscator 5.x

## A7) Java / Android + Python

**Java:** [CalebFenton/simplify](https://github.com/CalebFenton/simplify) (4685 — Android VM + deobfuscator) · [java-deobfuscator/deobfuscator](https://github.com/java-deobfuscator/deobfuscator) (1762) · [Diobf/Deobfuscator](https://github.com/Diobf/Deobfuscator) (541) · [FabricMC/Enigma](https://github.com/FabricMC/Enigma) (550, remap) · [gaoyu06/c2j-native-deobfuscator](https://github.com/gaoyu06/c2j-native-deobfuscator) (51, 2026-09, native-obfuscator çıktısı)
**Python/PyArmor:** [Svenskithesource/PyArmor-Unpacker](https://github.com/Svenskithesource/PyArmor-Unpacker) (763) · [Lil-House/Pyarmor-Static-Unpack-1shot](https://github.com/Lil-House/Pyarmor-Static-Unpack-1shot) (709, C++, **Pyarmor 8.0–9.3.x statik, 2026-11'de aktif**) · [GDATAAdvancedAnalytics/Pyarmor-Tooling](https://github.com/GDATAAdvancedAnalytics/Pyarmor-Tooling) (185, 2026-07) · [venaxyt/mysterium](https://github.com/venaxyt/mysterium) (176) · [DimaReverse/nuitka-static-unpacker](https://github.com/DimaReverse/nuitka-static-unpacker) (139, 2026-08) · [DimaReverse/hexpyrion](https://github.com/DimaReverse/hexpyrion) (33, Nuitka kaynak kurtarma)

## A8) PHP (ionCube / SourceGuardian / Zend Guard)

Güvenilir, saygın bir açık kaynak decoder **yok**; "ionCube decoder" satan siteler büyük oranda dolandırıcılıktır. Genel amaçlı: [kaimi-io/php-eval-unpacker](https://github.com/kaimi-io/php-eval-unpacker) (12, eval-zinciri çözümü).

---

## A9) LLVM / native obfuscator karşısı (devirt + deobf)

| Repo | Yıldız | Son aktivite | Not |
|---|---|---|---|
| [JonathanSalwan/Tigress_protection](https://github.com/JonathanSalwan/Tigress_protection) | 932 | 2023-11 | Tigress korumalarını kırma (Triton) |
| [19h/chernobog](https://github.com/19h/chernobog) | 313 | 2026-11-23 | **Hex-Rays eklentisi — Hikari LLVM obfuscation'ını çözer**; çok yeni |
| [w00tzenheimer/d810-ng](https://github.com/w00tzenheimer/d810-ng) | 338 | 2026-09 | D-810'in yenilenmiş/refactor edilmiş IDA eklentisi (MBA, CFF) |
| [mrphrazer/obfuscation_detection](https://github.com/mrphrazer/obfuscation_detection) | 688 | 2026-05 | Binary Ninja: obfuscate kodu otomatik tespit |
| [leetonidas/demovfuscator](https://github.com/leetonidas/demovfuscator) | 768 | 2025-05 | movfuscator çıktısını geri döndürme |
| [eversinc33/MicroSMT](https://github.com/eversinc33/MicroSMT) | 82 | 2026-04 | IDA: opaque predicate kaldırma (microcode → z3) |
| [eversinc33/binaryshield-devirtualizer](https://github.com/eversinc33/binaryshield-devirtualizer) | 96 | 2026-05 | BinaryShield protector LLVM devirt |
| [Mac-XK/Deobfuscator](https://github.com/Mac-XK/Deobfuscator) | 34 | 2026-05 | Hikari statik restorasyon (Çince) |
| [NoAddr/yaps](https://github.com/NoAddr/yaps) | 21 | 2026-06 | PUSHAN-tipi **Tigress-benzeri VM devirt** (VPC-duyarlı CFG) |
| [xqzme69/Amice-Deobfuscator](https://github.com/xqzme69/Amice-Deobfuscator) | 10 | 2026-11-24 | fuqiuluo/amice LLVM IR devirt + string decrypt (Rust) |
| [jgajek/cff-deobfuscator](https://github.com/jgajek/cff-deobfuscator) | 8 | 2026-06 | IDA: kontrol-akışı düzleştirme (CFF) deobf |
| D-810 (orijinal) | 334 | 2023-12 | [joydo/d810](https://github.com/joydo/d810) aynası; asıl kaynak GitLab (eshard) |

---

## A10) Genel amaçlı unpack / dump / analiz çerçeveleri

| Araç | Yıldız | Not |
|---|---|---|
| [hasherezade/pe-sieve](https://github.com/hasherezade/pe-sieve) | 3955 | Süreç tarama + implant/hollowing tespiti + dump |
| [hasherezade/hollows_hunter](https://github.com/hasherezade/hollows_hunter) | 2442 | Tüm süreçleri tarayıp döker |
| [hasherezade/mal_unpack](https://github.com/hasherezade/mal_unpack) | 847 | PE-sieve tabanlı dinamik unpacker |
| [unipacker/unipacker](https://github.com/unipacker/unipacker) | 785 | Emülasyon tabanlı otomatik unpacker (UPX/MPRESS/ASPack/PECompact…) |
| [NtQuery/Scylla](https://github.com/NtQuery/Scylla) | 1464 | **İAT rekonstrüksiyonu** klasiği; aktif fork: [ergrelet/Scylla](https://github.com/ergrelet/Scylla) (69, Python binding, 2026-07) |
| [glmcdona/Process-Dump](https://github.com/glmcdona/Process-Dump) | 1872 | Bellekten PE geri yazma |
| [EquiFox/KsDumper](https://github.com/EquiFox/KsDumper) | 1061 | Kernel-uzay dumper (korumalı süreçler) |
| [mrexodia/dumpulator](https://github.com/mrexodia/dumpulator) | 897 | Dump emülasyonu (Unicorn) — konfig çekme |
| [Phat3/PINdemonium](https://github.com/Phat3/PINdemonium) | 240 | Intel PIN tabanlı otomatik unpacker |
| [CheckPointSW/android_unpacker](https://github.com/CheckPointSW/android_unpacker) | 365 | Android generic unpacker |
| [1-3-7/disrobe](https://github.com/1-3-7/disrobe) | 175 | Rust statik decompiler/deobfuscator/unpacker (2026-11'de aktif) |
| [hasherezade/pin_n_sieve](https://github.com/hasherezade/pin_n_sieve) | 64 | Intel Pin + PE-sieve deneysel unpacker |
| [fkie-cad/GeMU](https://github.com/fkie-cad/GeMU) | 29 | QEMU tabanlı generic unpacker |
| [Fare9/ANBU](https://github.com/Fare9/ANBU) | 93 | PIN tabanlı öğrenme projesi |
| [carter-yagemann/vmi-unpack](https://github.com/carter-yagemann/vmi-unpack) | 55 | VMI ( Xen introspection) unpacker |
| [eybisi/kavanoz](https://github.com/eybisi/kavanoz) | 159 | Android banker statik unpack (arşiv) |
| [nickcano/RelocBonus](https://github.com/nickcano/RelocBonus) | 313 | Windows Loader'ı unpacker'a çeviren obfuscation aracı (araştırmalık) |
| **Platformlar:** [x64dbg](https://github.com/x64dbg/x64dbg) (50.391) · [SystemInformer](https://github.com/winsiderss/systeminformer) (16.579) · [Ghidra](https://github.com/NationalSecurityAgency/ghidra) (101.313) · [angr](https://github.com/angr/angr) (9416) · [Unicorn](https://github.com/unicorn-engine/unicorn) (9612) · [Qiling](https://github.com/qilingframework/qiling) (6201) · [Triton](https://github.com/JonathanSalwan/Triton) (4383) · [miasm](https://github.com/cea-sec/miasm) (4021) · [RetDec](https://github.com/avast/retdec) (8676) · [flare-floss](https://github.com/mandiant/flare-floss) (4241 — obfuscate string çözücü) |

## A11) KILL — genel anti-anti-analiz araçları

| Araç | Yıldız | Not |
|---|---|---|
| [x64dbg/ScyllaHide](https://github.com/x64dbg/ScyllaHide) | 4398 | Kullanıcı-mod anti-anti-debug eklentisi (x64dbg/IDA/Olly) |
| [mrexodia/TitanHide](https://github.com/mrexodia/TitanHide) | 2977 | Kernel-mod gizleyici sürücü (2026-07'de aktif) |
| [0xsdeo/AntiDebug_Breaker](https://github.com/0xsdeo/AntiDebug_Breaker) | 2266 | JS ters-mühendislik: anti-debug kırıcı |
| [zhaodice/qemu-anti-detection](https://github.com/zhaodice/qemu-anti-detection) | 1740 | QEMU'yu gizler — **VMP/VProtect/Themida/Enigma** anti-VM geçer; 2026-11'de aktif |
| [Air14/HyperHide](https://github.com/Air14/HyperHide) | 1681 | Hipervizör tabanlı anti-anti-debug (x64dbg) |
| [HackOvert/AntiDBG](https://github.com/HackOvert/AntiDBG) | 814 | Anti-debug teknik kataloğu (savunma öğrenimi) |
| [secrary/makin](https://github.com/secrary/makin) | 741 | Anti-debug/anti-VM numaralarını ifşa eder |

## A12) Packer/Protector TESPİT (dedektörler — bizim lig)

| Araç | Yıldız | Not |
|---|---|---|
| [horsicq/Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy) | 11999 | Endüstri standardı; imza+entropi; [DIE-engine](https://github.com/horsicq/DIE-engine) (3377) ayrı paket |
| [rednaga/APKiD](https://github.com/rednaga/APKiD) | 2641 | Android: packer/protector/obfuscator tanıma (YARA) |
| [JusticeRage/Manalyze](https://github.com/JusticeRage/Manalyze) | 1156 | Statik PE analiz+packer tespiti |
| [Yara-Rules/rules](https://github.com/Yara-Rules/rules) | 4966 | Genel YARA seti (packer kuralları dahil) |
| [wolfram77web/app-peid](https://github.com/wolfram77web/app-peid) | 349 | Web PEiD |
| [Nukem9/SwissArmyKnife](https://github.com/Nukem9/SwissArmyKnife) | 324 | x64dbg: PEiD/IDA imzaları + map/diff |
| [DosX-dev/PE-LiteScan](https://github.com/DosX-dev/PE-LiteScan) | 194 | Cross-platform sezgisel PE analiz |
| [packing-box/peid](https://github.com/packing-box/peid) | 154 | PEiD Python uyarlaması (2026-10'da aktif) |
| [packgenome/PackGenome-Artifacts](https://github.com/packgenome/PackGenome-Artifacts) | 30 | Packer tespiti için otomatik sağlam YARA üretimi (NDSS çalışması) |
| [0pc0deFR/YaraRules](https://github.com/0pc0deFR/YaraRules) | 33 | Compiler/packer/protector YARA kuralları |
| [anpa1200/Unpacker](https://github.com/anpa1200/Unpacker) | 46 | Tespit+unpack iş akışı (UPX/ASPack/Themida/VMP) |
| [cognis-digital/packpeek](https://github.com/cognis-digital/packpeek) | 5 | Statik packer parmak izi (UPX/ASPack/Themida/MPRESS/VMP) |
| [GHFear/Packernoculars](https://github.com/GHFear/Packernoculars) | 6 | Exe packer detector |
| [ShadowGuard-AI/file-executable-packer-detector](https://github.com/ShadowGuard-AI/file-executable-packer-detector) | 1 | Yeni; UPX/PECompact/… tespiti |

---

## A13) Son 12 ayın öne çıkanları (26.11.2025 → 26.11.2026)

> Kullanıcının isteği: "son bu yıl içinde paylaşılanlar çok güçlü" — işte 2025-2026 dalgası:

| Repo | Kategori | Yıldız | Son aktivite |
|---|---|---|---|
| [x86rc/vmp-lazy-unpack](https://github.com/x86rc/vmp-lazy-unpack) | VMP unpack | 500 | 2026-11-17 |
| [x86rc/unthemidator](https://github.com/x86rc/unthemidator) | Themida 3–4 unpack | 473 | 2026-11-11 |
| [colby57/vid](https://github.com/colby57/vid) | VMP İAT/PE rebuild | 598 | 2026-08-17 |
| [19h/chernobog](https://github.com/19h/chernobog) | Hikari devirt (IDA) | 313 | 2026-11-23 |
| [d810-ng](https://github.com/w00tzenheimer/d810-ng) | IDA deobf | 338 | 2026-09-29 |
| [Lil-House/Pyarmor-Static-Unpack-1shot](https://github.com/Lil-House/Pyarmor-Static-Unpack-1shot) | PyArmor 8–9.3 statik | 709 | 2026-11-01 |
| [sexyiam/VMPLift](https://github.com/sexyiam/VMPLift) | VMP 3.8–3.10 handler lift | 70 | 2026-08-28 |
| [notsnakesilent/VMPStatic](https://github.com/notsnakesilent/VMPStatic) | VMP 1.x–3.x statik unpack | 180 | 2026-09-05 |
| [YuroGod/VMPStaticUnpacker](https://github.com/YuroGod/VMPStaticUnpacker) | VMP 3.9.5 statik | 153 | 2026-07-29 |
| [chramiq/de4vmp](https://github.com/chramiq/de4vmp) | VMP .NET devirt | 90 | 2026-03-14 |
| [ivanpotatoes/KozDbg](https://github.com/ivanpotatoes/KozDbg) | VMP 3.3–3.10 anti-anti-debug | 99 | 2026-11-17 |
| [Nelj14 dumpers](https://github.com/nelj14/vmprotect-dumper) | VMP + Themida dumper | 31+42 | 2026-04 |
| [plisskien/VMProtect-3.x-Emulator-Memory-Dumper](https://github.com/plisskien/VMProtect-3.x-Emulator-Memory-Dumper) | Qiling/Unicorn emü-dump | 11 | 2026-11-07 |
| [ReverseSec/vmpmylove](https://github.com/ReverseSec/vmpmylove) | Çalıştırmadan analiz | 49 | 2026-11-07 |
| [Ahora57/import_wrapper_attack](https://github.com/Ahora57/import_wrapper_attack) | VMP 3.0–3.10.4 import saldırısı | 4 | 2026-11-19 |
| [guoxing2024/magicmida-rs](https://github.com/guoxing2024/magicmida-rs) | Magicmida Rust portu | 27 | 2026-11-24 |
| [Hendi48/Magicmida](https://github.com/Hendi48/Magicmida) | Themida unpacker | 766 | 2026-05-14 |
| [aftermathlabs/themida-devirt](https://github.com/aftermathlabs/themida-devirt) | Themida devirt | 128 | 2026-05-10 |
| [Hendi48/ASpirin](https://github.com/Hendi48/ASpirin) | ASProtect unpacker | 28 | 2026-04-11 |
| [jacksonOnly/EazUnpacker](https://github.com/JacksonOnly/EazUnpacker) | Eazfuscator unpack | 40 | 2026-11-14 |
| [SychicBoy/NETReactorSlayer](https://github.com/SychicBoy/NETReactorSlayer) | .NET Reactor | 1286 | 2026-09-12 |
| [jgajek/cilantro](https://github.com/jgajek/cilantro) | .NET devirt (yeni) | 6 | 2026-11-20 |
| [1-3-7/disrobe](https://github.com/1-3-7/disrobe) | Rust unpacker/deobf | 175 | 2026-11-23 |
| [orca-zhang/unpack](https://github.com/orca-zhang/unpack) | Otomatik PE unpack (Rust) | 98 | 2026-11-25 |
| [vrdons/evbunpack-rs](https://github.com/vrdons/evbunpack-rs) | EVB unpack (Rust) | 2 | 2026-11-25 |
| [MulanYueh/VMProtect3.5.1](https://github.com/MulanYueh/VMProtect3.5.1) | **3.5.1 kaynak aynası** | 44 | 2026-08 |
| [eversinc33/MicroSMT](https://github.com/eversinc33/MicroSMT) | Opaque predicate (IDA) | 82 | 2026-04-30 |
| [DimaReverse/nuitka-static-unpacker](https://github.com/DimaReverse/nuitka-static-unpacker) | Nuitka statik | 139 | 2026-08-22 |
| [zhaodice/qemu-anti-detection](https://github.com/zhaodice/qemu-anti-detection) | Anti-VM gizleme | 1740 | 2026-11-20 |
| [0xsdeo/AntiDebug_Breaker](https://github.com/0xsdeo/AntiDebug_Breaker) | JS anti-debug kır | 2266 | 2026-09-21 |

---

## A14) Kaynak durumu özet tablosu

| Durum | Ürünler |
|---|---|
| **[AÇIK] Resmî açık kaynak** | UPX · ConfuserEx (+forks) · KoiVM · BitMono · Obfuscar · Hydra · obfuz · O-LLVM/Hikari/Pluto/Armariris/goron/Polaris/DeClang/O-MVLL/ollvm17 · ROPfuscator · movfuscator · garble/gobfuscate · Tigress (site) · javascript-obfuscator · ProGuard/R8/yGuard · Nuitka · Ryujin · Obsidian · YAP · PEP · AlushPacker · wvmp · JitDecrypter/Nanomites · pe-protector · CompotProtector · PELock SDK (yalnız SDK) · sudachen/Molebox (eski sürüm) |
| **[LEAKED] Sızan açık kaynak** | **VMProtect 3.5.1** (Aralık 2023 sızıntısı) — canlı aynalar: [MulanYueh/VMProtect3.5.1](https://github.com/MulanYueh/VMProtect3.5.1), [WongHouLeong](https://github.com/WongHouLeong/VMProtect-Source-Code-LEAK), [GitLab](https://huihui.cat/mirrors/vmprotect-3.5.1); orijinal jmpoep aynası DMCA'lı (451). Başka VMP sürümünün kaynağı YOK. |
| **[KAPALI] Kaynak yok** | VMProtect 3.0.9–3.10.4 (3.5.1 hariç) + 3.11 · Themida/WinLicense/Code Virtualizer · Enigma Protector/EVB · Obsidium · ASProtect · EXECryptor · Armadillo · StarForce · Safengine Shielden · PELock (motor) · BoxedApp · MoleBox (yeni) · PECompact · ASPack · MPRESS · NSPack · FSG/MEW/UPack/Petite/tElock · Sentinel HASP · CodeMeter · Denuvo · .NET Reactor · Dotfuscator · Eazfuscator · SmartAssembly · Babel · Agile.NET · Spices · DeepSea · Goliath · DexGuard · Allatori · Zelix · Stringer · DashO · JScrambler · Luraph · PyArmor (çekirdek) · ionCube · SourceGuardian · Zend Guard |

## A15) Ek kaynaklar

- [lmy375/awesome-vmp](https://github.com/lmy375/awesome-vmp) — VMP analiz kaynak koleksiyonu (Çince, 1096 yıldız)
- [NotPrab/.NET-Deobfuscator](https://github.com/NotPrab/.NET-Deobfuscator) — .NET protector→araç eşleme listesi (1531 yıldız)
- [ZX41R/awesome-reverse-engineering-and-malware-analysis](https://github.com/ZX41R/awesome-reverse-engineering-and-malware-analysis) — doğrulanmış RE haritası (100 yıldız)
- [github.com/topics/vmprotect](https://github.com/topics/vmprotect) — konu sayfası
- `_xeroxz` blog + repolar: [git.back.engineering](https://git.back.engineering/_xeroxz) (vmp2, vmprofiler — GitHub dışı)
- [UnSafengine64 — MDPI Sensors 2024 makalesi](https://www.mdpi.com/1424-8220/24/3/840) (S. Choi)
- [vmpsoft.com/news](https://vmpsoft.com/news) — VMProtect resmî sürüm geçmişi

---

*Derleme: MVP_GOD_SSS_TIER_PACKER_FINDER — 26.11.2026. Sorgu dökümü ve ham API verileri araştırmacı tarafından saklanır (`scripts/gh_research*.py`).*
