# KnowedAlgorithm.md — Bilinen Packer / Protector / Obfuscator Envanteri

> **Kural: 1 packer = 1 satır.**
> Kaynak etiketleri: **[AÇIK]** resmî açık kaynak (linkli) · **[LEAKED]** sızdırılmış açık kaynak (linkli) · **[KAPALI]** kaynak kodu halka açık değil.
> Yıldız sayıları ve tarihler GitHub REST API'sinden alınmıştır (26.11.2026).
> Araç (unpacker/devirt/dumper/deobf/kill) listesi için → **[ArastirmaList.md](ArastirmaList.md)**

---

## 1) VMProtect Ailesi — elimizdeki Allver_Collection (12 öğe: 3.0.9 → 3.10.4)

| # | Packer | Kaynak | Tek satır |
|---|---|---|---|
| 1 | VMProtect **Ultimate 3.0.9** | **[KAPALI] kaynak yok** | Koleksiyonun en eski sürümü; 4-aile korpusunda (T32E/T32D/T64E/T64D) %100 kör test |
| 2 | VMProtect **Ultimate 3.2.0** | **[KAPALI] kaynak yok** | Orta nesil Ultimate; aile cipası DB'sinde ayrı profil, kör test %100 |
| 3 | VMProtect **Ultimate 3.3.1** | **[KAPALI] kaynak yok** | GUI'si yalnız i386; qemu-emüle wine altında çöker → sürüm atfı OZEL VARYANT olarak raporlanır (proje notu) |
| 4 | VMProtect **Ultimate 3.4.0** | **[KAPALI] kaynak yok** | Çok katmanlı testlerde "dış katman" olarak kanıtlandı (3.9.4-iç + 3.4.0-dış) |
| 5 | VMProtect **3.5.1** | **[LEAKED] tek kaynaklı sürüm** | Aralık 2023 sızıntısı; canlı aynalar: [MulanYueh/VMProtect3.5.1](https://github.com/MulanYueh/VMProtect3.5.1) (44 yıldız, 65 fork), [WongHouLeong/VMProtect-Source-Code-LEAK](https://github.com/WongHouLeong/VMProtect-Source-Code-LEAK), [GitLab aynası](https://huihui.cat/mirrors/vmprotect-3.5.1); orijinal jmpoep aynası DMCA ile 451'e düştü; klasör `universalAllver.rar` içinde de mevcut |
| 6 | VMProtect **Ultimate 3.6.0** | **[KAPALI] kaynak yok** | Belirli kombinasyonlarda (T64E+Pack, T64D+Ultra+HEPSI) bozuk çıktı üretir (proje bulgusu) |
| 7 | VMProtect **Professional 3.8.1** | **[KAPALI] kaynak yok** | Saf-wrapper (fn0) çıktılarında Ult 3.8.4 ile bayt-özdeş — eşitlik sınıfı (cipa kanıtıyla Pack/Ultra'da ayrışır) |
| 8 | VMProtect **Ultimate 3.8.4** | **[KAPALI] kaynak yok** | 3.8.1 eşitlik sınıfının diğer ucu; seçenek/fonksiyon koruması varsa kesin ayırım mümkün |
| 9 | VMProtect **Lite 3.8.7** | **[KAPALI] kaynak yok** | Lite kanalının korpus temsilcisi; 32-bit DLL runtime atfı bu sürümle kanıtlandı |
| 10 | VMProtect **Ultimate 3.9.4** | **[KAPALI] kaynak yok** | Resmî sürüm 26.02.2025; çift katman testlerinde "iç katman" olarak kanıtlandı |
| 11 | VMProtect **Professional 3.9.6** | **[KAPALI] kaynak yok** | Pro kanalının 2025 temsilcisi; T64D fn0 demoları repoda (`vmp396_T64D_fn0.dll`) |
| 12 | VMProtect **Lite 3.10.4** | **[KAPALI] kaynak yok** | Koleksiyonun en yenisi (resmî 28.02.2026, 64K sayfa desteği); Lite+HEPSI kombinasyonunda derleyici takılır (Lite kusuru, korpus dışı 8 build) |

**Aile notları:**
- Resmî hat: 3.9.4 (Şub 2025) → 3.10 (18.09.2025, **ARM64 desteği geldi**) → 3.10.2 → 3.10.4 → **3.11 (24.11.2026, güncel)** — [vmpsoft.com](https://vmpsoft.com)
- **Diğer sürümlerin kaynak kodu GitHub'da YOK.** Tarama sorguları: `vmprotect source`, `vmprotect 3.5 source`, `vmprotect 3.5.1`, `vmprotect in:name created:>2025-06-01` — yalnızca 3.5.1 aynaları bulundu. `SecurityResearchStaff/vmp2.0.4` kaynak DEĞİL (Çince handler/DispatchTable analiz notları).
- Resmî **SDK başlıkları** (VMProtectSDK) açıktır ([örnek](https://github.com/CertainLach/vmprotect) Rust, [Golang](https://github.com/nevmn/VMProtectSDK-Golang)) ama bunlar motor kaynağı değildir.
- "VMProtect-Cracked" tarzı depolar yalnızca **crack/link** dağıtır — kaynak içermez, envanter dışıdır.
- **[AÇIK] benzeri projeler** (eğitim amaçlı VPM/VM): [hmyit/VMPROTECT](https://github.com/hmyit/VMPROTECT) (39 yıldız), [mikasaw/wvmp](https://github.com/mikasaw/wvmp) (x86/x64 PE VM protector, 2026'da aktif).

---

## 2) Ticari PE Protector / Packer'lar (native, kapalı kaynak)

- **Themida** (Oreans) — **[KAPALI]** — x86/x64 VM + mutation + anti-debug/anti-VM; son hat v3.x–v4; aracı: unlicense, unthemidator → §A2
- **WinLicense** (Oreans) — **[KAPALI]** — Themida + lisans yönetimi (SecureEngine); whatlicense ile key extraction araştırması var → §A2
- **Code Virtualizer** (Oreans) — **[KAPALI]** — SDK tabanlı fonksiyon sanallaştırma; decv (1.3.8 decompiler) ve GhidrOrean → §A2
- **Enigma Protector** — **[KAPALI]** — x86/x64 DRM+packer; **aktif geliştirme: v8.10 (30.09.2026)**; evbunpack (EVB kısıtı) → §A3
- **Enigma Virtual Box** — **[KAPALI, ücretsiz]** — dosya sanallaştırma/paketleme; [mos9527/evbunpack](https://github.com/mos9527/evbunpack) (335 yıldız) ile çözülür → §A3
- **Obsidium** — **[KAPALI]** — x86/x64 protector; hâlâ satılıyor; hazır açık kaynak unpacker yok
- **ASProtect** — **[KAPALI, terk ~2010'lar]** — efsane Win32 protector; ASpirin (Hendi48) hedef özelinde → §A4
- **EXECryptor** — **[KAPALI, ölü]** — Delphi dünyasının klassiği; GitHub'da hazır araç yok
- **Armadillo** (Silicon Realms) — **[KAPALI, ölü]** — 2000'ler lisans+packer klasiği; yalnız miras tutorial'lar
- **StarForce** — **[KAPALI]** — Rus donanım/lisans koruması; SFFS-Unpacker (2018) → §A4
- **Safengine Shielden** — **[KAPALI, terk ~2016]** — UnSafengine64 + 2024 MDPI Sensors makalesi → §A4
- **PELock** — **[KAPALI]** — x86 protector + lisans SDK; resmî SDK deposu açık: [PELock/PELock-...-SDK](https://github.com/PELock/PELock-Software-Protection-and-Licensing-SDK) (233 yıldız) — SDK açık, motor kapalı
- **BoxedApp** — **[KAPALI]** — uygulama sanallaştırma/paketleme (aktif, boxedapp.com)
- **MoleBox** — **[KAPALI, ölü]** — eski sürümün kaynağı açık: [sudachen/Molebox](https://github.com/sudachen/Molebox) (182 yıldız, 2017) → §A4
- **PECompact** — **[KAPALI]** — VB GUI'li kompresör; crack dağıtımları kaynak değildir → §A4
- **ASPack / ASProtect kardeşi** — **[KAPALI]** — klasik PE kompresör (aspack.com, hâlâ satılıyor)
- **MPRESS** — **[KAPALI, ücretsiz]** — matcode'un LZMA kompresörü; DIE imzası mevcut
- **NSPack** — **[KAPALI, ölü]** — eski Çin menşeli packer; imzaları her detektörde
- **FSG / MEW SE / UPack / Petite / tElock** — **[KAPALI, ölü]** — 2000'ler mini-packer'ları; PEiD/DIE miras imzalarıyla tanınır
- **Sentinel HASP Envelope** (Thales/SafeNet) — **[KAPALI]** — donanım anahtarlı lisans zarfı
- **CodeMeter** (Wibu) — **[KAPALI]** — donanım tabanlı koruma + zarf
- **Denuvo Anti-Tamper** — **[KAPALI]** — oyun endüstrisi anti-tamper'i (kapsam notu: PE packer değil, kiralık koruma)

## 3) Açık Kaynak Native Packer / Protector'lar

- **UPX** — **[AÇIK]** — [upx/upx](https://github.com/upx/upx) (18.032 yıldız); `upx -d` resmî unpacker — **teknik olarak "korumasız" paketleyici**
- **Obsidian Protector** — **[AÇIK]** — [vertigo6622/obsidian-protector](https://github.com/vertigo6622/obsidian-protector); ARM64 + PyInstaller destekli tam özellikli protector (2026'da aktif)
- **Ryujin Protector** — **[AÇIK]** — [keowu/Ryujin](https://github.com/keowu/Ryujin) (355 yıldız); Intel BIN2BIN PE obfuscation/protection/DRM
- **YAP** — **[AÇIK]** — [undisassemble/yap](https://github.com/undisassemble/yap); x86-64 Windows PE protector (2026'da aktif)
- **PEP** — **[AÇIK]** — [NIKJOO/PEP](https://github.com/NIKJOO/PEP) (157 yıldız); "private exe protector"
- **AlushPacker** — **[AÇIK]** — [Alon-Alush/AlushPacker](https://github.com/Alon-Alush/AlushPacker); manuel loader'lı PE packer
- **WVmp** — **[AÇIK]** — [mikasaw/wvmp](https://github.com/mikasaw/wvmp); x86/x64 PE **VM protector** araştırması (2026)
- **JitDecrypter / Nanomites** — **[AÇIK]** — [Fatmike-GH](https://github.com/Fatmike-GH/JitDecrypter) (JIT deşifre) ve [Nanomites](https://github.com/Fatmike-GH/Nanomites) koruma teknikleri
- **pe-protector** — **[AÇIK]** — [ATsahikian/pe-protector](https://github.com/ATsahikian/pe-protector) (53 yıldız)
- **IMProtector** — **[AÇIK]** — [Souhardya/IMProtector](https://github.com/Souhardya/IMProtector); eski 32-bit crypter
- **CompotProtector** — **[AÇIK]** — [aronpaaul/CompotProtector](https://github.com/aronpaaul/CompotProtector); Rust ile x64 PE protector (2026)

## 4) Açık Kaynak Derleyici/LLVM Obfuscator'ları (native)

- **O-LLVM** — **[AÇIK]** — [obfuscator-llvm/obfuscator](https://github.com/obfuscator-llvm/obfuscator) (4.398 yıldız, arşiv); CFF/bogus/opaque efsanesi
- **Hikari** — **[AÇIK]** — [HikariObfuscator/Hikari](https://github.com/HikariObfuscator/Hikari) (2.101 yıldız); portlar: [Hikari-fix](https://github.com/PPKunOfficial/Hikari-fix) (2026'da aktif), [Hikari-LLVM19](https://github.com/Aethereux/Hikari-LLVM19), [ChandHsu/Hikari-LLVM15](https://github.com/ChandHsu/Hikari-LLVM15)
- **Pluto** — **[AÇIK]** — [bluesadi/Pluto](https://github.com/bluesadi/Pluto) (916 yıldız); LLVM 14 tabanlı
- **Armariris** — **[AÇIK]** — [GoSSIP-SJTU/Armariris](https://github.com/GoSSIP-SJTU/Armariris) (1.348 yıldız); Şanghay Jiao Tong LLVM çatısı
- **goron** — **[AÇIK]** — [amimo/goron](https://github.com/amimo/goron) (719 yıldız)
- **ollvm17** — **[AÇIK]** — [DreamSoule/ollvm17](https://github.com/DreamSoule/ollvm17) (676 yıldız); LLVM 17 portu
- **Polaris** — **[AÇIK]** — [za233/Polaris-Obfuscator](https://github.com/za233/Polaris-Obfuscator) (572 yıldız; 2026'da aktif)
- **DeClang** — **[AÇIK]** — [DeNA/DeClang](https://github.com/DeNA/DeClang) (503 yıldız)
- **O-MVLL** — **[AÇIK]** — [open-obfuscator/o-mvll](https://github.com/open-obfuscator/o-mvll) (1.192 yıldız); Android/iOS NDK
- **ROPfuscator** — **[AÇIK]** — [ropfuscator/ropfuscator](https://github.com/ropfuscator/ropfuscator) (442 yıldız); ROP tabanlı obfuscation
- **dittobytes** — **[AÇIK]** — [tijme/dittobytes](https://github.com/tijme/dittobytes) (656 yıldız); metamorfik C/C++ → PIC/BOF
- **Tigress** — **[AÇIK]** — akademik obfuscator ([tigress.cs.arizona.edu](https://tigress.cs.arizona.edu), GitHub aynası yok); kırma çalışması: [JonathanSalwan/Tigress_protection](https://github.com/JonathanSalwan/Tigress_protection) (932 yıldız) → §A10
- **movfuscator** — **[AÇIK]** — [xoreaxeaxeax/movfuscator](https://github.com/xoreaxeaxeax/movfuscator) (10.595 yıldız); "tek instruction" derleyici; karşısı: demovfuscator → §A10
- **garble** — **[AÇIK]** — [burrowers/garble](https://github.com/burrowers/garble) (5.840 yıldız); Go obfuscator
- **gobfuscate** — **[AÇIK]** — [unixpickle/gobfuscate](https://github.com/unixpickle/gobfuscate) (1.573 yıldız); eski Go obfuscator

## 5) .NET Obfuscator / Protector'ları

**Açık kaynak:**
- **ConfuserEx** — **[AÇIK]** — [yck1509/ConfuserEx](https://github.com/yck1509/ConfuserEx) (3.761 yıldız, arşiv) + aktif fork [mkaring/ConfuserEx](https://github.com/mkaring/ConfuserEx) (2.915 yıldız)
- **KoiVM** (+modded/DarksVM) — **[AÇIK]** — [yck1509/KoiVM](https://github.com/yck1509/KoiVM) (119 yıldız), [0x25bit/KoiVM-modded](https://github.com/0x25bit/KoiVM-modded), [TheProxyRE/KoiVM](https://github.com/TheProxyRE/KoiVM); devirt: OldRod → §A5
- **BitMono** — **[AÇIK]** — [bitmono-project/BitMono](https://github.com/bitmono-project/BitMono) (581 yıldız; 2026'da aktif)
- **Obfuscar** — **[AÇIK]** — [obfuscar/obfuscar](https://github.com/obfuscar/obfuscar) (3.232 yıldız)
- **Hydra** — **[AÇIK]** — [DestroyerDarkNess/Hydra](https://github.com/DestroyerDarkNess/Hydra) (54 yıldız); dnlib/AsmResolver tabanlı
- **obfuz** — **[AÇIK]** — [focus-creative-games/obfuz](https://github.com/focus-creative-games/obfuz) (844 yıldız); Unity/HybridCLR

**Kapalı kaynak:**
- **.NET Reactor** (Eziriz) — **[KAPALI]** — en yaygın ticari; kırıcı: NETReactorSlayer (1.286 yıldız) → §A5
- **Dotfuscator** (PreEmptive) — **[KAPALI]** — VS Community sürümü dağıtılır; de4dot desteği
- **Eazfuscator.NET** — **[KAPALI]** — optimizasyon odaklı; EazFixer/EazyDevirt ile devirt → §A5
- **SmartAssembly** (Redgate) — **[KAPALI]** — de4dot tanıması mevcut
- **Crypto Obfuscator** (LogicNP) — **[KAPALI, terk]** — eski nesil
- **Babel Obfuscator** — **[KAPALI]** — aktif ticari
- **Agile.NET / CliSecure** (SecureTeam) — **[KAPALI]** — AgileDotNetSlayer + devirtualizer → §A5
- **Spices.Net** — **[KAPALI]** — 9rays, eski
- **DeepSea Obfuscator** — **[KAPALI, ölü]**
- **Goliath.NET** — **[KAPALI]** — VM tabanlı, kapalı dağıtım
- **Xenocode Postbuild / Salamander .NET** — **[KAPALI, ölü]** — 2000'ler sonunun klasiği
- **Phoenix Protector** (NTCore) — **[KAPALI]** — ücretsiz sürümü var, kaynak yok

## 6) Java / Android

- **ProGuard** — **[AÇIK]** — [guardsquare/proguard](https://github.com/Guardsquare/proguard); R8 ([r8](https://r8.googlesource.com/r8)) Android Gradle varsayılanı
- **yGuard** — **[AÇIK]** — [yworks/yguard](https://github.com/yWorks/yguard)
- **DexGuard** (Guardsquare) — **[KAPALI]** — ProGuard'ın Android ticari ağabeyi
- **Allatori** — **[KAPALI]** — ucuz ticari jar obfuscator
- **Zelix KlassMaster** — **[KAPALI]** — eski güçlü flow obfuscator
- **Stringer Java Obfuscator** — **[KAPALI]** — string şifreleme odaklı
- **DashO** (PreEmptive) — **[KAPALI]** — Android/Java ticari

## 7) JavaScript

- **javascript-obfuscator (obfuscator.io)** — **[AÇIK]** — [javascript-obfuscator/javascript-obfuscator](https://github.com/javascript-obfuscator/javascript-obfuscator) (16.346 yıldız); karşı taraf: webcrack/synchrony → §A6
- **JScrambler** — **[KAPALI]** — kurumsal SaaS obfuscator
- **Luraph** — **[KAPALI]** — LuaU/JS SaaS obfuscator

## 8) Python

- **PyArmor** — **[YARI-AÇIK]** — [dashingsoft/pyarmor](https://github.com/dashingsoft/pyarmor) (5.231 yıldız); CLI açık, **çekirdek kapalı** (freemium); kırıcıları → §A7
- **Nuitka** — **[AÇIK]** — derleyici (protector değil); statik kurtarma araçları → §A7
- **PyInstaller / pyz** — **[NOT: koruma değil paketleme]** — unpacker'ları §A7'de

## 9) PHP

- **ionCube Encoder** — **[KAPALI]** — "decoder" iddialı sitelerin çoğu dolandırıcılık; güvenilir açık kaynak yok
- **SourceGuardian** — **[KAPALI]** — aynı durum
- **Zend Guard** — **[KAPALI]** — Zend ecoding eski nesil; yine güvenilir decoder yok

## 10) Packer/Protector TESPİT Araçları (bu projenin sahası)

- **Detect It Easy (DIE)** — **[AÇIK]** — [horsicq/Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy) (11.999 yıldız) + [DIE-engine](https://github.com/horsicq/DIE-engine) (3.377)
- **PEiD** — **[KAPALI, ölü]** — miras userdb; Python uyarlaması: [packing-box/peid](https://github.com/packing-box/peid) (154 yıldız)
- **Exeinfo PE** — **[KAPALI, ücretsiz]** — freeware detektör
- **Manalyze** — **[AÇIK]** — [JusticeRage/Manalyze](https://github.com/JusticeRage/Manalyze) (1.156 yıldız)
- **APKiD** — **[AÇIK]** — [rednaga/APKiD](https://github.com/rednaga/APKiD) (2.641 yıldız); Android "PEiD"
- **YARA kural setleri** — **[AÇIK]** — [Yara-Rules/rules](https://github.com/Yara-Rules/rules) (4.966), [PackGenome](https://github.com/packgenome/PackGenome-Artifacts) (otomatik packer YARA üretimi)
- **PE-LiteScan** — **[AÇIK]** — [DosX-dev/PE-LiteScan](https://github.com/DosX-dev/PE-LiteScan) (194 yıldız)
- **Packernoculars** — **[AÇIK]** — [GHFear/Packernoculars](https://github.com/GHFear/Packernoculars); Exe packer detector
- **MVP GOD SSS TIER PACKER FINDER** — **[AÇIK, bu repo]** — VMProtect 3.0.9–3.10.4 sürüm + özellik + katman dedektörü; %100 kör test, ML yok

---

*Bu envanter `MVP_GOD_SSS_TIER_PACKER_FINDER` projesi için derlendi. Araç listesi, yıldız sıralamaları ve son 12 ayın çıkışları: **[ArastirmaList.md](ArastirmaList.md)***
