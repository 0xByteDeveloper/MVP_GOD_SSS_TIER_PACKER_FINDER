# KnowedAlgorithm.md — Bilinen Packer / Protector / Obfuscator Envanteri (v3)

> **Kural: 1 packer = 1 satır.**
> Kaynak etiketleri: **[AÇIK]** resmî açık kaynak (linkli) · **[LEAKED]** sızdırılmış açık kaynak (linkli) · **[KAPALI]** kaynak kodu halka açık değil.
> Yıldız sayıları ve tarihler GitHub REST API'sinden alınmıştır (26.11.2026). (Yıldızlar canlıdır, ~günlük değişir.)
> Araç (unpacker/devirt/dumper/deobf/kill) listesi için → **[ArastirmaList.md](ArastirmaList.md)**
> v2 notu: envanter ~60 → **150+ packer**'a çıkarıldı; Çin Android sağlamlaştırma ailesi, DRM/oyun zarfları, anti-cheat hattı, modern açık kaynak protector dalgası ve script-dili obfuscator'ları eklendi.
> **v3 notu (kaynak-kod turu, 26.11.2026):** 66 hedefin KAYNAĞI indirilip analiz edildi (41 native packer + 9 ekosistem + 20 LLVM obfuscator pass'i + VMProtect 3.5.1 tam kaynak). Her açık kaynak packer'dan **deterministik iz çıkarıldı** (bölüm adları, sihirli baytlar, kripto sabitleri — dosya:satır kanıtıyla): → **[docs/KaynakKodAnalizi.md](docs/KaynakKodAnalizi.md)**. Bu izler `src/universal_db.h`'de motorun beslenmesi için kodlandı (K1/K2/K3 kanıt seviyeleri). Kritik bulgular: VMProtect 3.5.1'de bölüm adı RASTGELE üretilir (core.cc:3561); obfus.h/obfusheader.h başka protector'lerin bölümlerini SAHTE enjekte eder (FAKE_SIGNATURES) — dedektör artık bu sahteciliği DEMET olarak ayırt eder.

---

## 1) VMProtect Ailesi — elimizdeki Allver_Collection (12 öğe: 3.0.9 → 3.10.4)

| # | Packer | Kaynak | Tek satır |
|---|---|---|---|
| 1 | VMProtect **Ultimate 3.0.9** | **[KAPALI] kaynak yok** | Koleksiyonun en eski sürümü; 4-aile korpusunda (T32E/T32D/T64E/T64D) %100 kör test |
| 2 | VMProtect **Ultimate 3.2.0** | **[KAPALI] kaynak yok** | Orta nesil Ultimate; aile cipası DB'sinde ayrı profil, kör test %100 |
| 3 | VMProtect **Ultimate 3.3.1** | **[KAPALI] kaynak yok** | GUI'si yalnız i386; qemu-emüle wine altında çöker → sürüm atfı OZEL VARYANT olarak raporlanır (proje notu) |
| 4 | VMProtect **Ultimate 3.4.0** | **[KAPALI] kaynak yok** | Çok katmanlı testlerde "dış katman" olarak kanıtlandı (3.9.4-iç + 3.4.0-dış) |
| 5 | VMProtect **3.5.1** | **[LEAKED] tek kaynaklı sürüm** | Aralık 2023 sızıntısı; canlı aynalar: [MulanYueh/VMProtect3.5.1](https://github.com/MulanYueh/VMProtect3.5.1) (44 yıldız, 65 fork), [WongHouLeong/VMProtect-Source-Code-LEAK](https://github.com/WongHouLeong/VMProtect-Source-Code-LEAK), [GitLab aynası](https://huihui.cat/mirrors/vmprotect-3.5.1); orijinal jmpoep aynası DMCA/451; klasör `universalAllver.rar` içinde de mevcut |
| 6 | VMProtect **Ultimate 3.6.0** | **[KAPALI] kaynak yok** | Belirli kombinasyonlarda (T64E+Pack, T64D+Ultra+HEPSI) bozuk çıktı üretir (proje bulgusu) |
| 7 | VMProtect **Professional 3.8.1** | **[KAPALI] kaynak yok** | Saf-wrapper (fn0) çıktılarında Ult 3.8.4 ile bayt-özdeş — eşitlik sınıfı (cipa kanıtıyla Pack/Ultra'da ayrışır) |
| 8 | VMProtect **Ultimate 3.8.4** | **[KAPALI] kaynak yok** | 3.8.1 eşitlik sınıfının diğer ucu; seçenek/fonksiyon koruması varsa kesin ayırım mümkün |
| 9 | VMProtect **Lite 3.8.7** | **[KAPALI] kaynak yok** | Lite kanalının korpus temsilcisi; 32-bit DLL runtime atfı bu sürümle kanıtlandı |
| 10 | VMProtect **Ultimate 3.9.4** | **[KAPALI] kaynak yok** | Resmî sürüm 26.02.2025; çift katman testlerinde "iç katman" olarak kanıtlandı |
| 11 | VMProtect **Professional 3.9.6** | **[KAPALI] kaynak yok** | Pro kanalının 2025 temsilcisi (resmî 19.06.2025, Rust sembol demangling); T64D fn0 demoları repoda |
| 12 | VMProtect **Lite 3.10.4** | **[KAPALI] kaynak yok** | Koleksiyonun en yenisi (resmî 28.02.2026, 64K sayfa desteği); Lite+HEPSI kombinasyonunda derleyici takılır (Lite kusuru, korpus dışı 8 build) |

**Aile notları:**
- Resmî hat: 3.9.4 (Şub 2025) → 3.10 (18.09.2025, **ARM64**) → 3.10.1 (01.10.2025, Android native) → 3.10.2 (27.10.2025) → 3.10.3 (11.12.2025) → 3.10.4 (28.02.2026) → **3.10.5 (20.04.2026 — "Improved protection against static unpacking"!)** → 3.10.6 (23.06.2026, yeni VMProtectFunction* marker'ları) → **3.11 (08.10.2026 duyuru, 24.11.2026 dağıtım; Rust SDK, ARM64 LDAPR ailesi, macOS 27)** — [vmpsoft.com/news](https://vmpsoft.com/news)
- **3.10.5'in "statik unpackinge karşı koruma" iyileştirmesi bu projenin doğrudan rakip hamlesidir** — dedektör kapsamımız 3.0.9–3.10.4'tür, 3.10.5+ için cipa güncellemesi gerekir.
- **Diğer sürümlerin kaynak kodu GitHub'da YOK.** Tarama sorguları: `vmprotect source`, `vmprotect 3.5 source`, `vmprotect 3.4/3.6/3.8/3.9 source`, `vmprotect leak`, `vmprotect in:name created:>2025-06-01` — yalnızca 3.5.1 aynaları bulundu. `SecurityResearchStaff/vmp2.0.4` kaynak DEĞİL (Çince handler/DispatchTable analiz notları).
- Resmî **SDK başlıkları** açıktır ([CertainLach/vmprotect](https://github.com/CertainLach/vmprotect) Rust, [nevmn/VMProtectSDK-Golang](https://github.com/nevmn/VMProtectSDK-Golang), [orange-cpp/vmprotect-sdk](https://github.com/orange-cpp/vmprotect-sdk) vcpkg portu) ama bunlar motor kaynağı değildir.
- "VMProtect-Cracked" tarzı depolar yalnızca **crack/link** dağıtır — kaynak içermez, envanter dışıdır.
- **[AÇIK] benzeri projeler** (eğitim amaçlı VM protector): [hmyit/VMPROTECT](https://github.com/hmyit/VMPROTECT) (39★), [mikasaw/wvmp](https://github.com/mikasaw/wvmp) (x86/x64 PE VM protector, 2026'da aktif), [rwfpl/rewolf-x86-virtualizer](https://github.com/rwfpl/rewolf-x86-virtualizer) (376★ VM tabanlı x86 protector), [nodiuus/nocturne](https://github.com/nodiuus/nocturne) (180★, bin2bin x86-64 code virtualizer, 2026'da aktif), [ac3ss0r/cvm.h](https://github.com/ac3ss0r/cvm.h) (37★ header-only TM engine).

---

## 2) Oreans Ailesi (Themida / WinLicense / Code Virtualizer)

- **Themida** (Oreans) — **[KAPALI]** — x86/x64 VM + mutation + anti-debug/anti-VM; **güncel hat 3.2.6.0 (11.08.2026, Themida.exe tamamen 64-bit'e taşındı)** — [oreans.com](https://www.oreans.com/Themida.php)
- **WinLicense** (Oreans) — **[KAPALI]** — Themida + SecureEngine lisans yönetimi; aynı 3.2.6.0 hattında — [oreans.com](https://www.oreans.com)
- **Code Virtualizer** (Oreans) — **[KAPALI]** — SDK tabanlı fonksiyon sanallaştırma; **resmî v4.0 (4.0.1.0, 11.10.2026, x86/x64 MUTATE desteği)** — [changelog](https://www.oreans.com/CodeVirtualizerAllWhatsNew.php)
- Araçları (unlicense, unthemidator, Themidie, decv, GhidrOrean...) → §A2

## 3) Enigma Ailesi

- **Enigma Protector** — **[KAPALI]** — x86/x64 DRM+packer; **aktif geliştirme: 8.00 (28.01.2026) → 8.10 (30.09.2026, Go derlenmiş dosya desteği)** — [changelog](https://enigmaprotector.com/en/downloads/changelog.html)
- **Enigma Virtual Box** — **[KAPALI, ücretsiz]** — dosya sanallaştırma/paketleme; [mos9527/evbunpack](https://github.com/mos9527/evbunpack) (335★) ile çözülür → §A3

## 4) Diğer Ticari PE Protector / Packer'lar (native, kapalı kaynak)

- **VxLang** — **[KAPALI (beta ücretsiz, tam sürüm Patreon)** — yükselen yıldız: obfuscator + **code virtualizer** + protector + runtime code encryption; EXE/DLL/SYS/UEFI/.NET (ELF beta); GitHub sayfası [vxlang/vxlang-page](https://github.com/vxlang/vxlang-page) (799★, 2026-11'de aktif) — [vxlang.github.io](https://vxlang.github.io/)
- **Obsidium** — **[KAPALI]** — x86/x64 protector; hâlâ satılıyor; hazır açık kaynak unpacker yok
- **ASProtect** — **[KAPALI, terk ~2010'lar]** — efsane Win32 protector (SKE varyantları); ASpirin (Hendi48) hedef özelinde → §A4
- **EXECryptor** — **[KAPALI, ölü]** — Delphi dünyasının klassiği; GitHub'da hazır araç yok
- **Armadillo / SoftwarePassport** (Silicon Realms) — **[KAPALI, ölü]** — 2000'ler lisans+packer klasiği; yalnız miras tutorial'lar
- **SDProtector** — **[KAPALI, ölü]** — eski nesil Win32 protector
- **XProtector** — **[KAPALI, ölü]** — 2000'ler sonu Çin menşeli protector
- **StarForce** — **[KAPALI]** — Rus donanım/lisans koruması; SFFS-Unpacker (2018) → §A4
- **Safengine Shielden** — **[KAPALI, terk ~2016]** — UnSafengine64 + 2024 MDPI Sensors makalesi → §A4
- **PELock** — **[KAPALI]** — x86 protector + lisans SDK; resmî SDK deposu açık (233★) + 2026'da **Lua Virtualizer** ürün ailesi (Go/C#/Ruby/VSCode) — [PELock org](https://github.com/PELock) → §A4
- **CrackProof** — **[KAPALI]** — Çin menşeli ticari packer (il2cpp oyun korumasında da görülür); unpacker dalgası 2026'da patladı (Senbei, Nyadecrypt, crackproof-unpacker) → §A4
- **Tencent VM (TVM / .tvm0)** — **[KAPALI]** — Tencent oyun korumasının VM hattı (`.tvm0` bölümü); 2026'da tvm-recover + tvm-devirt çıktı → §A4
- **VProtect** — **[KAPALI]** — Çin menşeli packer (qemu-anti-detection readme'sinde VMP/Themida/Enigma ile aynı listede anılır)
- **ExeStealth** — **[KAPALI, ölü]** — 2000'ler packer'ı; hâlâ malware örneklerinde görülür (DIE imzası var)
- **Milfuscator** — **[KAPALI]** — x86 PE mutator; referans deposu [nelfo/Milfuscator](https://github.com/nelfo/Milfuscator) (237★, 2022)
- **HeartCrypt** — **[KAPALI, PaaS]** — packer-as-a-service (2024'ten beri aktif, malware sahnesi); açık kaynak aracı yok
- **BoxedApp** — **[KAPALI]** — uygulama sanallaştırma/paketleme (aktif, boxedapp.com)
- **MoleBox** — **[KAPALI, ölü]** — eski sürümün kaynağı açık: [sudachen/Molebox](https://github.com/sudachen/Molebox) (182★, 2017) → §A4
- **PECompact** — **[KAPALI]** — VB GUI'li kompresör; crack dağıtımları kaynak değildir
- **ASPack** — **[KAPALI]** — klasik PE kompresör (aspack.com, hâlâ satılıyor)
- **MPRESS** — **[KAPALI, ücretsiz]** — matcode'un LZMA kompresörü; DIE imzası mevcut; OS X için gdbinit'in mpress_dumper'ı var → §A5
- **NSPack** — **[KAPALI, ölü]** — eski Çin menşeli packer; imzaları her detektörde
- **FSG / MEW SE / UPack / Petite / tElock / RLPack / WWPack / Neolite / eXPressor / SVKP / Morphine / Yoda Crypter / PECrypt** — **[KAPALI, ölü]** — 2000'ler mini-packer'ları; PEiD/DIE miras imzalarıyla tanınır
- **hXOR-Packer** — **[AÇIK]** — [akuafif/hXOR-Packer](https://github.com/akuafif/hXOR-Packer); Huffman+XOR PE packer (unprotect.it kayıtlı)
- **Alternate EXE Packer** — **[KAPALI, ücretsiz]** — Alternatif software; basit LZMA sarmalayıcı
- **Sentinel HASP Envelope** (Thales/SafeNet) — **[KAPALI]** — donanım anahtarlı lisans zarfı
- **CodeMeter** (Wibu) — **[KAPALI]** — donanım tabanlı koruma + zarf

## 5) Oyun DRM / Disk Koruması / Anti-Tamper (PE zarfı yazarları)

- **SteamStub / CEG** (Valve) — **[KAPALI]** — Steam DRM zarfı + Custom Executable Generation anti-tamper; kırıcı: [atom0s/Steamless](https://github.com/atom0s/Steamless) (**5215★**) → §A6
- **Denuvo Anti-Tammer** (Denuvo Irdeto) — **[KAPALI]** — oyun endüstrisi anti-tamper'i; resmî GitHub org'unda **GAMBA + SiMBA** (MBA sadeleştirme araçları!) — [DenuvoSoftwareSolutions](https://github.com/DenuvoSoftwareSolutions) → §A6
- **SecuROM** (Sony DADC) — **[KAPALI, ölü]** — disc-check DRM zarfı; modern Windows'ta çalıştırma: nckstwrt/SecuROMLoader → §A6
- **SafeDisc** (Macrovision) — **[KAPALI, ölü]** — sektör koruması zarfı (secdrv sürücüsü kapatıldı); SafeDiscShim/SafeDiscLoader2 ile uyumluluk → §A6
- **SolidShield / Tages** — **[KAPALI, ölü]** — disk DRM zarfları; yalnız crack toplulukları
- **Anti-cheat sürücüleri** (EAC, BattlEye, XIGNCODE3, nProtect GameGuard, HackShield, mhyprot2, Tencent ACE, Vanguard) — **[KAPALI]** — packer değil kernel koruması; araştırma repoları → §A6.2; liste: [AreWeAntiCheatYet](https://areweanticheatyet.com/), [PCGamingWiki anti-cheat listesi](https://www.pcgamingwiki.com/wiki/List_of_games_with_anti-cheat_technology)

## 6) Açık Kaynak Native Packer / Protector / Crypter / Obfuscator'lar

- **UPX** — **[AÇIK]** — [upx/upx](https://github.com/upx/upx) (18.032★); `upx -d` resmî unpacker — **teknik olarak "korumasız" paketleyici**
- **obfus.h** — **[AÇIK]** — [DosX-dev/obfus.h](https://github.com/DosX-dev/obfus.h) (1889★, 2026-11'de aktif); derleme-zamanı C polimorfik obfuscation (tcc, x86/x64); karşısı: ObfusHunter/ObfusFake-Signatures-Remover → §A16
- **obfusheader.h** — **[AÇIK]** — [ac3ss0r/obfusheader.h](https://github.com/ac3ss0r/obfusheader.h) (1071★); taşınabilir C++14 compile-time obfuscation başlığı
- **es3n1n/obfuscator** — **[AÇIK]** — [es3n1n/obfuscator](https://github.com/es3n1n/obfuscator) (865★); PE (ve ELF) **bin2bin obfuscator** — sahne standardı
- **pe-union** — **[AÇIK]** — [bytecode77/pe-union](https://github.com/bytecode77/pe-union) (742★); native + .NET stub'lı crypter/binder/downloader
- **Ryujin Protector** — **[AÇIK]** — [keowu/Ryujin](https://github.com/keowu/Ryujin) (355★); Intel BIN2BIN PE obfuscation/protection/DRM
- **Astral-PE** — **[AÇIK]** — [DosX-dev/Astral-PE](https://github.com/DosX-dev/Astral-PE) (359★); header/EP düşük-seviye mutator (x32/x64)
- **ASM-Guard** — **[AÇIK]** — [DosX-dev/ASM-Guard](https://github.com/DosX-dev/ASM-Guard) (272★); native kod sıkıştırma + ters-mühendislik zorlaştırma
- **rewolf-x86-virtualizer** — **[AÇIK]** — [rwfpl/rewolf-x86-virtualizer](https://github.com/rwfpl/rewolf-x86-virtualizer) (376★); VM tabanlı x86 PE protector (klasik)
- **TinyLoad** — **[AÇIK]** — [iamsopotatoe-coder/TinyLoad](https://github.com/iamsopotatoe-coder/TinyLoad) (208★, 2026); x64 PE packer+crypter — **kendi VM'iyle** (LZMA+şifreleme)
- **Obsidian Protector** — **[AÇIK]** — [vertigo6622/obsidian-protector](https://github.com/vertigo6622/obsidian-protector); ARM64 + PyInstaller destekli tam özellikli protector (2026'da aktif)
- **Nocturne** — **[AÇIK]** — [nodiuus/nocturne](https://github.com/nodiuus/nocturne) (180★, 2026-11'de aktif); x86-64 PE **bin2bin code virtualizer**
- **KiteShield** — **[AÇIK]** — [GunshipPenguin/kiteshield](https://github.com/GunshipPenguin/kiteshield) (247★); Linux x86-64 ELF packer/protector
- **Maya** — **[AÇIK]** — [elfmaster/maya](https://github.com/elfmaster/maya) (162★); Linux ELF anti-exploit/anti-tamper protector
- **x0rro** — **[AÇIK]** — [phra/x0rro](https://github.com/phra/x0rro) (137★); Radare2 tabanlı PE/ELF/MachO crypter
- **YAP** — **[AÇIK]** — [undisassemble/yap](https://github.com/undisassemble/yap); x86-64 Windows PE protector (2026'da aktif)
- **PEP** — **[AÇIK]** — [NIKJOO/PEP](https://github.com/NIKJOO/PEP) (157★); "private exe protector"
- **chum** — **[AÇIK]** — [jonomango/chum](https://github.com/jonomango/chum) (107★); 64-bit PE binary rewriter
- **BinProtect** — **[AÇIK]** — [noahware/binprotect](https://github.com/noahware/binprotect) (360★, 2025-11'de doğdu); **bölüm eklemeyen** x64 PE bin2bin obfuscator
- **kagura** — **[AÇIK]** — [qusamulab/kagura](https://github.com/qusamulab/kagura) (51★, 2026'da aktif); LLVM pass plugin — CFG flattening + string şifreleme + **VM virtualization** + anti-tamper
- **XopProtector** — **[AÇIK]** — [xopJack/XopProtector](https://github.com/xopJack/XopProtector) (263★, 2026-11'de aktif); Android APK protector (DEX şifreleme + native shell + VMP + anti-debug)
- **NovaProtect** — **[AÇIK]** — [sudfiona/NovaProtect](https://github.com/sudfiona/NovaProtect) (64★, 2026); "ücretsiz koruma" hedefli açık kaynak packer
- **zhidun (智盾)** — **[AÇIK]** — [zhidun2027/zhidun](https://github.com/zhidun2027/zhidun) (74★, 2026-11'de aktif); Android DEX şifreleme + native shell + anti-tamper (dokümante)
- **AlushPacker** — **[AÇIK]** — [Alon-Alush/AlushPacker](https://github.com/Alon-Alush/AlushPacker); manuel loader'lı PE packer
- **WVmp** — **[AÇIK]** — [mikasaw/wvmp](https://github.com/mikasaw/wvmp); x86/x64 PE VM protector araştırması (2026)
- **JitDecrypter / Nanomites** — **[AÇIK]** — [Fatmike-GH](https://github.com/Fatmike-GH/JitDecrypter) ve [Nanomites](https://github.com/Fatmike-GH/Nanomites) koruma teknikleri
- **hm-pe-packer / GreyM / Kryptonite / PE-Crypter / NullCrypt** — **[AÇIK]** — [TheAenema/hm-pe-packer](https://github.com/TheAenema/hm-pe-packer) (52★), [greyb1t/GreyM](https://github.com/greyb1t/GreyM) (43★), [ximerus/Kryptonite](https://github.com/ximerus/Kryptonite) (32★), [jozemberi/PE-Crypter](https://github.com/jozemberi/PE-Crypter) (164★), [0xNullSec/NullCrypt](https://github.com/0xNullSec/NullCrypt) (22★, 2026; Rust crypter)
- **nimcrypt** — **[AÇIK]** — [icyguider/nimcrypt](https://github.com/icyguider/nimcrypt) (102★); Nim ile yazılmış PE crypter
- **pe-protector / IMProtector / CompotProtector** — **[AÇIK]** — [ATsahikian/pe-protector](https://github.com/ATsahikian/pe-protector) (53★), [Souhardya/IMProtector](https://github.com/Souhardya/IMProtector), [aronpaaul/CompotProtector](https://github.com/aronpaaul/CompotProtector)
- **BatchToApp / NET-MalwareCryptor** — **[AÇIK]** — [DosX-dev/BatchToApp](https://github.com/DosX-dev/BatchToApp) (174★; bat→exe+obfuscation), [DosX-dev/NET-MalwareCryptor](https://github.com/DosX-dev/NET-MalwareCryptor) (128★; eski .NET packer)
- **Protectors (koleksiyon)** — **[AÇIK]** — [rootm0s/Protectors](https://github.com/rootm0s/Protectors) (521★); obfuscator/şifreleme/junk/anti-debug PE modifikasyon derlemesi
- **GoDefender** — **[AÇIK]** — [KiExitDispatcher/GoDefender](https://github.com/KiExitDispatcher/GoDefender) (854★); Go için anti-VM/anti-debug/anti-sandbox kütüphanesi (koruma tarafı)
- **CVM (cvm.h)** — **[AÇIK]** — [ac3ss0r/cvm.h](https://github.com/ac3ss0r/cvm.h) (37★); header-only Turing-complete VM motoru — kendi VM protector'unu yazmak için temel

## 7) LLVM / Derleyici Obfuscator'ları (native)

- **O-LLVM** — **[AÇIK]** — [obfuscator-llvm/obfuscator](https://github.com/obfuscator-llvm/obfuscator) (4398★, arşiv); CFF/bogus/opaque efsanesi
- **Hikari** — **[AÇIK]** — [HikariObfuscator/Hikari](https://github.com/HikariObfuscator/Hikari) (2101★); portlar: [Hikari-fix](https://github.com/PPKunOfficial/Hikari-fix) (2026'da aktif), [Aethereux/Hikari-LLVM19](https://github.com/Aethereux/Hikari-LLVM19) (152★, **LLVM 19-20**), [ChandHsu/Hikari-LLVM15](https://github.com/ChandHsu/Hikari-LLVM15), [Lessica/HikariSummer](https://github.com/Lessica/HikariSummer) (LLVM 12), [Equati0n/Hikari-LLVM15.0.2](https://github.com/Equati0n/Hikari-LLVM15.0.2)
- **Pluto** — **[AÇIK]** — [bluesadi/Pluto-Obfuscator](https://github.com/bluesadi/Pluto-Obfuscator) (916★); LLVM 14
- **Armariris** — **[AÇIK]** — [GoSSIP-SJTU/Armariris](https://github.com/GoSSIP-SJTU/Armariris) (1348★); Şanghay Jiao Tong
- **goron** — **[AÇIK]** — [amimo/goron](https://github.com/amimo/goron) (719★)
- **ollvm17 / ollvm16 / ollvm-16 / ollvm-pass** — **[AÇIK]** — [DreamSoule/ollvm17](https://github.com/DreamSoule/ollvm17) (676★, LLVM 17), [DreamSoule/ollvm16](https://github.com/DreamSoule/ollvm16) (94★), [wwh1004/ollvm-16](https://github.com/wwh1004/ollvm-16) (271★), [lich4/ollvm-pass](https://github.com/lich4/ollvm-pass) (102★; bağımsız Hikari pass'i)
- **xollvm** — **[AÇIK]** — [und3ath/xollvm](https://github.com/und3ath/xollvm) (206★, 2026-11'de aktif); "Modern LLVM Obfuscator"
- **morok** — **[AÇIK]** — [19h/morok](https://github.com/19h/morok) (109★, 2026-11'de aktif); modüler C++23 LLVM New-PM IR obfuscator (pass plugin)
- **eshard obfuscator-llvm** — **[AÇIK]** — [eshard/obfuscator-llvm](https://github.com/eshard/obfuscator-llvm) (415★, 2026-10'da aktif); eShard'ın (D-810 yazarı) LLVM obfuscation pass'i
- **amice** — **[AÇIK]** — [fuqiuluo/amice](https://github.com/fuqiuluo/amice) (289★, 2026-11'de aktif); Rust/C/C++/Android — **instruction-level VMP / code virtualization** (LLVM 11–23!)
- **Polaris** — **[AÇIK]** — [za233/Polaris-Obfuscator](https://github.com/za233/Polaris-Obfuscator) (572★; 2026'da aktif)
- **DeClang** — **[AÇIK]** — [DeNA/DeClang](https://github.com/DeNA/DeClang) (503★)
- **O-MVLL** — **[AÇIK]** — [open-obfuscator/o-mvll](https://github.com/open-obfuscator/o-mvll) (1192★); Android/iOS NDK
- **dProtect** — **[AÇIK]** — [open-obfuscator/dProtect](https://github.com/open-obfuscator/dProtect) (418★); ProGuard tabanlı Java/Kotlin obfuscator (O-MVLL ekibinden)
- **ROPfuscator** — **[AÇIK]** — [ropfuscator/ropfuscator](https://github.com/ropfuscator/ropfuscator) (442★); ROP tabanlı obfuscation
- **dittobytes** — **[AÇIK]** — [tijme/dittobytes](https://github.com/tijme/dittobytes) (656★); metamorfik C/C++ → PIC/BOF
- **lyra** — **[AÇIK]** — [hakaioffsec/lyra](https://github.com/hakaioffsec/lyra) (32★, 2026); Rust için LLVM IR obfuscator
- **kilij** — **[AÇIK]** — [dannyisbad/kilij](https://github.com/dannyisbad/kilij) (51★, 2026); LLVM 20 — 12 IR pass + **bytecode VM (3 çalışma modu)**
- **LeetObfuscator / Taokari / Himitsu / A2MBA** — **[AÇIK]** — [Zydak/LeetObfuscator](https://github.com/Zydak/LeetObfuscator) (45★), [hutaoshusband/Taokari-LLVM](https://github.com/hutaoshusband/Taokari-LLVM) (9★; MIR virtualization araştırması), [HimitsuShell/HimitsuObfuscator](https://github.com/HimitsuShell/HimitsuObfuscator) (14★; GPL-free LLVM 17), [xqzme69/A2MBA-LLVM](https://github.com/xqzme69/A2MBA-LLVM) (34★; MBA sağlamlaştırma pass'i)
- **ollvm-rust / VM_Garble** — **[AÇIK]** — [0xlane/ollvm-rust](https://github.com/0xlane/ollvm-rust) (207★; rustc'ye yüklenebilir obfuscation pass'i), [NIKJOO/VM_Garble](https://github.com/NIKJOO/VM_Garble) (10★, 2026; Go binary virtualization)
- **Obscura** — **[AÇIK]** — [assemblew/Obscura](https://github.com/assemblew/Obscura) (54★, 2026); "Hikari + O-MVLL'in yeni çağı" — C/C++/ObjC/Swift
- **Arkari** — **[KAPALI, ücretli]** — [joydo/Arkari](https://github.com/joydo/Arkari) (goron tabanlı ticari LLVM obfuscator; GitHub sayfası tanıtım)
- **Tigress** — **[AÇIK]** — akademik obfuscator ([tigress.cs.arizona.edu](https://tigress.cs.arizona.edu)); kırma çalışması: [JonathanSalwan/Tigress_protection](https://github.com/JonathanSalwan/Tigress_protection) (932★) → §A14
- **movfuscator** — **[AÇIK]** — [xoreaxeaxeax/movfuscator](https://github.com/xoreaxeaxeax/movfuscator) (10.595★); "tek instruction" derleyici; karşısı: demovfuscator → §A14
- **garble / gobfuscate** — **[AÇIK]** — [burrowers/garble](https://github.com/burrowers/garble) (5840★), [unixpickle/gobfuscate](https://github.com/unixpickle/gobfuscate) (1573★); Go obfuscator
- **Crash0v3rrid3/obscura (JS)** — **[AÇIK]** — [Crash0v3rrid3/obscura](https://github.com/Crash0v3rrid3/obscura) (16★, 2026); javascript-obfuscator'ın Rust portu (21 transform, ~700x hızlı)
- Kaynak listesi: **[lich4/awesome-ollvm](https://github.com/lich4/awesome-ollvm)** (67★) — "(gerçekten) awesome OLLVM'ler" kataloğu

## 8) .NET Obfuscator / Protector'ları

**Açık kaynak:**
- **ConfuserEx** — **[AÇIK]** — [yck1509/ConfuserEx](https://github.com/yck1509/ConfuserEx) (3761★, arşiv) + aktif fork [mkaring/ConfuserEx](https://github.com/mkaring/ConfuserEx) (2915★)
- **ConfuserEx 2 / ConfuserEx3 / ConfuserNext** — **[AÇIK]** — [mkaring/ConfuserEx](https://github.com/mkaring/ConfuserEx) (2.x hattı), [BC-SECURITY/ConfuserEx3](https://github.com/BC-SECURITY/ConfuserEx3) (2026'da yeni), [dib0/ConfuserNext](https://github.com/dib0/ConfuserNext) (2026-11'de aktif; .NET Framework için modern devam)
- **KoiVM** (+DarksVM/CawkVM modları) — **[AÇIK]** — [yck1509/KoiVM](https://github.com/yck1509/KoiVM) (119★), [0x25bit/KoiVM-modded](https://github.com/0x25bit/KoiVM-modded) (DarksVM), [Trollicus/KoiVM](https://github.com/Trollicus/KoiVM) (mod), CawkVM (ConfuserEx VM varyantı; unpacker: ElektroKill/CawkVM-Unpacker 79★); devirt: OldRod → §A7
- **BitMono** — **[AÇIK]** — [bitmono-project/BitMono](https://github.com/bitmono-project/BitMono) (581★; 2026'da aktif)
- **Obfuscar** — **[AÇIK]** — [obfuscar/obfuscar](https://github.com/obfuscar/obfuscar) (3232★)
- **Hydra** — **[AÇIK]** — [DestroyerDarkNess/Hydra](https://github.com/DestroyerDarkNess/Hydra) (54★); dnlib/AsmResolver tabanlı
- **obfuz** — **[AÇIK]** — [focus-creative-games/obfuz](https://github.com/focus-creative-games/obfuz) (844★); Unity/HybridCLR
- **Mdcrypt** — **[AÇIK]** — [wwh1004/Mdcrypt](https://github.com/wwh1004/Mdcrypt) (45★, WIP); "yeni nesil .NET protector"
- **AstroNet** — **[AÇIK]** — [lckt0/AstroNet](https://github.com/lckt0/AstroNet) (26★); dnlib + modded KoiVM
- **MurkyStrings** — **[AÇIK]** — [dr4k0nia/MurkyStrings](https://github.com/dr4k0nia/MurkyStrings) (109★); .NET string obfuscator
- **Origami** — **[AÇIK]** — [dr4k0nia/Origami](https://github.com/dr4k0nia/Origami) (177★); PE formatını istismar eden .NET packer
- **Confuser.Protections.HoLLy** — **[AÇIK]** — [holly-hacker/Confuser.Protections.HoLLy](https://github.com/holly-hacker/Confuser.Protections.HoLLy) (68★); ConfuserEx için ek korumalar
- **Anti-De4dot** — **[AÇIK, anti-araç]** — [fl2on/Anti-De4dot](https://github.com/fl2on/Anti-De4dot) (35★); de4dot'a karşı korunma — dedektör/test tarafı için negatif varyant üreticisi
- **BeeByte** (Unity Asset Store) — **[LEAKED]** — şirketi kapandı; kaynak paylaşımı: [TouMobSiab/BeeByte-Obfuscation-Source-Code-](https://github.com/TouMobSiab/BeeByte-Obfuscation-Source-Code-) (21★); kırıcıları beeless/OsOmE1 → §A7

**Kapalı kaynak:**
- **.NET Reactor** (Eziriz) — **[KAPALI]** — en yaygın ticari; kırıcı: NETReactorSlayer (1286★) → §A7
- **IntelliLock** (Eziriz) — **[KAPALI]** — lisans odaklı kardeşi
- **Dotfuscator** (PreEmptive) — **[KAPALI]** — VS Community sürümü dağıtılır; de4dot desteği
- **Eazfuscator.NET** — **[KAPALI]** — EazFixer/EazyDevirt ile devirt → §A7
- **SmartAssembly** (Redgate) — **[KAPALI]** — de4dot tanıması mevcut
- **Crypto Obfuscator** (LogicNP) — **[KAPALI, terk]**
- **Babel Obfuscator** — **[KAPALI]** — aktif ticari (babelfor.net)
- **Agile.NET / CliSecure** (SecureTeam) — **[KAPALI]** — AgileDotNetSlayer + devirtualizer → §A7
- **Spices.Net** — **[KAPALI]** — 9rays, eski
- **DeepSea Obfuscator** — **[KAPALI, ölü]**
- **Goliath.NET** — **[KAPALI]** — VM tabanlı, kapalı dağıtım
- **Xenocode Postbuild / Salamander .NET** — **[KAPALI, ölü]** — 2000'ler sonunun klasiği
- **Phoenix Protector** (NTCore) — **[KAPALI]** — ücretsiz sürümü var, kaynak yok
- **DotKill** — **[KAPALI]** — unpacker'ı meşhur (lckt0/DotKill-Unpacker 155★) → §A7
- **NetZ** — **[KAPALI, ölü]** — 2000'ler .NET packer'ı (kaynak yok, tarihî)

## 9) Java Obfuscator/Protector + Android Ticari Sağlamlaştırma (加固)

**Java (JVM):**
- **ProGuard** — **[AÇIK]** — [Guardsquare/proguard](https://github.com/Guardsquare/proguard); R8 Android Gradle varsayılanı ([preemptive/r8-docs](https://github.com/preemptive/r8-docs) gayriresmî dokümantasyon)
- **yGuard** — **[AÇIK]** — [yWorks/yguard](https://github.com/yWorks/yguard)
- **Allatori** — **[KAPALI]** — ucuz ticari jar obfuscator; **v3.0 kaynağı sızdı**: [netindev/Allatori-v3.0](https://github.com/netindev/Allatori-v3.0) (53★, 2016) + crack: [lqs1848/AllatoriCrack](https://github.com/lqs1848/AllatoriCrack) (307★) + 2026 dalga: [Skid-Technology/OpenAllatori](https://github.com/Skid-Technology/OpenAllatori) (14★, "9.9 sürümü")
- **Zelix KlassMaster (ZKM)** — **[KAPALI]** — eski güçlü flow obfuscator; **v27'ye kadar kırıcılar 2026'da çıktı** (zkm-deobfuscator, ZKM-27-Full-Deobfuscator, OpenZKM) → §A8
- **Stringer Java Obfuscator** — **[KAPALI]** — string şifreleme odaklı
- **DashO** (PreEmptive) — **[KAPALI]** — Android/Java ticari; örnekler: [preemptive/dasho-samples](https://github.com/preemptive/dasho-samples)
- **JNIC** — **[KAPALI, ücretli]** — Java→native derleme obfuscator'u; açık klonlar: [nuym/j2c](https://github.com/nuym/j2c) (45★), [MyJ2c/Open-MyJ2c](https://github.com/MyJ2c/Open-MyJ2c) (45★); "fake" sürüm skandalı: [YumeGod/OpenMyJ2C](https://github.com/YumeGod/OpenMyJ2C) (48★); leaked: [Skid-Technology/OpenJNIC](https://github.com/Skid-Technology/OpenJNIC) (38★, "3.7.0")
- **Binsecure** — **[KAPALI]** — sahne obfuscator'u; 1.8.3 sürümü depoda: [Astra-520/Binsecure-1.8.3](https://github.com/Astra-520/Binsecure-1.8.3)
- **kboxObfuscator** — **[KAPALI, 2026]** — "ZKM seviyesi" Java bytecode protector (JNIC native + VMP + native master-key); [kboxcbh1337/kboxObfuscator](https://github.com/kboxcbh1337/kboxObfuscator) (23★)
- **DexGuard** (Guardsquare) — **[KAPALI]** — Android ticari ağabey; gradle-plugin araştırması: [Ivonhoe/DexGuard](https://github.com/Ivonhoe/DexGuard) (271★)

**Android Çin/Ticari sağlamlaştırma (加固) ailesi:**
- **Bangcle (梆梆)** — **[KAPALI]** — 2 nesil Android hardening; araştırma: [KuNgia09/Bangcle](https://github.com/KuNgia09/Bangcle) (407★), [ylcangel/crack_dexhelper](https://github.com/ylcangel/crack_dexhelper) (507★)
- **Ijiami (爱加密)** — **[KAPALI]** — popüler Çin hardening'i; tespit+dump scripti: [Alexjr2/Android_Dump_Dex](https://github.com/Alexjr2/Android_Dump_Dex) (89★)
- **360 Jiagu (360加固)** — **[KAPALI]** — Qihoo sağlamlaştırması; unpacker: ApkShelling/JiaguCleaner → §A9
- **Tencent Legu (乐固)** — **[KAPALI]** — unpacker: [quarkslab/legu_unpacker_2019](https://github.com/quarkslab/legu_unpacker_2019) (214★)
- **Baidu Jiagu (百度加固)** — **[KAPALI]** — unpacker: [OakChen/ApkShelling](https://github.com/OakChen/ApkShelling) (460★; 4 sağlamlaştırıcıyı birden söker)
- **SecNeo** — **[KAPALI]** — Çin hardening; BlackDex/FART ile çözülür → §A9
- **Virbox Protector** (深思数盾) — **[KAPALI]** — Çin DRM+protector (PE+Android+more); aarch64 runtime unpacker: [msuiche/vmunprotect-aarch64](https://github.com/msuiche/vmunprotect-aarch64)
- **NetEase Yidun (网易易盾)** — **[KAPALI]** — NetEase sağlamlaştırma/anti-bot
- **Dingxiang (顶象)** — **[KAPALI]** — Çin hardening
- **Kiwi (几维安全)** — **[KAPALI]** — Çin SO+DEX koruması
- **Payegis (通付盾)** — **[KAPALI]** — 1. nesil kaynağı açık: [wanchouchou/ApkProtect](https://github.com/wanchouchou/ApkProtect) (185★, 2015)
- **Naga (娜迦)** — **[KAPALI]** — eski nesil Çin hardening'i
- **LIAPP** (Kore) — **[KAPALI]** — bypass PoC: [Assasans/konofd-client-stub](https://github.com/Assasans/konofd-client-stub) (11★)
- **AppGuard / AppSealing / Promon SHIELD / Arxan** — **[KAPALI]** — Kore/Avrupa mobil koruma ailesi
- **DexProtector** — **[KAPALI]** — güçlü Android protector; araştırma: [romainthomas/dexprotector](https://github.com/romainthomas/dexprotector) (97★, 2025-12) → §A9

## 10) JavaScript / TypeScript

- **javascript-obfuscator (obfuscator.io)** — **[AÇIK]** — [javascript-obfuscator/javascript-obfuscator](https://github.com/javascript-obfuscator/javascript-obfuscator) (16.346★); karşı taraf: webcrack/synchrony → §A10
- **JS-Confuser** — **[AÇIK]** — [MichaelXF/js-confuser](https://github.com/MichaelXF/js-confuser) (527★) + deneysel VM modu [js-confuser-vm](https://github.com/MichaelXF/js-confuser-vm) (24★); kırıcıları → §A10
- **JSDefender** (PreEmptive) — **[KAPALI]** — JS koruma ürünü; demo kırıcıları: 0v41n/JSDefender-Deobfuscator (42★) → §A10
- **JScrambler** — **[KAPALI]** — kurumsal SaaS obfuscator; Enterprise kırıcı: Ciarands/jscrambler-deobfuscator (65★) → §A10
- **JSFuck** — **[AÇIK]** — [aemkei/jsfuck](https://github.com/aemkei/jsfuck) (8604★); 6 karakterle JS
- **Luraph** — **[KAPALI]** — LuaU/JS SaaS obfuscator
- **Paranoid** — **[KAPALI]** — Paranoid Technologie'nin protector'u; kırıcı: giacomoferretti/paranoid-deobfuscator (91★) → §A10
- **JSVMP (ByteDance/Alibaba anti-bot VM'leri)** — **[KAPALI]** — 抖音/阿里 jsvmp interpreter'ları + **Ruishu (瑞数)** dinamik JS koruması — web anti-bot sahası; RE örnekleri: [0xAllenChen/spider_reverse](https://github.com/0xAllenChen/spider_reverse) (948★), [Charles-Hello/-228-](https://github.com/Charles-Hello/-228-) (170★)
- **hercules-obfuscator** — **[AÇIK]** — [zeusssz/hercules-obfuscator](https://github.com/zeusssz/hercules-obfuscator) (238★); Lua obfuscator (Roblox sahnesi)

## 11) Python

- **PyArmor** — **[YARI-AÇIK]** — [dashingsoft/pyarmor](https://github.com/dashingsoft/pyarmor) (5231★); CLI açık, **çekirdek kapalı** (freemium); kırıcıları → §A11
- **Nuitka** — **[AÇIK]** — derleyici (protector değil); statik kurtarma araçları → §A11
- **PyInstaller / pyz** — **[NOT: koruma değil paketleme]** — unpacker'ları §A11'de
- **PjOrion** — **[KAPALI, ölü]** — eski Python obfuscator; deobf: [extremecoders-re/bytecode_simplifier](https://github.com/extremecoders-re/bytecode_simplifier) (127★)
- **BabyArmor / python-obfuscate / antidc** — **[AÇIK]** — [obaby/BabyArmor](https://github.com/obaby/BabyArmor) (6★; PyArmor mantığından ilham), [ViewTechOrg/python-obfuscate](https://github.com/ViewTechOrg/python-obfuscate) (6★; anti-pycdc), [Azim-Vau/antidc](https://github.com/Azim-Vau/antidc) (12★; anti-uncompyle6) — negatif test üreticileri

## 12) PHP

- **ionCube Encoder** — **[KAPALI]** — "decoder" iddialı sitelerin çoğu dolandırıcılık; güvenilir açık kaynak yok
- **SourceGuardian** — **[KAPALI]** — aynı durum
- **Zend Guard** — **[KAPALI]** — eski nesil; güvenilir decoder yok
- **phpBolt / Nu-Coder** — **[KAPALI]** — ikincil PHP encoder'lar; durum aynı

## 13) macOS / iOS

- **MachObfuscator** — **[AÇIK]** — [kam800/MachObfuscator](https://github.com/kam800/MachObfuscator) (543★); Apple platformları için Mach-O obfuscator
- **Hikari/Obscura iOS hattı** — **[AÇIK]** — [assemblew/Obscura](https://github.com/assemblew/Obscura) (ObjC/Swift); [not1cyyy/Hikari-LLVM19](https://github.com/not1cyyy/Hikari-LLVM19) pass'i
- **IOSSecuritySuite** — **[AÇIK]** — [securing/IOSSecuritySuite](https://github.com/securing/IOSSecuritySuite) (2756★); iOS anti-tamper/anti-debug kütüphanesi (koruma tarafı)
- **VMProtect macOS / Linux çıktıları** — **[KAPALI]** — VMP 3.10.6+ Mach-O/ELF destekleri (bkz. §1)

## 14) Packer/Protector TESPİT Araçları (bu projenin sahası)

- **Detect It Easy (DIE)** — **[AÇIK]** — [horsicq/Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy) (12.0k★; 3.21, Nisan 2026: 777 PE imzası) + [DIE-engine](https://github.com/horsicq/DIE-engine) (3378★)
- **Exeinfo PE** — **[AÇIK, resmî depo!]** — [ExeinfoASL/ASL](https://github.com/ExeinfoASL/ASL) (1164★) + [ExeinfoASL/Exeinfo](https://github.com/ExeinfoASL/Exeinfo) (197★) + [plugins](https://github.com/ExeinfoASL/plugins); userdb 4.469 imza (2026 ölçümü)
- **PEiD** — **[KAPALI, ölü; AÇIK Python portu]** — [packing-box/peid](https://github.com/packing-box/peid) (154★); YARA dönüşümü: PEiD_to_Yara → §A16
- **Manalyze** — **[AÇIK]** — [JusticeRage/Manalyze](https://github.com/JusticeRage/Manalyze) (1156★)
- **APKiD** — **[AÇIK]** — [rednaga/APKiD](https://github.com/rednaga/APKiD) (2641★); Android "PEiD"; C portu: [horsicq/CXAPKiD](https://github.com/horsicq/CXAPKiD) (2026-11!)
- **XAPKDetector** — **[AÇIK]** — [horsicq/XAPKDetector](https://github.com/horsicq/XAPKDetector) (695★); APK/DEX detektör
- **YARA kural setleri** — **[AÇIK]** — [Yara-Rules/rules](https://github.com/Yara-Rules/rules) (4966★), [fr0gger/Yara-Unprotect](https://github.com/fr0gger/Yara-Unprotect) (26★), [PackGenome](https://github.com/packgenome/PackGenome-Artifacts) (otomatik packer YARA üretimi, NDSS)
- **PE-LiteScan** — **[AÇIK]** — [DosX-dev/PE-LiteScan](https://github.com/DosX-dev/PE-LiteScan) (194★)
- **Packernoculars** — **[AÇIK]** — [GHFear/Packernoculars](https://github.com/GHFear/Packernoculars); Exe packer detector
- **PyPackerDetect** — **[AÇIK]** — [cylance/PyPackerDetect](https://github.com/cylance/PyPackerDetect) (35★) + bakımlı fork [packing-box/pypackerdetect](https://github.com/packing-box/pypackerdetect) (30★, 2026-10'da aktif)
- **bintropy** — **[AÇIK]** — [packing-box/bintropy](https://github.com/packing-box/bintropy) (52★); sıkıştırma/şifreleme olasılığı (entropi) analizi
- **PackiD** — **[AÇIK]** — [mesaleh/PackiD](https://github.com/mesaleh/PackiD) (12★); packer identification kütüphanesi
- **ObfusHunter** — **[AÇIK]** — [hACKCASCAC/ObfusHunter](https://github.com/hACKCASCAC/ObfusHunter) (28★, 2026); Obfus.h imzaları + anti-debug + PE koruma detektörü
- **ObfusFake-Signatures-Remover** — **[AÇIK]** — [hACKCASCAC/ObfusFake-Signatures-Remover](https://github.com/hACKCASCAC/ObfusFake-Signatures-Remover) (10★); **sahte VMProtect/Denuvo/Enigma imzalarını ayıklar** — negatif test üreticisi, bu projenin radarına giren bir tehdit
- **FindEXEC** — **[AÇIK]** — [DosX-dev/FindEXEC](https://github.com/DosX-dev/FindEXEC) (152★); EXE'leri NET/UPX/VMP... kategorilerine ayırır
- **apkshell** — **[AÇIK]** — [bin-maker/apkshell](https://github.com/bin-maker/apkshell) (164★); APK hangi ticari sağlamlaştırıcıyla paketlenmiş, tespit (Çince, güncel)
- **DRMDetector** — **[AÇIK]** — [iaski15/DRMDetector](https://github.com/iaski15/DRMDetector) (1★, 2026); oyun exe'lerinde Denuvo/VMP/Themida/UPX/SteamStub taraması
- **MVP GOD SSS TIER PACKER FINDER** — **[AÇIK, bu repo]** — VMProtect 3.0.9–3.10.4 sürüm + özellik + katman dedektörü; %100 kör test, ML yok

---

*Bu envanter `MVP_GOD_SSS_TIER_PACKER_FINDER` projesi için derlendi (v2, 26.11.2026). Araç listeleri, yıldız sıralamaları ve son 12 ayın çıkışları: **[ArastirmaList.md](ArastirmaList.md)***
