# ArastirmaList.md — Packer/Protector Araç Ekosistemi Araştırma Listesi (v2)

> **Amaç:** Listedeki HER packer için unpacker / devirtualizer / dumper / İAT-fixer / killer / deobfuscator repoları.
> **Metod:** GitHub REST API (`search/repositories` + `repos` + kullanıcı/org taramaları) — **260+ sorgu, 160+ yazar/org profil taraması, web doğrulaması**; 7.476 benzersiz repo tarandı, derlenenler burada.
> **Tüm yıldız sayıları ve tarihler API'den alınmıştır: 26.11.2026.** (Yıldızlar canlıdır, ~günlük değişir.)
> Etiketler: **[UNPACK]** **[DEVIRT]** **[DUMP/İAT]** **[KILL]** **[DEOBF]** **[DETECT]** **[SRC]** **[ARAŞTIRMA]**
> Packer envanteri (1 satır = 1 packer) → **[KnowedAlgorithm.md](KnowedAlgorithm.md)**
> Yasal not: araçlar yalnızca kendi yazılımlarınız / yetkili güvenlik araştırması içindir.

---

## İçindekiler

- A1) VMProtect · A2) Themida/WinLicense/CV · A3) Enigma · A4) Diğer ticari protector'lar (ASProtect, Safengine, StarForce, PELock, CrackProof, TVM, Milfuscator...) · A5) Klasik packer'lar (UPX & co) · A6) DRM/oyun zarfları + anti-cheat · A7) .NET · A8) Java · A9) Android sağlamlaştırma unpacking · A10) JavaScript · A11) Python · A12) PHP · A13) Go/Rust/Lua/Mach-O · A14) LLVM/native obfuscation + devirt · A15) Genel unpack/dump framework'leri · A16) Tespit + imza veritabanları · A17) KILL (anti-anti-analiz) · A18) Akademik devirt/deobf · A19) Son 12 ayın dalgası · A20) Kaynak durumu özeti · A21) Kaynaklar

---

## A1) VMProtect (2.x – 3.11) — ana sahamız

Güncel durum: VMProtect **aktif** — 3.10.5 (20.04.2026, **"statik unpackinge karşı koruma iyileştirmesi"**) → 3.10.6 (23.06.2026) → **3.11 (08.10.2026)**.
Bizim dedektör kapsamı: **3.0.9 → 3.10.4** (11 sürüm, 310 build, %100 kör test). 3.10.5+ cipa güncellemesi bekleniyor.

### A1.1 — Devirtualizasyon (statik/devirt)

| Repo | Yıldız | Son aktivite | Not |
|---|---|---|---|
| [can1357/NoVmp](https://github.com/can1357/NoVmp) | 2237 | 2021-08 | Efsane: VTIL tabanlı **statik devirt**, VMP x64 3.x — klasik referans; 2026 fork'u: [BUnipendix/AnimeNoVMP](https://github.com/BUnipendix/AnimeNoVMP) (3★, sağlamlaştırılmış) |
| [JonathanSalwan/VMProtect-devirtualization](https://github.com/JonathanSalwan/VMProtect-devirtualization) | 1556 | 2022-06 | Triton (sembolik yürütme) + LLVM ile saf fonksiyon devirt; blog yazısı repoda |
| [can1357/VTIL](https://github.com/can1357/VTIL) / [vtil-project/VTIL-Core](https://github.com/vtil-project/VTIL-Core) | 1630 | 2026-07 | NoVmp'nin çatısı: Virtual-machine Translation IR (resmî org reposu da aktif) |
| [wallds/NoVmpy](https://github.com/wallds/NoVmpy) | 441 | 2025-01 | NoVmp'nin Python portu (arşiv) |
| [fjqisba/VmpHelper](https://github.com/fjqisba/VmpHelper) | 424 | 2026-07 | **IDA eklentisi — VMP'yi decompile etmeye yardımcı**; aktif |
| [eversinc33/MogVMP](https://github.com/eversinc33/MogVMP) | 322 | 2026-07 | Remill + LLVM ile **VMP 3.0–3.5 → LLVM IR** lifti (arşiv; yazar aktif) |
| [archercreat/titan](https://github.com/archercreat/titan) | 166 | 2024-03 | VMProtect devirtualizer (+ [vm_jit](https://github.com/archercreat/vm_jit) PoC 127★; fork: [gmh5225/titan-1](https://github.com/gmh5225/titan-1) 75★) |
| [sunwm518/VMProtect-3-5-DEvirt](https://github.com/sunwm518/VMProtect-3-5-DEvirt) | 121 | 2023-01 | VMP 3.5 devirt çalışması |
| [VMProtectResearch/vmp2-devirtualization](https://github.com/VMProtectResearch/vmp2-devirtualization) | 99 | 2024-11 | **VMP 2.x** devirt |
| [lmy375/pinvmp](https://github.com/lmy375/pinvmp) | 147 | 2018-05 | PinVMP: Intel PIN tabanlı **sanallaştırılmış kod analizi yardımcısı** (Çince klasiği) |
| [sexyiam/VMPLift](https://github.com/sexyiam/VMPLift) | 70 | 2026-08 | **VMP 3.8–3.10** handler map/lift → IDA/Ghidra'da okunur; yeni nesil |
| [sh4m2hwz/devirt_vmp](https://github.com/sh4m2hwz/devirt_vmp) | 71 | 2023-03 | Python devirt |
| [Rasetsuu/vmp-devirt](https://github.com/Rasetsuu/vmp-devirt) | 67 | 2026-10 | Yeni devirt çalışması |
| [wul7chaos/vmp-reverse-skill](https://github.com/wul7chaos/vmp-reverse-skill) | 34 | 2026-09 | Devirt pipeline: dispatcher/handler dilimleme + iki nesil P-code IR (2026) |
| [banda59/VMP-devirtualize-project](https://github.com/banda59/VMP-devirtualize-project) | 35 | 2026-02 | Devirt laboratuvarı |
| [Fare9/Dragons-vs-VMs](https://github.com/Fare9/Dragons-vs-VMs) | 30 | 2026-10 | "Dragon Tales" ile VMP analizi notları/scripts (2026) |
| [aftermathlabs/vmp2](https://github.com/aftermathlabs/vmp2) | 133 | 2025-11 | VMP2 deobf tooling; orijinali `_xeroxz` @ [git.back.engineering](https://git.back.engineering/_xeroxz/vmp2); kardeş: [vmhook](https://github.com/aftermathlabs/vmhook) |
| [xtremegamer1/vmprofiler](https://github.com/xtremegamer1/vmprofiler) | 6 | 2022-12 | `_xeroxz` vmprofiler'ın (VMP3 handler profilleme) gayriresmî fork'u |
| [LLVMParty/TicklingVMProtect](https://github.com/LLVMParty/TicklingVMProtect) | 176 | 2021-09 | "Tickling VMProtect with LLVM" blog serisinin assetleri |
| [ilyida/vmp3-demo-devirt](https://github.com/ilyida/vmp3-demo-devirt) | 0 | 2026-11 | VMP 3 demo VM analizi (araştırma aşamasında) — kullanıcının önerdiği |
| [etormadiv/devirtualizeme32_vmp_3.0.9_v2](https://github.com/etormadiv/devirtualizeme32_vmp_3.0.9_v2) | 17 | 2018-10 | devirt.me meydan okuması — **VMP 3.0.9** özel (32-bit) |
| [godfearingman/thresh](https://github.com/godfearingman/thresh) | 10 | 2026-11 | vmprotect devirtualiser (yeni) |
| [cockmanreal/VMP_DEVIRT](https://github.com/cockmanreal/VMP_DEVIRT) | 3 | 2026-11 | SMT sembolik yürütme + derleyici odaklı devirt — VMP 3.x 64-bit + Themida |
| [xiaoyu777-coder/Devirtualization-Vmp-Sample](https://github.com/xiaoyu777-coder/Devirtualization-Vmp-Sample) | 8 | 2026-10 | **VMP 3.10.4** handler izleme araştırması (LLVM lift YOK, saf handler) |
| [wul7chaos](https://github.com/wul7chaos) / [yx-storehouse/vmp-devirt-research](https://github.com/yx-storehouse/vmp-devirt-research) | 0–34 | 2026-11 | VMP+Themida handler→IR early-stage araştırmalar |
| [SecurityResearchStaff/vmp2.0.4](https://github.com/SecurityResearchStaff/vmp2.0.4) | 2 | 2017-06 | **VMP 2.0.4** handler/DispatchTable analiz notları (Çince; kaynak kod DEĞİL) |
| [mrexodia/VMProtectTest](https://github.com/mrexodia/VMProtectTest) | 44 | 2023-02 | VMP korumalı test binary'leri (x64dbg yazarından) |
| [wanttobeno/vmp3.2crack](https://github.com/wanttobeno/vmp3.2crack) | 31 | 2018-10 | VMP 3.2 lisans analizi (Çince; **kaynak değil**, telif araştırması) |

### A1.2 — Unpacker / Dumper / İAT onarımı

| Repo | Yıldız | Son aktivite | Not |
|---|---|---|---|
| [colby57/vid](https://github.com/colby57/vid) | 598 | 2026-08 | x86/x64 **import kurtarma + PE yeniden inşa**; aktif, güçlü |
| [x86rc/vmp-lazy-unpack](https://github.com/x86rc/vmp-lazy-unpack) | 500 | 2026-11-17 | Son dönemin en popüler yeni VMP unpacker'ı (unthemidator yazarından) |
| [void-stack/VMUnprotect](https://github.com/void-stack/VMUnprotect) | 508 | 2023-04 | VMP sanallaştırılmış metot çağrılarını dinamik loglar/manipüle eder (ana repo) |
| [0xnobody/vmpdump](https://github.com/0xnobody/vmpdump) | 1452 | 2020-11 | **Dinamik VMP dumper + import fixer (VTIL tabanlı)** — kaçırılmaması gereken klasik; orijinali can1357: [can1357/vmpdump](https://github.com/can1357/vmpdump) (45★) |
| [0xnobody/vmpattack](https://github.com/0xnobody/vmpattack) | 472 | 2021-05 | VMP → VTIL lifter (aynı yazarın NoVmp öncesi araçları) |
| [void-stack/VMUnprotect.Dumper](https://github.com/void-stack/VMUnprotect.Dumper) | 470 | 2022-08 | **.NET** VMProtect dumper (arşiv) |
| [mike1k/VMPImportFixer](https://github.com/mike1k/VMPImportFixer) | 389 | 2021-08 | Import Protection fix'leyici klasik |
| [KuNgia09/vmp3-import-fix](https://github.com/KuNgia09/vmp3-import-fix) | 324 | 2023-12 | VMP3 İAT fix (Çince; videolu anlatımlı) |
| [notsnakesilent/VMPStatic](https://github.com/notsnakesilent/VMPStatic) | 180 | 2026-09 | **Go ile statik unpacker — VMP 1.x–3.x** + PE rebuild; aktif |
| [YuroGod/VMPStaticUnpacker](https://github.com/YuroGod/VMPStaticUnpacker) | 153 | 2026-07 | Statik unpacker — **VMP 3.9.5** desteği |
| [nblog/Vm2Import](https://github.com/nblog/Vm2Import) | 101 | 2023-04 | Unicorn emülasyonu ile İAT fix |
| [sudha2323/vmprotectunpacker](https://github.com/sudha2323/vmprotectunpacker) | 78 | 2025-07 | OEP kurtarma + orijinal binary restore |
| [keowu/birosca](https://github.com/keowu/birosca) | 45 | 2023-07 | **VMP 1.x–1.9x** dinamik unpack toolkit (OEP, PE fix, İAT, anti-debug bypass) |
| [PlaneJun/VMP-Import-Fix](https://github.com/PlaneJun/VMP-Import-Fix) | 62 | 2024-08 | VMP 3.X İAT decrypt (Çince) |
| [ReverseSec/vmpmylove](https://github.com/ReverseSec/vmpmylove) | 49 | 2026-11-07 | **Hedefi çalıştırmadan** unpack edilmiş VMP binary analizi |
| [Shhoya/MutantKiller](https://github.com/Shhoya/MutantKiller) | 49 | 2022-02 | VMP **Mutation** API fix |
| [whowould/VMProtect-Unpacker](https://github.com/whowould/VMProtect-Unpacker) | 40 | 2026-10-06 | Statik + runtime unpacker (kullanıcının önerdiği) |
| [archercreat/vmpfix](https://github.com/archercreat/vmpfix) | 38 | 2021-12 | Evrensel x86/x64 **VMP 2.0–3.x import fixer** |
| [crowbar-team/vmp-import-resolver](https://github.com/crowbar-team/vmp-import-resolver) | 34 | 2025-01 | **VMP 3.5+** dinamik import çözücü |
| [nelj14/vmprotect-dumper](https://github.com/nelj14/vmprotect-dumper) | 31 | 2026-04 | Payload çıkarıcı + İAT rekonstrüksiyonu; suspend-process tekniği |
| [bilka00/vmprotect_import_fixer](https://github.com/bilka00/vmprotect_import_fixer) | 15 | 2022-02 | İAT fixer — **3.0.9 → 3.5.0 aralığında test edildi** (korpusumuzla birebir örtüşür!) |
| [vdisasm/pas-vmp-glueimport](https://github.com/vdisasm/pas-vmp-glueimport) | 15 | 2017-06 | VMSweeper kurtardığı importları VMP dump'ına iliştirir (Pascal) |
| [milk-analyzer/vmpunpack](https://github.com/milk-analyzer/vmpunpack) | 20 | 2026-08 | Generic VMP/packer unpacker — patched-Wine hattı, x64 malware odaklı |
| [Lucyferek-nunu/vmp-unpacker](https://github.com/Lucyferek-nunu/vmp-unpacker) | 12 | 2026-08 | vmprotect unpacker + iat fixer (yeni) |
| [plisskien/VMProtect-3.x-Emulator-Memory-Dumper](https://github.com/plisskien/VMProtect-3.x-Emulator-Memory-Dumper) | 11 | 2026-11-07 | **Qiling/Unicorn emülatörü + bellek dumper** — VMP 3.x, 3.10.4'te test |
| [mizt0/vmp-iat-recovery-tool](https://github.com/mizt0/vmp-iat-recovery-tool) | 9 | 2023-07 | Rust İAT kurtarma |
| [whoamicrashh/VMProtectDumper](https://github.com/whoamicrashh/VMProtectDumper) | 2 | 2026-11-20 | Bellekten unpack: OEP yakalama + İAT (kullanıcının önerdiği; aktif) |
| [ghidrat/vmp-dumper](https://github.com/ghidrat/vmp-dumper) | 0 | 2026-11-01 | x64 import kurtarma + PE dumper — yeni |
| [Moosh43/destiny2-vmprotect-kit](https://github.com/Moosh43/destiny2-vmprotect-kit) | 8 | 2026-08 | VMP **de-mutate/de-thread** toolkit (Destiny 2 build özel) |
| [msuiche/vmunprotect-aarch64](https://github.com/msuiche/vmunprotect-aarch64) | 3 | 2026-10-22 | **Virbox/VMProtect korumalı aarch64 ELF** runtime unpacker (M. Suiche; Apple Silicon odaklı) |
| [ivanpotatoes/VMProtect-Resource-Extractor](https://github.com/ivanpotatoes/VMProtect-Resource-Extractor) | 4 | 2026-11-16 | Korumalı kaynak çıkarıcı — statik/emülasyon/x64dbg eklenti üçlüsü (yeni) |

### A1.3 — VMProtect .NET tarafı

| Repo | Yıldız | Son aktivite | Not |
|---|---|---|---|
| [void-stack/VMAttack](https://github.com/void-stack/VMAttack) | 227 | 2023-06 | .NET kod sanallaştırma araştırması |
| [DarkBullNull/VMP.NET-Kill](https://github.com/DarkBullNull/VMP.NET-Kill) | 217 | 2021-04 | .NET VMP unpack yardımcısı (arşiv) |
| [chramiq/de4vmp](https://github.com/chramiq/de4vmp) | 90 | 2026-03 | **vmp .net devirtualizer** — yeni |
| [CodeCrackerSND/VMProtectNoDelegates-.NET-](https://github.com/CodeCrackerSND/VMProtectNoDelegates-.NET-) | 8 | 2026-06 | .NET delegate temizleme |

### A1.4 — KILL: anti-anti-debug / anti-anti-VM (VMP özel)

| Repo | Yıldız | Son aktivite | Not |
|---|---|---|---|
| [strivexjun/XAntiDebug](https://github.com/strivexjun/XAntiDebug) | 697 | 2019-05 | "VMProtect 3.x anti-debug method improved" |
| [Adofyn1/VMPHide](https://github.com/Adofyn1/VMPHide) | 83 | 2026-09 | **VMP anti-VM + anti-debug bypass** (2026; ScyllaHide yaklaşımı) |
| [ivanpotatoes/KozDbg](https://github.com/ivanpotatoes/KozDbg) | 99 | 2026-11-17 | **x64dbg/x32dbg anti-anti-debug eklentisi — VMP 3.3.x–3.10.x profilleri**; kernel sürücü gerektirmez; çok yeni ve çok güçlü |
| [ivanpotatoes/KozVM](https://github.com/ivanpotatoes/KozVM) | 13 | 2026-11-17 | x64dbg **anti-anti-VM** eklentisi — aynı sürüm aralığı |
| [KonBuku/VMDOG](https://github.com/KonBuku/VMDOG) | 64 | 2024-12 | VMware spoof — **tüm VMP sürümlerini** ve güncel anti-VM'leri geçer |
| [nevioo1337/VMHide](https://github.com/nevioo1337/VMHide) | 31 | 2024-08 | VMP'nin VMWare/VMWare Tools tespitini user-mode API hook'la atlatır |
| [Ahora57/Unabomber](https://github.com/Ahora57/Unabomber) | 51 | 2023-06 | Anti-anti-debug araçlarını hata yoluyla tespit (VMP korumasına ilham) |
| [Ahora57/Baltica-29](https://github.com/Ahora57/Baltica-29) | 10 | 2023-06 | VMP anti-anti-VM geliştirilmiş |
| [Ahora57/VMP_UTIL](https://github.com/Ahora57/VMP_UTIL) | 31 | 2025-07 | VMP özellik PoC'leri |
| [Ahora57/troy_starr](https://github.com/Ahora57/troy_starr) | 9 | 2026-01 | ScyllaHide/SharpOD debugger PID sızıntısı |
| [Ahora57/import_wrapper_attack](https://github.com/Ahora57/import_wrapper_attack) | 4 | 2026-11-19 | **VMP 3.0–3.10.4 + Themida/WinLicense import mekanizmasına saldırı** PoC |
| [Ahora57/sexy_mead](https://github.com/Ahora57/sexy_mead) | 7 | 2024-08 | Oreans loader/SDK seçeneklerini bypass |
| [CatCaller/x64Dbg](https://github.com/CatCaller/x64Dbg) | 9 | 2026-03 | **VMP 3.10.3** anti-debug'ını geçecek şekilde modlanmış x64dbg |
| [CatCaller/TitanHide](https://github.com/CatCaller/TitanHide) | 7 | 2026-03 | TitanHide fork'u — **güncel VMP 3.10.3** için ayarlı |

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
| [UzawaReisaQwQ/codex-vmprotect-unpack-skill](https://github.com/UzawaReisaQwQ/codex-vmprotect-unpack-skill) | 6 | ChatGPT-Codex **VMP unpack skill** — "3.5.0–3.10.4 x64/x86" (2026-11; AI-ajan dalgası) |
| [7777lolonlyyou/VMProtect-LLM-SKILL](https://github.com/7777lolonlyyou/VMProtect-LLM-SKILL) | 5 | LLM tabanlı VMP/Themida/özel-VM devirt iş akışı skill'i (2026-11) |
| [abeinb/x64dbg-MCP-Plugin](https://github.com/abeinb/x64dbg-MCP-Plugin) | 22 | x64dbg MCP eklentisi (LyScript tabanlı) — **VMP unpack/anti-debug bypass senaryoları** için AI ajan bağlantısı |
| [github.com/topics/vmprotect](https://github.com/topics/vmprotect) | — | GitHub konu sayfası |
| `universalAllver.rar` (yerel) | — | Elimizde: 11 sürüm binary + **3.5.1 kaynak klasörü** |

**Diğer sürümlerin kaynağı yok:** API taraması (`vmprotect source`, `vmprotect 3.4/3.6/3.8/3.9 source`, `vmprotect leak`, `vmprotect in:name created:>2025-06-01`) yalnızca 3.5.1 aynaları buldu. 3.0.9–3.10.4 (3.5.1 hariç) için kaynak GitHub'da **mevcut değil**; crack dağıtan depolar kaynak içermez.

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
| [VenTaz/Themidie](https://github.com/VenTaz/Themidie) | 585 | 2026-11-22 | **x64dbg eklentisi — Themida 3.x anti-debug/VM/monitoring bypass (x64)**; fork'ları: [gmh5225/Themidie2](https://github.com/gmh5225/Themidie2) (28★), TopSoftdeveloper fork (4★) — Themida KILL aracı olarak kaçınılmaz |
| [Hendi48/Magicmida](https://github.com/Hendi48/Magicmida) | 766 | 2026-05 | Themida unpacker (Pascal; aktif) |
| [x86rc/unthemidator](https://github.com/x86rc/unthemidator) | 473 | 2026-11-11 | **Themida/CV/WinLicense v3.0–v4** otomatik unpacker + dump fixer; çok yeni |
| [ergrelet/themida-unmutate](https://github.com/ergrelet/themida-unmutate) | 416 | 2024-07 | T/WL/CV 3.x **mutation** obfuscation statik deobfuscator |
| [cg10036/Themida-Unpacker-for-.NET](https://github.com/cg10036/Themida-Unpacker-for-.NET) | 249 | 2025-02 | .NET Themida (arşiv) |
| [bobalkkagi/bobalkkagi](https://github.com/bobalkkagi/bobalkkagi) | 218 | 2023-03 | Themida 3.x unpack + unwrap + devirt (planlı) |
| [TopSoftdeveloper/UnpackThemida](https://github.com/TopSoftdeveloper/UnpackThemida) | 216 | 2026-08 | Dinamik unpacker + import fixer (unlicense hattı; aktif) |
| [aftermathlabs/themida-devirt](https://github.com/aftermathlabs/themida-devirt) | 128 | 2026-05 | Themida **devirt sonuçları** (fork: [gavz/themida-devirt](https://github.com/gavz/themida-devirt) 0★) |
| [stuxnet147/Themida-Research](https://github.com/stuxnet147/Themida-Research) | 122 | 2025-02 | Themida 3.x araştırması; aynı yazarın [IDA-PeepholeOptimizer](https://github.com/stuxnet147/IDA-PeepholeOptimizer) (4★) themida devirt WIP |
| [ret2vibec/whatlicense](https://github.com/ret2vibec/whatlicense) | 116 | 2024-04 | **WinLicense key extraction** (Intel PIN) |
| [ergrelet/themida-spotter-bn](https://github.com/ergrelet/themida-spotter-bn) | 104 | 2024-07 | Binary Ninja: Themida obfuscate kod tespiti |
| [ergrelet/themida-unmutate-bn](https://github.com/ergrelet/themida-unmutate-bn) | 50 | 2024-07 | Binary Ninja: unmutate port |
| [pakt/decv](https://github.com/pakt/decv) | 92 | 2012 | **Code Virtualizer 1.3.8 decompiler** (tarihi) |
| [RenardDev/OreansCrack](https://github.com/RenardDev/OreansCrack) | 56 | 2026-01 | Oreans ürünlerinde **lisans emülasyonu** PoC (WIP) |
| [67-6f-64/AntiOreans-CodeDevirtualizer](https://github.com/67-6f-64/AntiOreans-CodeDevirtualizer) | 82 | 2023-04 | Oreans code devirtualizer (+ orijinal [ocd](https://github.com/67-6f-64/ocd) 5★; fork: [Dy-Baby](https://github.com/Dy-Baby/Themida-AntiOreans-CodeDevirtualizer) 9★) |
| [nelj14/themida-dumper](https://github.com/nelj14/themida-dumper) | 42 | 2026-04 | Themida/WL payload çıkarıcı (suspend + dump) |
| [DimaReverse/nuitka-themida-unpacker](https://github.com/DimaReverse/nuitka-themida-unpacker) | 34 | 2026-09 | İki aşamalı pipeline: unlicense → Nuitka onefile |
| [guoxing2024/magicmida-rs](https://github.com/guoxing2024/magicmida-rs) | 27 | 2026-11-24 | **Magicmida'nın Rust portu** — Themida v3 x64 otomatik unpacker (aynası: [sunwm518/magicmida-rs](https://github.com/sunwm518/magicmida-rs)) |
| [SohWeeKiat/Themida-3.x.x-CRC-Bypass](https://github.com/SohWeeKiat/Themida-3.x.x-CRC-Bypass) | 24 | 2023-07 | Themida 3.x CRC bypass PoC (aynaları 67-6f-64/sunwm518) |
| [koolkdev/antiantidebug](https://github.com/koolkdev/antiantidebug) | 2 | 2026-06 | Themida Code Virtualizer devirt eski araştırma kodu |
| [gavz/analysis.oreans](https://github.com/gavz/analysis.oreans) | 40 | 2020-08 | Themida/WL/CV içeriden analiz notları |
| [Marisa-Chan/GhidrOrean](https://github.com/Marisa-Chan/GhidrOrean) | 16 | 2025-06 | Ghidra ile Oreans devirt |
| [4IbWNsis3S/Oreans-Eagle-VM-decoder](https://github.com/4IbWNsis3S/Oreans-Eagle-VM-decoder) | 3 | 2025-12 | WL/Themida/CV **Eagle VM** handler decoder |
| [NohamR/Code-Virtualizer-Demo](https://github.com/NohamR/Code-Virtualizer-Demo) | 2 | 2026-03 | Code Virtualizer'ın **macOS ARM64**'te ObjC swizzling koruması demosu |
| [orange-cpp/secure_engine](https://github.com/orange-cpp/secure_engine) | 11 | 2024-11 | WinLicense/Themida/CV SDK wrapper |
| [Fl0sec/plutonium-devirt](https://github.com/Fl0sec/plutonium-devirt) | 0 | 2026-11-23 | Themida VM analizi + offline replay (yeni) |
| [abcSup/themida-devirt](https://github.com/abcSup/themida-devirt) | 0 | 2026-11-25 | Yeni devirt çalışması |
| [clovexx/unmutate-dump](https://github.com/clovexx/unmutate-dump) | 0 | 2026-11-24 | Dump + anonim packer bölge birleştirme → themida-unmutate hattı |
| [pkochubey/Unmida](https://github.com/pkochubey/Unmida) | 1 | 2026-11-07 | Komut satırı Themida unpacker (yeni) |
| [Arcticbyp/seb-re-toolkit](https://github.com/Arcticbyp/seb-re-toolkit) | 2 | 2026-10 | Safe Exam Browser'ın Themida korumalı `seb_x64.dll` bütünlük modülü RE toolkit'i |
| Not | — | sunwm518 hesabında Magicmida / themida-unmutate / magicmida-rs **fork aynaları** da mevcut |

**Sürüm bağlamı:** Themida & WinLicense 3.2.6.0 (11.08.2026 — Themida.exe tamamen 64-bit), Code Virtualizer **4.0.1.0** (11.10.2026, resmî v4).

---

## A3) Enigma Protector / Enigma Virtual Box

| Repo | Yıldız | Son aktivite | Not |
|---|---|---|---|
| [mos9527/evbunpack](https://github.com/mos9527/evbunpack) | 335 | 2025-11 | **Enigma Virtual Box unpacker** — en olgun araç |
| [EVBExtractor/evb-extractor](https://github.com/EVBExtractor/evb-extractor) | 24 | 2013 | EVB konteyner çıkarıcı (tarihi) |
| [ofkarosia/evbunpack](https://github.com/ofkarosia/evbunpack) | 3 | 2025-12 | evbunpack Rust portu (+ [evbunpack_core](https://github.com/ofkarosia/evbunpack_core) kütüphane, 2025-12) |
| [vrdons/evbunpack-rs](https://github.com/vrdons/evbunpack-rs) | 2 | 2026-11-25 | evbunpack Rust portu (yeni, aktif; benzeri [moshouhot/evbunpack-rs](https://github.com/moshouhot/evbunpack-rs), 2026-11-04) |
| [ashduino101/EnigmaUnprotector](https://github.com/ashduino101/EnigmaUnprotector) | 6 | 2026-09 | Enigma Protector obfuscation'ından kod/veri kurtarma |
| [eybee/EnigmaDevirtualizer](https://github.com/eybee/EnigmaDevirtualizer) | 1 | 2018 | Enigma VM (v2.x–3.x) devirt denemesi |
| [Hintay/py-enigma](https://github.com/Hintay/py-enigma) | 2 | 2022-09 | Enigma API Python bağlaması |
| [Selennoid/enigma-dll-loader](https://github.com/Selennoid/enigma-dll-loader) | 1 | 2025-10 | Enigma eklentisi: harici DLL yükleme |

**Not:** Enigma Protector (tam ürün, v8.10 / 30.09.2026) için hazır uçtan-uca açık kaynak unpacker **yok**; pratik yol: x64dbg + OEP takibi + Scylla/pe-sieve dump + evbunpack (yalnız EVB paketleri).

---

## A4) Diğer ticari protector'lar + yeni Çin dalgası

**ASProtect:** [Hendi48/ASpirin](https://github.com/Hendi48/ASpirin) (28★, 2026-04, hedef özelinde unpacker) · [pstolarz/asprext](https://github.com/pstolarz/asprext) (24★, WinDbg eklentisi) · [e-gleba/airstrike3d-tools](https://github.com/e-gleba/airstrike3d-tools) (26★, oyun özelinde ASProtect araç seti)
**Safengine Shielden:** [sctnightcore/UnSafengine64](https://github.com/sctnightcore/UnSafengine64) (33★) · [holycall/UnSafengine64](https://github.com/holycall/UnSafengine64) (32★, C++) — bilimsel makale: [UnSafengine64, MDPI Sensors 2024](https://www.mdpi.com/1424-8220/24/3/840)
**StarForce:** [vdisasm/SFFS-Unpacker](https://github.com/vdisasm/SFFS-Unpacker) (19★, Pascal, SFFS) · [King Kong Signature Edition fix](https://github.com/WIFIDarthMaul/Peter-Jackson-s-King-Kong-Signature-Edition-Fix) (50★, 2026, oyun özelinde StarForce kaldırma)
**PELock:** resmî [SDK deposu](https://github.com/PELock/PELock-Software-Protection-and-Licensing-SDK) (233★) · [pelock_unpack_lab](https://github.com/aaarrti/pelock_unpack_lab) (2026-02) · resmî **Lua Virtualizer** ailesi: [PELock/Lua-Virtualizer-Go](https://github.com/PELock/Lua-Virtualizer-Go) (2026-10'da aktif; C#/Ruby/VSCode bağlamaları org'da)
**MoleBox:** [sudachen/Molebox](https://github.com/sudachen/Molebox) (182★, eski sürümün kaynağı açık) · [molebox-oep-finder](https://github.com/extremecoders-re/molebox-oep-finder) (3★)
**Milfuscator (referans):** [nelfo/Milfuscator](https://github.com/nelfo/Milfuscator) (237★, 2022) — x86 PE mutator (analiz/karşı-araç üretimi için depo)
**CrackProof (Çin packer'ı — 2026'nın en sıcak unpack hedefi):**
- [Momoko-Ayase/Senbei](https://github.com/Momoko-Ayase/Senbei) (94★, 2026-11-18) — **statik CrackProof unpacker** (aktif!)
- [Naominet/Nyadecrypt](https://github.com/Naominet/Nyadecrypt) (31★, 2026-10) — Crackproof dumper (ChinaLeaker Hypertech)
- [sbga-tech/crackproof-unpacker](https://github.com/sbga-tech/crackproof-unpacker) (18★, 2026-11-25) — yeni unpacker
- [kungfulon/crackproof](https://github.com/kungfulon/crackproof) (6★) — unpack yardımcı kütüphanesi
- [notunixian/crackproof-unpacker](https://github.com/notunixian/crackproof-unpacker) (3★, 2026-07) + [HtMetadataDecrypt](https://github.com/notunixian/HtMetadataDecrypt) (4★, il2cpp metadata) — statik unpack denemeleri
**Tencent VM (TVM / .tvm0):**
- [jz0/tvm-devirt](https://github.com/jz0/tvm-devirt) (168★, 2026-10-24) — **Tencent VM statik devirtualizer** (yeni ve güçlü)
- [NeuroSaki987/tvm-recover](https://github.com/NeuroSaki987/tvm-recover) (88★, 2026-11-14) — `.tvm0` unpack + PE yeniden yazma
- [wj-stack/tvm0](https://github.com/wj-stack/tvm0) (6★) — tvm0 araştırması
**EXECryptor / Obsidium / Armadillo / SDProtector / XProtector / VProtect:** hazır açık kaynak araç yok — forum tutorial'ları miras (tuts4you/exetools arşivleri).

---

## A5) UPX & Klasik Packer'lar (ASPack, PECompact, MPRESS, NSPack, FSG, MEW, Petite, Upack, tElock, RLPack, WWPack, Neolite, eXPressor, SVKP, Morphine, Yoda, PECrypt, ExeStealth, hXOR...)

- [upx/upx](https://github.com/upx/upx) — 18.032★; `upx -d` resmî çözüm
- [orca-zhang/unpack](https://github.com/orca-zhang/unpack) — 98★, Rust, 2026-11-25'te aktif; UPX/ASPack vb. otomatik tanı+dök
- [anpa1200/Unpacker](https://github.com/anpa1200/Unpacker) — 46★, 2026-10; UPX/ASPack/Themida/VMP tespit+unpack iş akışı
- [CCint3/UnpackUPX](https://github.com/CCint3/UnpackUPX) — 35★; Android'de UPX unpack
- [bdunlap9/UPX-Unpackers](https://github.com/bdunlap9/UPX-Unpackers) — 35★; UPX unpacker derlemesi
- [gdbinit/mpress_dumper](https://github.com/gdbinit/mpress_dumper) — 65★; **MPRESS dumper (OS X)** — gdbinit'in klasiği
- [DosX-dev/UPX-Patcher](https://github.com/DosX-dev/UPX-Patcher) — 197★; `upx -d`'yi **imkânsız kılan** yama (savunma tarafı; dedektörün negatif varyantları için de ilham)
- [c3rb3ru5d3d53c/karton-unpacker](https://github.com/c3rb3ru5d3d53c/karton-unpacker) — 58★; Karton servis entegrasyonu
- [kn0wl3dge/mozitools](https://github.com/kn0wl3dge/mozitools) — 52★; Mozi botnet unpack/config
- [ElvisBlue/Imprect-PeCompact](https://github.com/ElvisBlue/Imprect-PeCompact) — Imprect eklentisi, PECompact İAT yönlendirme fix
- [Real-hackbard/MPRESS-Compressor-GUI](https://github.com/Real-hackbard/MPRESS-Compressor-GUI) (7★) + [PECompact2-Compressor-GUI](https://github.com/Real-hackbard/PECompact2-Compressor-GUI) (5★, 2026) — kapalı packer'lar için GUI sarmalayıcılar (pack üretimi)
- **hXOR-Packer / Milfuscator / ExeStealth / NSPack / FSG / MEW / Petite / tElock...** için hazır araç yok: PEiD/DIE imzaları + generik dump (§A15) + olydbg/x64dbg miras script'leri yegâne yol.

---

## A6) Oyun DRM / Disc Koruması / Anti-Tamper / Anti-Cheat

### A6.1 — SteamStub / CEG / SafeDisc / SecuROM / Denuvo

| Repo | Yıldız | Son aktivite | Not |
|---|---|---|---|
| [atom0s/Steamless](https://github.com/atom0s/Steamless) | **5215** | 2024-03 | **SteamStub DRM remover** — Steam zarfı için tek çözüm standardı |
| [RibShark/SafeDiscShim](https://github.com/RibShark/SafeDiscShim) | 604 | 2025-09 | SafeDisc korumalı oyunları modern Windows'ta çalıştırma (secdrv kapalı) |
| [reetamdan/hypervisor-crack-audit](https://github.com/reetamdan/hypervisor-crack-audit) | 330 | 2026-03 | **Denuvo bypass'ında hypervisor DRM metodunun** güvenlik analizi (sürücü RE) |
| [BIAO-001/SteamToolbox](https://github.com/BIAO-001/SteamToolbox) | 147 | 2026-11 | Steam araç kutusu — **Denuvo lisans anahtarı çıkarma** özelliği dahil |
| [nckstwrt/SecuROMLoader](https://github.com/nckstwrt/SecuROMLoader) | 123 | 2026-01 | SecuROM oyunlarını CD/DVD olmadan modern Windows'ta oynatma |
| [nathan-baggs/diamond](https://github.com/nathan-baggs/diamond) | 119 | 2026-01 | Denuvo hacking kodu (araştırma) |
| [Fire-Head/MHNoDRM](https://github.com/Fire-Head/MHNoDRM) | 88 | 2023-09 | Manhunt Steam fix — **SecuROM CD crack protection remover** |
| [nckstwrt/SafeDiscLoader2](https://github.com/nckstwrt/SafeDiscLoader2) | 86 | 2026-03 | SafeDisc 2+ oyunları modern Windows'ta oynatır (v1: [SafeDiscLoader](https://github.com/nckstwrt/SafeDiscLoader), 56★, 2025-11) |
| [Nitr0-G/Denuvo-Info](https://github.com/Nitr0-G/Denuvo-Info) | 74 | 2025-12 | Denuvo kırma notları |
| [Rattpak/CEG-Anti-Tamper-Analysis](https://github.com/Rattpak/CEG-Anti-Tamper-Analysis) | 62 | 2025-05 | Steam **CEG anti-tamper** RE + kısmi devre dışı bırakma |
| [modgames44/HiperVisor-Denuvo](https://github.com/modgames44/HiperVisor-Denuvo) | 33 | 2026-04 | Hypervisor Denuvo devre dışı bırakma/geri alma |
| [momo5502/denuvo-slides](https://github.com/momo5502/denuvo-slides) | 13 | 2025-11 | Denuvo sunum slaytları ([momo5502.com/slides/denuvo](https://momo5502.com/slides/denuvo)) — momo5502'nin Denuvo RE serisinin özeti |
| [Tesla697/TokeerDRM-App](https://github.com/Tesla697/TokeerDRM-App) | 9 | 2026-06 | Denuvo aktivasyon kod paylaşım araçları (token araştırması; + UbiTokeer 6★) |
| [one-eyed-queen/Denuvo-Research](https://github.com/one-eyed-queen/Denuvo-Research) | 6 | 2026-09 | Bağımsız Denuvo araştırması |
| **Denuvo resmî org:** [DenuvoSoftwareSolutions/GAMBA](https://github.com/DenuvoSoftwareSolutions/GAMBA) (257★) + [SiMBA](https://github.com/DenuvoSoftwareSolutions/SiMBA) (200★) | — | 2023 | Denuvo'nun kendi MBA sadeleştirme araçları — **koruma tarafının beynini açıkça paylaşması** (devirt dünyası için kıymetli) |

### A6.2 — Anti-cheat sürücüleri (kernel koruması araştırmaları)

| Repo | Yıldız | Son aktivite | Not |
|---|---|---|---|
| [danielkrupinski/VAC-Bypass](https://github.com/danielkrupinski/VAC-Bypass) | 659 | 2021-09 | Valve Anti-Cheat bypass (C) |
| [adrianyy/EACReversing](https://github.com/adrianyy/EACReversing) | 595 | 2019-04 | EasyAntiCheat RE notları |
| [eversinc33/unKover](https://github.com/eversinc33/unKover) | 370 | 2026-03 | Anti-rootkit/anti-cheat — kernel'de gizli kodu ortaya çıkarma |
| [kagurazakasanae/Mhyprot2DrvControl](https://github.com/kagurazakasanae/Mhyprot2DrvControl) | 362 | 2020-10 | mhyprot2 (Genshin) sürücüsünü süreç enum/RW/kill için kullanma kütüphanesi |
| [thesecretclub/CVEAC-2020](https://github.com/thesecretclub/CVEAC-2020) | 357 | 2020-09 | **EasyAntiCheat integrity check bypass** (bellek değişikliği taklidi) |
| [Apxaey/Handle-Hijacking-Anti-Cheat-Bypass](https://github.com/Apxaey/Handle-Hijacking-Anti-Cheat-Bypass) | 217 | 2021-03 | Native API handle hijacking ile AC bypass |
| [ch4ncellor/EAC-Reversal](https://github.com/ch4ncellor/EAC-Reversal) | 248 | 2021-12 | EAC sürücüsü RE (09/2021) |
| [haram/splendid_implanter](https://github.com/haram/splendid_implanter) | 246 | 2020-10 | BattlEye uyumlu user-mode injector (secret.club) |
| [MlgmXyysd/Il2CppMemoryDumper](https://github.com/MlgmXyysd/Il2CppMemoryDumper) | 207 | 2026-02 | Il2Cpp ELF + metadata bellek dumper (korumasız build) |
| [weak1337/BE-Shellcode](https://github.com/weak1337/BE-Shellcode) | 232 | 2021-11 | BattlEye shellcode çözümlemesi |
| [0x1-1/Battleye-VAC-EAC-Kernel-Bypass](https://github.com/0x1-1/Battleye-VAC-EAC-Kernel-Bypass) | 194 | 2023-10 | Kernel-mod BE/EAC/VAC bypass |
| [zouxianyu/BlindEye](https://github.com/zouxianyu/BlindEye) | 194 | 2022-10 | BattlEye kernel modül bypass |
| [vasie1337/kernel-anticheat](https://github.com/vasie1337/kernel-anticheat) | 191 | 2025-06 | Kernel anti-cheat (savunma tarafı RE temeli) |
| [tarekwiz/LeagueDumper](https://github.com/tarekwiz/LeagueDumper) | 161 | 2019-02 | League of Legends yeni anti-cheat dönemine özel süreç dumper |
| [CamxxCore/EasyAntiCheat-Emulator](https://github.com/CamxxCore/EasyAntiCheat-Emulator) | 160 | 2024-05 | EAC spoof DLL |
| [03927/IoCreateDriver](https://github.com/03927/IoCreateDriver) | 168 | 2026-09 | Sürücüsüz sürücü yükleme — AC bypass araştırması |
| [Lixense/ff-ace-anticheat-analysis](https://github.com/Lixense/ff-ace-anticheat-analysis) | 35 | 2026-09 | **Tencent ACE** (Anti-Cheat Expert) RE post-mortem (Free Fire, libanogs) — 2026 |
| [not1cyyy/PowerVM](https://github.com/not1cyyy/PowerVM) | 35 | 2026-08 | **Stealth Type-1 Hipervizör** — modern anti-cheat korumalı süreçleri debug etmek için |
| [lauralex/OAC](https://github.com/lauralex/OAC) | 21 | 2026-11 | Savunma tarafı: x64 Windows anti-cheat/endpoint bütünlük araştırma temeli |
| [extrant/Helldivers2-HD2-nProtect-Bypass-And-Dumper](https://github.com/extrant/Helldivers2-HD2-nProtect-Bypass-And-Dumper) | 8 | 2026-03 | Helldivers 2 **nProtect bypass + runtime unpacker** — packer dökümü içeren oyun vakası |
| Kaynak listeleri | — | — | [AreWeAntiCheatYet](https://github.com/AreWeAntiCheatYet/AreWeAntiCheatYet) (517★, Linux uyumluluk haritası) · [PCGamingWiki anti-cheat listesi](https://www.pcgamingwiki.com/wiki/List_of_games_with_anti-cheat_technology) |

---

## A7) .NET protector'ları (ConfuserEx / KoiVM / Reactor / Eazfuscator / Agile.NET / BeeByte / Babel)

**Evrensel:** [de4dot/de4dot](https://github.com/de4dot/de4dot) (7426★, arşiv — 30+ obfuscator tanır) · [ViRb3/de4dot-cex](https://github.com/ViRb3/de4dot-cex) (573★, ConfuserEx tam destek) · [NotPrab/.NET-Deobfuscator](https://github.com/NotPrab/.NET-Deobfuscator) (1531★ — **protector başına araç listesi**) · [NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator) (1500★ — obfuscator kataloğu) · [dnSpyEx/dnSpy](https://github.com/dnSpyEx/dnSpy) (11.533★) · [icsharpcode/ILSpy](https://github.com/icsharpcode/ILSpy) (27.160★) · [0xd4d/dnlib](https://github.com/0xd4d/dnlib) (2506★) · [Washi1337/AsmResolver](https://github.com/Washi1337/AsmResolver) (1140★) · [wwh1004/ExtremeDumper](https://github.com/wwh1004/ExtremeDumper) (1063★ — **.NET assembly dumper**, wwh1004 klasikleri arasında) · [CodeCracker-Tools/MegaDumper](https://github.com/CodeCracker-Tools/MegaDumper) (464★ — native+.NET dump) · [holly-hacker/dnSpy.Extension.HoLLy](https://github.com/holly-hacker/dnSpy.Extension.HoLLy) (389★ — obfuscate assembly'lere özel dnSpy eklentisi) · [imperva/frida-jit-unpacker](https://github.com/imperva/frida-jit-unpacker) (67★, 2024 — .NET JIT seviyesinde unpack) · derlenmiş binary'ler: [vee2xx/de4dot-built-binaries](https://github.com/vee2xx/de4dot-built-binaries) (54★) · yeniler: [JacksonOnly/de4dotEx](https://github.com/JacksonOnly/de4dotEx) (2★, 2026-11) · [dawwinci/de4dot-cex-babel](https://github.com/dawwinci/de4dot-cex-babel) (8★) · [jordansoftware/.NET-Deobfuscator](https://github.com/jordansoftware/.NET-Deobfuscator) (4★, 2026-05 — Universal .NET Defender Remover)

**ConfuserEx:** [mkaring/ConfuserEx](https://github.com/mkaring/ConfuserEx) (2915★, aktif fork) · [yck1509/ConfuserEx](https://github.com/yck1509/ConfuserEx) (3761★, orijinal) · [undebel/NoFuserEx](https://github.com/undebel/NoFuserEx) (430★) · [wwh1004/ConfuserExTools](https://github.com/wwh1004/ConfuserExTools) (208★) · [chaplin89/ClarifierEx](https://github.com/chaplin89/ClarifierEx) (100★) · [Dump-GUY/ConfuserEx2_String_Decryptor](https://github.com/Dump-GUY/ConfuserEx2_String_Decryptor) (107★) · [dr4k0nia/Unscrambler](https://github.com/dr4k0nia/Unscrambler) (106★, modded CE) · [landoncrabtree/UnconfuserExTools](https://github.com/landoncrabtree/UnconfuserExTools) (85★) · [Zypherion-Technologies/UnConfuserEx](https://github.com/Zypherion-Technologies/UnConfuserEx) (48★, **2026-06 — ConfuserEx2** deobfuscator) · [uvbs/ConfuserEx-Unpacker](https://github.com/uvbs/ConfuserEx-Unpacker) (46★, emülasyon) · [KoiHook/ConfuserEx-Unpacker-2](https://github.com/KoiHook/ConfuserEx-Unpacker-2) (39★, emülasyon v2) · [imkk000/confuserex-unpacker-custom](https://github.com/imkk000/confuserex-unpacker-custom) (20★, 2026-06'da aktif) · [CusDec-dev/ConfuserEx2-Unpacker](https://github.com/CusDec-dev/ConfuserEx2-Unpacker) (3★, 2026-10) · [8opa/DeConfuserEx-tools](https://github.com/8opa/DeConfuserEx-tools) (1★, 2026-08)
**KoiVM / CawkVM:** [Washi1337/OldRod](https://github.com/Washi1337/OldRod) (389★ — **otomatik KoiVM devirt**) · [yck1509/KoiVM](https://github.com/yck1509/KoiVM) (119★) · [0x25bit/KoiVM-modded](https://github.com/0x25bit/KoiVM-modded) (40★, DarksVM) · [Trollicus/KoiVM](https://github.com/Trollicus/KoiVM) (13★, mod) · [AxDSan/Venturi77CallHijacker](https://github.com/AxDSan/Venturi77CallHijacker) (18★, KoiVM/EazVM/AgileVM patcher) · [ElektroKill/CawkVM-Unpacker](https://github.com/ElektroKill/CawkVM-Unpacker) (79★) · [lckt0/AstroNet](https://github.com/lckt0/AstroNet) (26★, modded KoiVM decrypt)
**.NET Reactor:** [SychicBoy/NETReactorSlayer](https://github.com/SychicBoy/NETReactorSlayer) (1286★, 2026-09'da aktif) · [CursedLand/Cursed.Reactor](https://github.com/CursedLand/Cursed.Reactor) (56★ — VM & NecroBit hariç tam unpack) · [dawwinci/krypton-devirtualizer](https://github.com/dawwinci/krypton-devirtualizer) (26★, 2026-08) · [0301091405/autoreaktor](https://github.com/0301091405/autoreaktor) (6★, 2026-10 — hunt→de4dot→Slayer→Krypton toplu pipeline) · [konstant16-Z/NETReactorSlayerCross](https://github.com/konstant16-Z/NETReactorSlayerCross) (1★, net8.0 CLI) · string örneği: [DarkBullNull/.NETReactor_6.3.0.0_Only_Strings](https://github.com/DarkBullNull/.NETReactor_6.3.0.0_Only_Strings) (21★)
**Eazfuscator:** [holly-hacker/EazFixer](https://github.com/holly-hacker/EazFixer) (459★, 2026-01) · [puff/EazyDevirt](https://github.com/puff/EazyDevirt) (183★, VM→IL) · [saneki/eazdevirt](https://github.com/saneki/eazdevirt) (180★) · [holly-hacker/EazDecode](https://github.com/holly-hacker/EazDecode) (46★ — şifreli sembol adları) · [ldstr/EazTrialRemover](https://github.com/ldstr/EazTrialRemover) (83★) · [JacksonOnly/EazUnpacker](https://github.com/JacksonOnly/EazUnpacker) (40★, 2026-11-14 — C# kaynak kurtarma) · [Trollicus/EazDecryptor](https://github.com/Trollicus/EazDecryptor) (17★) · [silentsignal/eazfuscator.net-symbol-decrypter](https://github.com/silentsignal/eazfuscator.net-symbol-decrypter) (11★ — toplu sembol decrypt)
**Agile.NET/CliSecure:** [SychicBoy/AgileDotNetSlayer](https://github.com/SychicBoy/AgileDotNetSlayer) (125★) · [dawwinci/agile-net-devirtualizer](https://github.com/dawwinci/agile-net-devirtualizer) (47★, 2026-08 — generic VM devirt)
**BeeByte (Unity):** [OsOmE1/Beebyte-Deobfuscator](https://github.com/OsOmE1/Beebyte-Deobfuscator) (131★, Il2CppInspector eklentisi) · [ioncodes/beeless](https://github.com/ioncodes/beeless) (56★) · [TouMobSiab/BeeByte-Obfuscation-Source-Code-](https://github.com/TouMobSiab/BeeByte-Obfuscation-Source-Code-) (21★ — **kaynak paylaşımı**) · [Silv3rPRO/proshine-cleaner](https://github.com/Silv3rPRO/proshine-cleaner) (8★)
**Babel Obfuscator:** [CleoV2/Babel-Deobfuscator](https://github.com/CleoV2/Babel-Deobfuscator) (40★) · [EHVNArchive/BabelDeobfuscator](https://github.com/EHVNArchive/BabelDeobfuscator) (8★)
**Diğer:** [lckt0/DotKill-Unpacker](https://github.com/lckt0/DotKill-Unpacker) (155★ — anti-de4dot/junk/CFF temizleme) · [advanced-threat-research/DotDumper](https://github.com/advanced-threat-research/DotDumper) (266★, otomatik .NET unpacker+logger) · [jgajek/cilantro](https://github.com/jgajek/cilantro) (6★, 2026-11-20 — yeni nesil .NET deobf+devirt) · [wwh1004/antinet](https://github.com/wwh1004/antinet) (117★, .NET anti-debugger) · [wwh1004/Mdcrypt](https://github.com/wwh1004/Mdcrypt) (45★, protector WIP) · [dr4k0nia/Origami](https://github.com/dr4k0nia/Origami) (177★, packer — test için) · [dr4k0nia/Greenline](https://github.com/dr4k0nia/Greenline) (40★, Redline unpacker) · [dr4k0nia/Simple-Costura-Decompressor](https://github.com/dr4k0nia/Simple-Costura-Decompressor) (83★) · [dr4k0nia/MurkyStrings](https://github.com/dr4k0nia/MurkyStrings) (109★) · [fl2on/Anti-De4dot](https://github.com/fl2on/Anti-De4dot) (35★ — **anti-araç**, negatif test üreticisi) · [ramaikn/SimpleAntiDump](https://github.com/ramaikn/SimpleAntiDump) (1★ — MegaDumper/ExtremeDumper'a karşı anti-dump)

---

## A8) Java (JVM) obfuscator'ları + araçlar

**Genel deobf/decompiler platformları:**
- [skylot/jadx](https://github.com/skylot/jadx) — **52.005★**; dex→Java decompiler
- [Konloch/bytecode-viewer](https://github.com/Konloch/bytecode-viewer) — 15.732★; jar/APK RE suiti
- [google/android-classyshark](https://github.com/google/android-classyshark) — 7544★; Android/Java bytecode viewer
- [Col-E/Recaf](https://github.com/Col-E/Recaf) — 7489★; modern Java bytecode editörü
- [Storyyeller/Krakatau](https://github.com/Storyyeller/Krakatau) — 2265★ (2026-10'da aktif); decompiler+assembler+disassembler
- [java-deobfuscator/deobfuscator](https://github.com/java-deobfuscator/deobfuscator) — 1762★
- [CalebFenton/simplify](https://github.com/CalebFenton/simplify) — 4685★; Android VM + deobfuscator
- [loerting/threadtear](https://github.com/loerting/threadtear) — 984★; çok işlevli deobf suiti
- [tp7309/TTDeDroid](https://github.com/tp7309/TTDeDroid) — 949★; apk/aar/dex/jar tek tuş decompile
- [LaurieWired/JADXecute](https://github.com/LaurieWired/JADXecute) — 752★; jadx-gui dinamik manipülasyon eklentisi
- [Diobf/Deobfuscator](https://github.com/Diobf/Deobfuscator) — 541★; Java deobfuscator (org: Diobf)
- [Col-E/CAFED00D](https://github.com/Col-E/CAFED00D) — 145★; **obfuscation-resilient** class reader/writer
- [FabricMC/Enigma](https://github.com/FabricMC/Enigma) — 550★ (remap)
- [GenericException/SkidSuite](https://github.com/GenericException/SkidSuite) — 355★; Java RE araç koleksiyonu
- [eikendev/java-decompiler](https://github.com/eikendev/java-decompiler) — 74★; CFR+Vineflower+Procyon+jadx+Krakatau docker

**Zelix KlassMaster (ZKM):**
- [GraxCode/zelixkiller](https://github.com/GraxCode/zelixkiller) — 73★; ZKM ≤v11 (yerine threadtear geçti)
- [StylesFoundation/OpenZKM](https://github.com/StylesFoundation/OpenZKM) — 57★, **2026-10-30**; ZKM 27.0.0 decompile/rebuild
- [LvStrnggg/zkm-flow](https://github.com/LvStrnggg/zkm-flow) — 55★, 2025-09; ZKM control-flow obfuscation writeup + transformer
- [DarkCreative1/zkm-deobfuscator](https://github.com/DarkCreative1/zkm-deobfuscator) — 30★, **2026-10**; statik ZKM deobfuscator (isim+string+int+flow)
- [unleg1t/ZKM-27-Full-Deobfuscator](https://github.com/unleg1t/ZKM-27-Full-Deobfuscator) — 22★, **2026-09**; ZKM 27 tam deobfuscator

**Allatori:**
- [lqs1848/AllatoriCrack](https://github.com/lqs1848/AllatoriCrack) — 307★; Allatori crack (Çince)
- [netindev/Allatori-v3.0](https://github.com/netindev/Allatori-v3.0) — 53★; **Allatori v3.0 kaynak kodu (sızıntı, 2016)**
- [Skid-Technology/OpenAllatori](https://github.com/Skid-Technology/OpenAllatori) — 14★, **2026-11**; son ticari sürüm (9.9) paylaşımı

**JNIC / Java→native (j2c):**
- [YumeGod/JNIC-Virtualization](https://github.com/YumeGod/JNIC-Virtualization) — 65★; JNIC jar'dan native lib dump + uyumlu loader
- [YumeGod/OpenMyJ2C](https://github.com/YumeGod/OpenMyJ2C) — 48★; "8000 CNY'ye satılan sahte JNIC" ifşası
- [nuym/j2c](https://github.com/nuym/j2c) — 45★; açık kaynak, hızlı JNIC
- [MyJ2c/Open-MyJ2c](https://github.com/MyJ2c/Open-MyJ2c) — 45★; MyJ2C resmî açık repo
- [Skid-Technology/OpenJNIC](https://github.com/Skid-Technology/OpenJNIC) — 38★, **2026-11**; JNIC 3.7.0 paylaşımı
- [mxchu666/JnicDeobfuscator](https://github.com/mxchu666/JnicDeobfuscator) — 8★, **2026-11**; JNIC obfuscate JAR deobf/devirt
- [kboxcbh1337/kboxObfuscator](https://github.com/kboxcbh1337/kboxObfuscator) — 23★, **2026-11**; ZKM seviyesi Java protector (JNIC native + VMP + master-key)

**Diğer obfuscator'lar / araçlar:**
- [gaoyu06/c2j-native-deobfuscator](https://github.com/gaoyu06/c2j-native-deobfuscator) — 51★, 2026-09; native-obfuscator çıktısı deobf
- [GraxCode/dasho8-string-deobfuscator](https://github.com/GraxCode/dasho8-string-deobfuscator) — 15★; DashO 8.x string
- [Initial-One/Java-humanify](https://github.com/Initial-One/Java-humanify) — 130★, 2025-10; LLM ile Java deobf
- **AI/MCP dalgası (2025-2026):** [zinja-coder/jadx-ai-mcp](https://github.com/zinja-coder/jadx-ai-mcp) (3037★) · [zinja-coder/jadx-mcp-server](https://github.com/zinja-coder/jadx-mcp-server) (856★) · [cncsnet1/jadx-gui-ai](https://github.com/cncsnet1/jadx-gui-ai) (792★, AI güçlendirilmiş jadx-gui) · [CreditTone/android-reverse-engineering-skill](https://github.com/CreditTone/android-reverse-engineering-skill) (583★) · [sniperrich/RecafMCP](https://github.com/sniperrich/RecafMCP) (39★) · [Naptila/recaf-mcp](https://github.com/Naptila/recaf-mcp) (15★) · [tha23rd/recaf-mcp](https://github.com/tha23rd/recaf-mcp) (11★) · [vmoranv/jshookmcp](https://github.com/vmoranv/jshookmcp) (2131★ — arama-öncelikli RE workspace, 735 araç)

---

## A9) Android sağlamlaştırma (加固/壳) unpacking — Çin ekosistemi ağırlıklı

**Ulusal (universal) unpacker'lar:**
| Repo | Yıldız | Son aktivite | Not |
|---|---|---|---|
| [CodingGay/BlackDex](https://github.com/CodingGay/BlackDex) | **6483** | 2023-11 | Android 5.0–12 unpack/dexdump — root/Xposed GEREKTİRMEZ; canlandırma: [ZiTanIOI/newBlackDex](https://github.com/ZiTanIOI/newBlackDex) (142★, 2026) |
| [hluwa/frida-dexdump](https://github.com/hluwa/frida-dexdump) | 4549 | 2023-03 | Frida ile bellekten dex dump — de facto standart |
| [WrBug/dumpDex](https://github.com/WrBug/dumpDex) | 3167 | 2020-05 | Xposed tabanlı klasik脱壳工具 |
| [hanbinglengyue/FART](https://github.com/hanbinglengyue/FART) | 2751 | 2025-01 | **FART**: ART ortamında otomatik脱壳 (aktif çağrı yöntemi) — Çin unpacker'larının atası |
| [DrizzleRisk/drizzleDumper](https://github.com/DrizzleRisk/drizzleDumper) | 2411 | 2017-12 | Bellek aramalı脱壳 |
| [dstmath/frida-unpack](https://github.com/dstmath/frida-unpack) | 1619 | 2025-06 | Frida tabanlı脱壳 (Çince) |
| [zhkl0228/unidbg](https://github.com/zhkl0228/unidbg) | **5341** | 2026-11-19 | Android native lib **emülasyonu** — SO kabuklarını statik çözmek için temel araç ([unidbg_tools](https://github.com/dqzg12300/unidbg_tools) 358★) |
| [WrBug/DeveloperHelper](https://github.com/WrBug/DeveloperHelper) | 1419 | 2025-08 | 界面分析+加固脱壳 helper (Android 9+) |
| [zyq8709/DexHunter](https://github.com/zyq8709/DexHunter) | 1357 | 2016-07 | Dex genel otomatik unpacker (klasik; modern fork: [Mufanc/DexHunter](https://github.com/Mufanc/DexHunter) 194★) |
| [strazzere/android-unpacker](https://github.com/strazzere/android-unpacker) | 1185 | 2020-01 | Defcon 22 "Android Hacker Protection Level 0" |
| [F8LEFT/FUPK3](https://github.com/F8LEFT/FUPK3) | 821 | 2019-04 | FUPK3 — FART öncesi ART unpacker efsanesi |
| [Youlor/Youpk](https://github.com/Youlor/Youpk) | 821 | 2021-10 | Youpk — ART aktif çağrı脱壳机 (ROM); paneli: [westinyang/unpacker-panel](https://github.com/westinyang/unpacker-panel) (189★) |
| [Youlor/unpacker](https://github.com/Youlor/unpacker) | 814 | 2022-06 | Youpk'nın tool reposu |
| [LaurieWired/BadUnboxing](https://github.com/LaurieWired/BadUnboxing) | 382 | 2025-08 | **Otomatik Android custom unpacker üreteci** (2024-25 yeniliği) |
| [ylcangel/crack_dexhelper](https://github.com/ylcangel/crack_dexhelper) | 507 | 2019-07 | **Bangcle企业版** detaylı RE + 2 unpacker (classes0.jar + frida hook) |
| [OakChen/ApkShelling](https://github.com/OakChen/ApkShelling) | 460 | 2021-05 | **360加固/梆梆加固/腾讯乐固/百度加固** ücretsiz sürümlerini tek araçla söker |
| [smartdone/dexdump](https://github.com/smartdone/dexdump) | 408 | 2018-09 | Xposed ile 1. nesil壳快速脱壳 |
| [CheckPointSW/android_unpacker](https://github.com/CheckPointSW/android_unpacker) | 365 | — | Check Point'in generic Android unpacker'ı |
| [CYRUS-STUDIO/CyReverse](https://github.com/CYRUS-STUDIO/CyReverse) | 303 | 2026-07 | Android RE örnek kod arşivi |
| [Ivonhoe/DexGuard](https://github.com/Ivonhoe/DexGuard) | 271 | 2022-07 | DexGuard gradle-plugin incelemesi (dex2jar önleme) |
| [index-login/MobileRE-Skill](https://github.com/index-login/MobileRE-Skill) | 291 | 2026-11 | **AI-ajan mobil RE skill seti**: Frida hook + 一键脱壳 + anti-detect + Ghidra MCP (2026) |
| [enovella/fridroid-unpacker](https://github.com/enovella/fridroid-unpacker) | 227 | 2025-12 | Java packer'ları Frida ile yenme |
| [wwh1004/JitUnpacker-Framework](https://github.com/wwh1004/JitUnpacker-Framework) | 230 | 2019-08 | JIT hook + unpacker çerçevesi |
| [quarkslab/legu_unpacker_2019](https://github.com/quarkslab/legu_unpacker_2019) | 214 | 2023-04 | **Tencent Legu** unpack script'leri (Quarkslab) |
| [Xposed-Modules-Repo/com.zhenxi.fundex2](https://github.com/Xposed-Modules-Repo/com.zhenxi.fundex2) | 261 | 2023-06 | FunDex脱壳机 (Android 5-13, class extraction) |
| [TimelifeCzy/Shell_Protect](https://github.com/TimelifeCzy/Shell_Protect) | 397 | 2026-04 | **VM 一键加壳/脱壳** (pack+unpack+anti-debug; 2026'da aktif) |
| [spriteviki/Dex2oatHunter](https://github.com/spriteviki/Dex2oatHunter) | 147 | 2016-06 | Otomatik dex unpack (DexHunter çağı) |
| [tiwe0/r0dump](https://github.com/tiwe0/r0dump) | 145 | 2026-11 | **Android 16 ART-entegre DEX dumper + onarım** (FART esinli; 2026) |
| [corellium/corellium-android-unpacking](https://github.com/corellium/corellium-android-unpacking) | 141 | 2025-11 | Corellium cihazlarıyla otomatik unpack |
| [CYRUS-STUDIO/frida_dex_dump](https://github.com/CYRUS-STUDIO/frida_dex_dump) | 124 | 2026-04 | Frida dex脱壳 (güncel bakım) |
| [Huai-Tian/Exuvia](https://github.com/Huai-Tian/Exuvia) | 52 | 2026-11 | **AI-ajanlar için deterministik Android unpack pipeline** (2026) |
| [CYRUS-STUDIO/FartFixer](https://github.com/CYRUS-STUDIO/FartFixer) | 30 | 2025-06 | FART çıktısını onarıp DEX'e birleştirir |
| [Alexjr2/Android_Dump_Dex](https://github.com/Alexjr2/Android_Dump_Dex) | 89 | 2025-10 | Frida script: **popüler packer'ları tespit + dump** (arm/arm64) |
| [asmjmp0/appdbg](https://github.com/asmjmp0/appdbg) | 262 | 2025-02 | Orijinal JVM'de app metodu çalıştırma |
| [saf3d0s/android-native-auto-reverse-skill](https://github.com/saf3d0s/android-native-auto-reverse-skill) | 29 | 2026-07 | APK/DEX/SO statik+dinamik otomatik RE skill'i (Codex) |
| [dzx1994/LeguDecompile](https://github.com/dzx1994/LeguDecompile) | 141 | 2019-02 | 乐固 so statik脱壳 + taklit加壳 |
| [FeilongTest/JiaguCleaner](https://github.com/FeilongTest/JiaguCleaner) | 28 | 2024-12 | **360加固脱壳修复** aracı |
| [NiLuogege/ApkShellingDemo](https://github.com/NiLuogege/ApkShellingDemo) | 29 | 2020-04 | Xposed ile 360/梆梆/乐固/百度 dex çıkarma demo |
| [malwaremusings/unpacker](https://github.com/malwaremusings/unpacker) | 121 | 2016-03 | Otomatik malware unpacker (2015 nesili) |
| [P4nda0s/panda-dex-dumper](https://github.com/P4nda0s/panda-dex-dumper) | 177 | 2023-02 | Rust dinamik dex dumper (frida'sız) |
| [Assasans/konofd-client-stub](https://github.com/Assasans/konofd-client-stub) | 11 | 2026-01 | **LIAPP** bypass client stub |
| [apkunpacker/unrasp_guard](https://github.com/apkunpacker/unrasp_guard) | 113 | 2022-06 | LolGuard anti-tamper/anti-Frida bypass |
| [oliverstank/super-un-pack-](https://github.com/oliverstank/super-un-pack-) | 1 | 2026-07 | Meta'nın **libsuperpack.so** unpack'ı (Unicorn emü) |
| [nitanmarcel/jadx-emu-dexguard-unpacker](https://github.com/nitanmarcel/jadx-emu-dexguard-unpacker) | 1 | 2026-11 | jadx-emu uzantısı — **DexGuard** gizli dex çıkarma (2026) |

**Packer-özel araştırmalar:**
- **DexProtector:** [romainthomas/dexprotector](https://github.com/romainthomas/dexprotector) (97★, 2025-12 — "A Glimpse Into DexProtector") · [autozw/DexProtectorTool](https://github.com/autozw/DexProtectorTool) (31★, **2026-11-08** — offline DEX kurtarma) · [huynambka/dexprotector_experiments](https://github.com/huynambka/dexprotector_experiments) (12★, 2026)
- **Bangcle (梆梆):** [KuNgia09/Bangcle](https://github.com/KuNgia09/Bangcle) (407★ — 2. nesil koruma RE) · [123456789zws/libDexHelper](https://github.com/123456789zws/libDexHelper) (3★, 2025-11 — libDexHelper.so frida bypass)
- **Payegis (通付盾):** [wanchouchou/ApkProtect](https://github.com/wanchouchou/ApkProtect) (185★ — 1. nesil koruma kaynağı)
- **Açık kaynak Android protector'ları (test üretimi):** [xopJack/XopProtector](https://github.com/xopJack/XopProtector) (263★, 2026-11'de aktif — DEX şifre+native shell+VMP) · [zhidun2027/zhidun](https://github.com/zhidun2027/zhidun) (74★, 2026-11 — DEX şifre+native shell) · [longtaoge/AndroidShell](https://github.com/longtaoge/AndroidShell) (172★) · [CodingGay/BlackObfuscator](https://github.com/CodingGay/BlackObfuscator) (1132★ — DEX obfuscator; AS eklentisi 473★, GUI 158★)

---

## A10) JavaScript (obfuscator.io / JS-Confuser / JSDefender / JScrambler / JSFuck / Luraph / Paranoid)

| Repo | Yıldız | Son aktivite | Not |
|---|---|---|---|
| [jehna/humanify](https://github.com/jehna/humanify) | 3313 | 2026-11-17 | ChatGPT ile JS deobfuscate (LLM dalgasının JS temsilcisi) |
| [j4k0xb/webcrack](https://github.com/j4k0xb/webcrack) | 3086 | 2026-11-19 | obfuscator.io çıktısı: deobf + unminify + unbundler |
| [aemkei/jsfuck](https://github.com/aemkei/jsfuck) | 8604 | 2025-03 | 6 karakterle JS yazma (obfuscator tarafı; test için) |
| [relative/synchrony](https://github.com/relative/synchrony) | 1269 | — | javascript-obfuscator temizleyici |
| [lelinhtinh/de4js](https://github.com/lelinhtinh/de4js) | 1582 | 2021-11 | Web tabanlı JS deobfuscator/unpacker (packer, obfuscator.io, JSFuck...) |
| [kuizuo/js-deobfuscator](https://github.com/kuizuo/js-deobfuscator) | 1193 | 2026-11-08 | Babel AST tabanlı otomatik deobf (playground+CLI; 2026'da aktif) |
| [ben-sb/javascript-deobfuscator](https://github.com/ben-sb/javascript-deobfuscator) | 1162 | — | Genel amaçlı |
| [ben-sb/obfuscator-io-deobfuscator](https://github.com/ben-sb/obfuscator-io-deobfuscator) | 812 | — | obfuscator.io özel |
| [HumanSecurity/restringer](https://github.com/HumanSecurity/restringer) | 621 | — | JS deobfuscator |
| [0xsdeo/AntiDebug_Breaker](https://github.com/0xsdeo/AntiDebug_Breaker) | 2266 | 2026-09-21 | **[KILL]** JS anti-debug/anti-devtools kırıcı |
| [LostMyCode/javascript-deobfuscator](https://github.com/LostMyCode/javascript-deobfuscator) | 192 | 2024-05 | Obfuscator.io çıktısı deobf |
| [giacomoferretti/paranoid-deobfuscator](https://github.com/giacomoferretti/paranoid-deobfuscator) | 91 | 2025-03 | **Paranoid** protector çıktısı deobf |
| [Ciarands/jscrambler-deobfuscator](https://github.com/Ciarands/jscrambler-deobfuscator) | 65 | 2026-11-24 | **JScrambler Enterprise** deobf (2026'da aktif) |
| [MichaelXF/js-confuser](https://github.com/MichaelXF/js-confuser) | 527 | 2026-08 | **[OBF]** JS-Confuser obfuscator (kendi VM'i: [js-confuser-vm](https://github.com/MichaelXF/js-confuser-vm) 24★) |
| [youdie323323/js-confuser-deobfuscator](https://github.com/youdie323323/js-confuser-deobfuscator) | 44 | 2025-12 | JS-Confuser deobf (+ [0v41n/JSConfuser-String-Decryptor](https://github.com/0v41n/JSConfuser-String-Decryptor) 36★) |
| [0v41n/JSDefender-Deobfuscator](https://github.com/0v41n/JSDefender-Deobfuscator) | 42 | 2025-03 | **JSDefender (PreEmptive)** deobf (+ [JorianWoltjer/deobfuscate-preemptive](https://github.com/JorianWoltjer/deobfuscate-preemptive) 9★) |
| [enkhee-Osiris/Decoder-JSFuck](https://github.com/enkhee-Osiris/Decoder-JSFuck) | 48 | 2023-06 | JSFuck decoder (alternatifler: de-jsfuck 41★, JSUNFuck 28★, unjsfuck 16★) |
| [munew/hcaptcha-wasm-deobfuscator](https://github.com/munew/hcaptcha-wasm-deobfuscator) | 62 | 2025-08 | hCaptcha HSW **WASM** deobf — WASM koruma örneği |
| [lolcaken/javascript-deobfuscator](https://github.com/lolcaken/javascript-deobfuscator) | 9 | 2026-10 | javascript-obfuscator 5.x deobf |
| [zhongguagua/ai-code-decompile](https://github.com/zhongguagua/ai-code-decompile) | 133 | 2026-01 | AI+AST tabanlı JS混淆还原 (Çince) |
| [coleleavitt/jsbeautify](https://github.com/coleleavitt/jsbeautify) | 11 | 2026-10 | Rust + Oxc, "agent-first" deobfuscator |
| [Sorte1/untwist](https://github.com/Sorte1/untwist) | 6 | 2026-11-25 | Rust (oxc) — obfuscator.io + minifier + unbundler geri alma (yeni) |
| [ejfkdev/jd](https://github.com/ejfkdev/jd) | 3 | 2026-08 | webcrack+synchrony'nin Go portu |
| [vertexdev246/unspooler](https://github.com/vertexdev246/unspooler) | 1 | 2026-11-20 | Tarayıcı-içi: JS-Confuser + javascript-obfuscator + **JSDefender** + packer geri sarma |

**Web anti-bot VM'leri (JSVMP/Ruishu):** bu korumalar ticari packer olmaktan öte SaaS — RE örnekleri [0xAllenChen/spider_reverse](https://github.com/0xAllenChen/spider_reverse) (948★; 瑞数/网易易盾/极验), [Charles-Hello/-228-](https://github.com/Charles-Hello/-228-) (170★; 抖音 jsvmp + devtools tespiti), [erma0/js-reverse-skill](https://github.com/erma0/js-reverse-skill) (91★, 2026-09).

---

## A11) Python (PyArmor / PyInstaller / Nuitka / pyc)

| Repo | Yıldız | Son aktivite | Not |
|---|---|---|---|
| [zrax/pycdc](https://github.com/zrax/pycdc) | 4683 | 2026-04 | Decompyle++ — pyc disassembler+decompiler (aktif fork'lar: [ejfkdev/pycdc](https://github.com/ejfkdev/pycdc) — Python 2.0–3.15; [zrsx/pycdc](https://github.com/zrsx/pycdc), 2026-11) |
| [extremecoders-re/pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) | 4536 | 2026-07 | PyInstaller Extractor — standart |
| [rocky/python-uncompyle6](https://github.com/rocky/python-uncompyle6) | 4333 | 2026-10 | Cross-version bytecode decompiler |
| [syssec-utd/pylingual](https://github.com/syssec-utd/pylingual) | 1453 | 2026-11-18 | **LLM tabanlı modern Python decompiler** (2025-26 yeniliği; pylingual.dev) |
| [rocky/python-decompile3](https://github.com/rocky/python-decompile3) | 1284 | 2026-07 | 3.7–3.8 decompiler |
| [pyinstxtractor/pyinstxtractor-ng](https://github.com/pyinstxtractor/pyinstxtractor-ng) | 747 | 2026-10 | Next Generation sürüm (+ [go portu](https://github.com/pyinstxtractor/pyinstxtractor-go) 169★) |
| [Svenskithesource/PyArmor-Unpacker](https://github.com/Svenskithesource/PyArmor-Unpacker) | 763 | — | PyArmor unpacker (eski sürümler) |
| [Lil-House/Pyarmor-Static-Unpack-1shot](https://github.com/Lil-House/Pyarmor-Static-Unpack-1shot) | 709 | 2026-11-01 | C++, **Pyarmor 8.0–9.3.x statik**, tek atış |
| [extremecoders-re/decompyle-builds](https://github.com/extremecoders-re/decompyle-builds) | 456 | 2026-05 | pycdc ön-derleme binary'leri |
| [serfend/pydumpck](https://github.com/serfend/pydumpck) | 400 | 2024-05 | exe/elf/pyz/pyc çoklu-thread decompile (pycdc+uncompyle6 tabanlı) |
| [extremecoders-re/nuitka-extractor](https://github.com/extremecoders-re/nuitka-extractor) | 249 | 2026-01 | **Nuitka** derlenmiş exe çıkarıcı |
| [DimaReverse/nuitka-static-unpacker](https://github.com/DimaReverse/nuitka-static-unpacker) | 139 | 2026-08 | Nuitka statik unpacker (+ [hexpyrion](https://github.com/DimaReverse/hexpyrion) 33★ kaynak kurtarma) |
| [u0pattern/PyArmor-Deobfuscator](https://github.com/u0pattern/PyArmor-Deobfuscator) | 113 | 2021-02 | PyArmor deobf (eski) |
| [extremecoders-re/bytecode_simplifier](https://github.com/extremecoders-re/bytecode_simplifier) | 127 | 2024-02 | **PjOrion** obfuscate Python deobf |
| [GDATAAdvancedAnalytics/Pyarmor-Tooling](https://github.com/GDATAAdvancedAnalytics/Pyarmor-Tooling) | 185 | 2026-07 | GDATA'ın PyArmor araçları |
| [venaxyt/mysterium](https://github.com/venaxyt/mysterium) | 176 | — | PyArmor benzeri protector (test için) |
| [ddouworld/pycdc-studio](https://github.com/ddouworld/pycdc-studio) | 44 | 2026-04 | pycdc/pycdas Qt GUI |
| [BarakAharoni/pycDcode](https://github.com/BarakAharoni/pycDcode) | 41 | 2026-05 | PYC bytecode decompilation |
| [vxnetrip/pyarmor-8-decrypt](https://github.com/vxnetrip/pyarmor-8-decrypt) | 36 | 2025-07 | PyArmor 8 decrypt |
| [Azim-Vau/antidc](https://github.com/Azim-Vau/antidc) | 12 | 2021-08 | **[OBF]** uncompyle6'ya karşı encode (negatif test) |
| [Fadi002/pyarmor-research](https://github.com/Fadi002/pyarmor-research) | 9 | 2026-08 | PyArmor RE notları |
| [opsecalyzer/pyinstxtractor-forMalware](https://github.com/opsecalyzer/pyinstxtractor-forMalware) | 4 | 2026-06 | PyInstaller çıkarıcı + PyArmor cracker + IOC tarayıcı tek komut |
| [obaby/BabyArmor](https://github.com/obaby/BabyArmor) | 6 | 2025-06 | **[OBF]** PyArmor mantıklı basit Python kripto |
| [ViewTechOrg/python-obfuscate](https://github.com/ViewTechOrg/python-obfuscate) | 6 | 2025-07 | **[OBF]** encode, anti-pycdc |

---

## A12) PHP (ionCube / SourceGuardian / Zend Guard)

Güvenilir, saygın bir açık kaynak decoder **yok**; "ionCube decoder" satan siteler büyük oranda dolandırıcılıktır. Genel amaçlı: [kaimi-io/php-eval-unpacker](https://github.com/kaimi-io/php-eval-unpacker) (12★, eval-zinciri çözümü).

---

## A13) Go / Rust / Lua / Mach-O

- [burrowers/garble](https://github.com/burrowers/garble) — 5840★; Go obfuscator (packer tarafı; karşılığı yok — garble çıktısını sembol kurtarma: `garble -debug` + [0xbytezone?] değil, görece tek yol RE araçları)
- [0xlane/ollvm-rust](https://github.com/0xlane/ollvm-rust) — 207★; rustc'ye dinamik yüklenen LLVM obfuscation pass'i
- [VAHPEM/rust-deobf](https://github.com/VAHPEM/rust-deobf) — 17★, **2026-11**; Rust binary'lerde obfuscation kurtarma (string/crate/flow)
- [hakaioffsec/lyra](https://github.com/hakaioffsec/lyra) — 32★, 2026-10; Rust için LLVM IR obfuscator
- [dannyisbad/kilij](https://github.com/dannyisbad/kilij) — 51★, 2026-02; LLVM 20 obfuscation framework (12 pass + bytecode VM)
- [NIKJOO/VM_Garble](https://github.com/NIKJOO/VM_Garble) — 10★, 2026-10; **Go binary obfuscation + virtualization**
- [carved4/go-crypter](https://github.com/carved4/go-crypter) — 33★, 2026-03; Go payload crypter (in-memory)
- [1-3-7/disrobe](https://github.com/1-3-7/disrobe) — 175★, 2026-11-23; Rust statik decompiler/deobfuscator/unpacker (Python disassembler dahil)
- **Lua:** [zeusssz/hercules-obfuscator](https://github.com/zeusssz/hercules-obfuscator) (238★ — obfuscator) · [jte/lua-decompiler](https://github.com/jte/lua-decompiler) (6★, 2026-10 — Lua 5.1-5.5/LuaJIT/Luau decompiler)
- **Mach-O:** [kam800/MachObfuscator](https://github.com/kam800/MachObfuscator) (543★ — obfuscator) · [horsicq/XMachOViewer](https://github.com/horsicq/XMachOViewer) (971★ — viewer) · [1ndahous3/macho-packers-collection](https://github.com/1ndahous3/macho-packers-collection) (0★, 2026-11-24 — Mach-O packer koleksiyonu, yeni)

---

## A14) LLVM / native obfuscation karşısı (devirt + deobf + MBA)

| Repo | Yıldız | Son aktivite | Not |
|---|---|---|---|
| [KasperskyLab/hrtng](https://github.com/KasperskyLab/hrtng) | 1976 | 2026-11-12 | Kaspersky'nin **IDA eklentisi**: deobf + decrypt + patch + lib tanıma |
| [RolfRolles/HexRaysDeob](https://github.com/RolfRolles/HexRaysDeob) | 806 | 2021-02 | Hex-Rays **microcode API** ile obfuscating compiler kırma (klasik) |
| [JonathanSalwan/Tigress_protection](https://github.com/JonathanSalwan/Tigress_protection) | 932 | 2023-11 | Tigress korumalarını kırma (Triton) |
| [19h/chernobog](https://github.com/19h/chernobog) | 313 | 2026-11-23 | Hex-Rays eklentisi — **Hikari LLVM** obfuscation çözme |
| [w00tzenheimer/d810-ng](https://github.com/w00tzenheimer/d810-ng) | 338 | 2026-09 | D-810'in yenilenmiş IDA eklentisi (MBA, CFF) |
| [amimo/ollvm-breaker](https://github.com/amimo/ollvm-breaker) | 447 | 2020-02 | Binary Ninja ile **OLLVM CFF düzleştirme** (Çince klasiği) |
| [mrphrazer/obfuscation_detection](https://github.com/mrphrazer/obfuscation_detection) | 688 | 2026-05 | Binary Ninja: obfuscate kodu otomatik tespit |
| [mrphrazer/msynth](https://github.com/mrphrazer/msynth) | 399 | 2026-09 | **MBA ifade sadeleştirme** framework'ü (Syntia tabanlı) |
| [mrphrazer/obfuscation_analysis](https://github.com/mrphrazer/obfuscation_analysis) | 260 | 2026-05 | Binary Ninja: obfuscate kod çözümleme + sadeleştirme |
| [mrphrazer/r2con2021_deobfuscation](https://github.com/mrphrazer/r2con2021_deobfuscation) | 204 | 2021-10 | VM tabanlı deobf workshop materyali |
| [leetonidas/demovfuscator](https://github.com/leetonidas/demovfuscator) | 768 | 2025-05 | movfuscator çıktısını geri döndürme |
| [eversinc33/MicroSMT](https://github.com/eversinc33/MicroSMT) | 82 | 2026-04 | IDA: opaque predicate kaldırma (microcode → z3) |
| [eversinc33/binaryshield-devirtualizer](https://github.com/eversinc33/binaryshield-devirtualizer) | 96 | 2026-05 | BinaryShield protector LLVM devirt |
| [joydo/d810](https://github.com/joydo/d810) (ayna; asıl kaynak: [gitlab.com/eshard/d810](https://gitlab.com/eshard/d810)) | 334 | 2023-12 | IDA: MBA/CFF deobf (fork: [zhkl0228/d810](https://github.com/zhkl0228/d810) 67★) |
| [overkazaf/D810G](https://github.com/overkazaf/D810G) | 8 | 2026-10 | **Ghidra'ya taşınan D-810**: OLLVM/Tigress deflatten + 60 MBA kuralı (2026!) |
| [fkie-cad/deflate-d](https://github.com/fkie-cad/deflate-d) | 2 | 2026-10-16 | Fraunhofer FKIE'nin yeni **deflattener**'ı (+ evaluation reposu) |
| [maskelihileci/IDA_Ollvm-unflattener](https://github.com/maskelihileci/IDA_Ollvm-unflattener) | 91 | 2025-04 | IDA: OLLVM CFF deobf |
| [xiaojianbang8888/OLLVM_Deobfuscator](https://github.com/xiaojianbang8888/OLLVM_Deobfuscator) | 71 | 2026-06 | OLLVM deobf aracı (Çince) |
| [bluesadi/debogus](https://github.com/bluesadi/debogus) | 70 | 2021-11 | angr ile OLLVM **bogus control flow** çözme (Pluto yazarından) |
| [za233/IDADeflat](https://github.com/za233/IDADeflat) | 45 | 2023-08 | IDA deflatten eklentisi |
| [Mac-XK/Deobfuscator](https://github.com/Mac-XK/Deobfuscator) | 34 | 2026-05 | Hikari statik restorasyon (Çince) |
| [NoAddr/yaps](https://github.com/NoAddr/yaps) | 21 | 2026-06 | PUSHAN-tipi **Tigress-benzeri VM devirt** (VPC-duyarlı CFG) |
| [xqzme69/Amice-Deobfuscator](https://github.com/xqzme69/Amice-Deobfuscator) | 10 | 2026-11-24 | fuqiuluo/amice LLVM IR devirt + string decrypt (Rust) |
| [jgajek/cff-deobfuscator](https://github.com/jgajek/cff-deobfuscator) | 8 | 2026-06 | IDA: CFF deobf |
| [aftermathlabs/ring-1.io](https://github.com/aftermathlabs/ring-1.io) | 114 | 2026-02 | ring-1.io **WASM obfuscation challenge** deobf/analizi |
| **MBA sadeleştirme:** [DenuvoSoftwareSolutions/GAMBA](https://github.com/DenuvoSoftwareSolutions/GAMBA) (257★) · [SiMBA](https://github.com/DenuvoSoftwareSolutions/SiMBA) (200★) · [mojtabafalleh/MBA-Simplifier](https://github.com/mojtabafalleh/MBA-Simplifier) (13★, 2025-09, Unicorn emü) · [xqzme69/A2MBA-LLVM](https://github.com/xqzme69/A2MBA-LLVM) (34★, 2026-11, sağlamlaştırma tarafı) | — | — | MBA zinciri: Denuvo'nun kendi araçları + topluluk |
| **Kaynak listesi:** [lich4/awesome-ollvm](https://github.com/lich4/awesome-ollvm) (67★) — "gerçekten awesome" OLLVM + IDA deobf kataloğu | | | |

---

## A15) Genel amaçlı unpack / dump / analiz çerçeveleri

| Araç | Yıldız | Not |
|---|---|---|
| [Bioruebe/UniExtract2](https://github.com/Bioruebe/UniExtract2) | 4489 | Universal Extractor 2 — her tür arşiv/kurulum paketi çıkarma (installer tarafı) |
| [redballoonsecurity/ofrak](https://github.com/redballoonsecurity/ofrak) | 2089 | **OFRAK**: binary unpack + modify + repack (Red Balloon) |
| [hasherezade/pe-sieve](https://github.com/hasherezade/pe-sieve) | 3955 | Süreç tarama + implant/hollowing tespiti + dump |
| [hasherezade/libpeconv](https://github.com/hasherezade/libpeconv) | 1400 | PE yükle/manipüle/dump kütüphanesi — pe-sieve'in motoru (unpacker yazmak için temel) |
| [hasherezade/hollows_hunter](https://github.com/hasherezade/hollows_hunter) | 2442 | Tüm süreçleri tarayıp döker |
| [hasherezade/mal_unpack](https://github.com/hasherezade/mal_unpack) (847★) + [mal_unpack_drv](https://github.com/hasherezade/mal_unpack_drv) (97★) | — | PE-sieve tabanlı dinamik unpacker (+ sürücü varyantı) |
| [unipacker/unipacker](https://github.com/unipacker/unipacker) | 785 | Emülasyon tabanlı otomatik unpacker (UPX/MPRESS/ASPack/PECompact…) |
| [NtQuery/Scylla](https://github.com/NtQuery/Scylla) | 1464 | **İAT rekonstrüksiyonu** klasiği; aktif fork: [ergrelet/Scylla](https://github.com/ergrelet/Scylla) (69★, Python binding) |
| [glmcdona/Process-Dump](https://github.com/glmcdona/Process-Dump) | 1872 | Bellekten PE geri yazma |
| [EquiFox/KsDumper](https://github.com/EquiFox/KsDumper) (1061★) + [mastercodeon314/KsDumper-11](https://github.com/mastercodeon314/KsDumper-11) (601★) | — | Kernel-uzay dumper; KsDumper-11 diriliş fork'u (2025-01) |
| [mrexodia/dumpulator](https://github.com/mrexodia/dumpulator) | 897 | Dump emülasyonu (Unicorn) — konfig çekme |
| [OALabs/PyIATRebuild](https://github.com/OALabs/PyIATRebuild) | 125 | Dump edilmiş PE için otomatik İAT rebuild (OALabs) |
| [hasherezade/IAT_patcher](https://github.com/hasherezade/IAT_patcher) | 269 | Kalıcı İAT hook uygulaması |
| [techlinn/MemPE](https://github.com/techlinn/MemPE) | 123 | Yüklenmiş/manuel-map edilmiş EXE/DLL için bellek dumper + rebuilder (2026-07) |
| [Phat3/PINdemonium](https://github.com/Phat3/PINdemonium) | 240 | Intel PIN tabanlı otomatik unpacker |
| [fkie-cad/GeMU](https://github.com/fkie-cad/GeMU) | 29 | QEMU tabanlı generic unpacker |
| [fkie-cad/RoAMer](https://github.com/fkie-cad/RoAMer) | 89 | Robust Automated Malware Unpacker (Fraunhofer) |
| [RolfRolles/FinSpyVM](https://github.com/RolfRolles/FinSpyVM) | 103 | **FinSpy VM** statik unpacker (sanallaştırılmış malware vakası) |
| [Fare9/ANBU](https://github.com/Fare9/ANBU) | 93 | PIN tabanlı öğrenme projesi |
| [carter-yagemann/vmi-unpack](https://github.com/carter-yagemann/vmi-unpack) | 55 | VMI (Xen introspection) unpacker |
| [eybisi/kavanoz](https://github.com/eybisi/kavanoz) | 159 | Android banker statik unpack |
| [nickcano/RelocBonus](https://github.com/nickcano/RelocBonus) | 313 | Windows Loader'ı unpacker'a çeviren obfuscation aracı (araştırmalık) |
| **horsicq unpacker suiti:** [XVolkolak](https://github.com/horsicq/XVolkolak) (unpacker **emülatörü**, 9★, 2026-08) · [XEmulUnpacker](https://github.com/horsicq/XEmulUnpacker) (7★) · [XStaticUnpacker](https://github.com/horsicq/XStaticUnpacker) (6★) · [XFileUnpacker](https://github.com/horsicq/XFileUnpacker) (9★) | — | DIE yazarının unpacker araç ailesi (hepsi güncel) |
| [aftermathlabs/bintests](https://github.com/aftermathlabs/bintests) | 86 | **32/64-bit PE test korpusu** — bin2bin dönüşüm doğrulama dosyaları (test seti olarak altın) |
| [1-3-7/disrobe](https://github.com/1-3-7/disrobe) | 175 | Rust statik decompiler/deobfuscator/unpacker (2026-11'de aktif) |
| [c3rb3ru5d3d53c/karton-unpacker](https://github.com/c3rb3ru5d3d53c/karton-unpacker) | 58 | Karton servis entegrasyonlu unpacker |
| [orca-zhang/unpack](https://github.com/orca-zhang/unpack) | 98 | Rust otomatik PE unpack (UPX/ASPack tanı+dök) |
| [anpa1200/Unpacker](https://github.com/anpa1200/Unpacker) | 46 | Tespit+unpack iş akışı (UPX/ASPack/Themida/VMP) |
| **Platformlar:** [x64dbg](https://github.com/x64dbg/x64dbg) (50.391★) · [SystemInformer](https://github.com/winsiderss/systeminformer) (16.579★) · [Ghidra](https://github.com/NationalSecurityAgency/ghidra) (101.313★) · [angr](https://github.com/angr/angr) (9416★) · [Unicorn](https://github.com/unicorn-engine/unicorn) (9612★) · [Qiling](https://github.com/qilingframework/qiling) (6201★) · [Triton](https://github.com/JonathanSalwan/Triton) (4384★, 2026-11'de aktif) · [miasm](https://github.com/cea-sec/miasm) (4021★) · [RetDec](https://github.com/avast/retdec) (8676★) · [flare-floss](https://github.com/mandiant/flare-floss) (4241★ — obfuscate string çözücü) · [mandiant/speakeasy](https://github.com/mandiant/speakeasy) (Windows emü) · [lief-project/LIEF](https://github.com/lief-project/LIEF) (5680★ — PE/ELF/DEX/Mach-O parse) · [erocarrera/pefile](https://github.com/erocarrera/pefile) (2092★ — Python PE parse) | — | — |

---

## A16) Packer/Protector TESPİT (dedektörler + imza veritabanları — bizim lig)

| Araç | Yıldız | Not |
|---|---|---|
| [horsicq/Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy) | 11999 | Endüstri standardı; imza+entropi; v3.21 (Nis 2026): 777 PE imzası; [DIE-engine](https://github.com/horsicq/DIE-engine) (3378★) ayrı paket |
| [ExeinfoASL/ASL](https://github.com/ExeinfoASL/ASL) + [Exeinfo](https://github.com/ExeinfoASL/Exeinfo) + [plugins](https://github.com/ExeinfoASL/plugins) | 1164 + 197 | **Exeinfo PE resmî GitHub depoları** (userdb ~4.469 imza; ASL org'u 2026-09'da aktif) |
| [rednaga/APKiD](https://github.com/rednaga/APKiD) | 2641 | Android: packer/protector/obfuscator tanıma (YARA) |
| [horsicq/XAPKDetector](https://github.com/horsicq/XAPKDetector) | 695 | APK/DEX detektör (DIE ailesi); C portu [CXAPKiD](https://github.com/horsicq/CXAPKiD) (3★, 2026-11) |
| [JusticeRage/Manalyze](https://github.com/JusticeRage/Manalyze) | 1156 | Statik PE analiz+packer tespiti |
| [Yara-Rules/rules](https://github.com/Yara-Rules/rules) | 4966 | Genel YARA seti (packer kuralları dahil) |
| [fr0gger/Yara-Unprotect](https://github.com/fr0gger/Yara-Unprotect) | 26 | [Unprotect](https://unprotect.it) teknikleri için YARA kuralları |
| [Nukem9/SwissArmyKnife](https://github.com/Nukem9/SwissArmyKnife) | 324 | x64dbg: PEiD/IDA imzaları + map/diff |
| [DosX-dev/PE-LiteScan](https://github.com/DosX-dev/PE-LiteScan) | 194 | Cross-platform sezgisel PE analiz |
| [packing-box/peid](https://github.com/packing-box/peid) | 154 | PEiD Python uyarlaması (2026-10'da aktif) |
| [packing-box/pypackerdetect](https://github.com/packing-box/pypackerdetect) (30★, bakımlı) / [cylance/PyPackerDetect](https://github.com/cylance/PyPackerDetect) (35★, orijinal) | — | Packed örnek tespiti (dataset curation) |
| [packing-box/bintropy](https://github.com/packing-box/bintropy) | 52 | Entropi tabanlı "packed mı?" analizi — packing-box araştırma org'u |
| [DosX-dev/FindEXEC](https://github.com/DosX-dev/FindExec) | 152 | EXE'leri NET/UPX/VMP... kategorilerine otomatik ayırır |
| [bin-maker/apkshell](https://github.com/bin-maker/apkshell) | 164 | APK'ların **hangi ticari sağlamlaştırıcıyla** paketlendiğini tespit (Çince, sürekli güncel) |
| [wolfram77web/app-peid](https://github.com/wolfram77web/app-peid) | 349 | Web PEiD |
| [mesaleh/PackiD](https://github.com/mesaleh/PackiD) | 12 | Packer identification kütüphanesi |
| [packgenome/PackGenome-Artifacts](https://github.com/packgenome/PackGenome-Artifacts) | 30 | Packer tespiti için otomatik sağlam YARA üretimi (NDSS çalışması) |
| [0pc0deFR/YaraRules](https://github.com/0pc0deFR/YaraRules) | 33 | Compiler/packer/protector YARA kuralları |
| [hACKCASCAC/ObfusHunter](https://github.com/hACKCASCAC/ObfusHunter) | 28 | **Obfus.h imzaları + anti-debug + PE koruma detektörü** (2026) |
| [hACKCASCAC/ObfusFake-Signatures-Remover](https://github.com/hACKCASCAC/ObfusFake-Signatures-Remover) | 10 | **Sahte VMProtect/Denuvo/Enigma imzalarını ayıklayıcı** — Obfus.h'in "fake protection" özelliği; dedektörler için negatif-test tehdidi (+ [ObfusHide-StringDumper](https://github.com/hACKCASCAC/ObfusHide-StringDumper) 4★) |
| [iaski15/DRMDetector](https://github.com/iaski15/DRMDetector) | 1 | Oyun exe'lerinde Denuvo/VMP/Themida/UPX/SteamStub taraması (WPF, 2026-08) |
| [anpa1200/Unpacker](https://github.com/anpa1200/Unpacker) | 46 | Tespit+unpack iş akışı |
| [cognis-digital/packpeek](https://github.com/cognis-digital/packpeek) | 5 | Statik packer parmak izi |
| [GHFear/Packernoculars](https://github.com/GHFear/Packernoculars) | 6 | Exe packer detector |
| [ShadowGuard-AI/file-executable-packer-detector](https://github.com/ShadowGuard-AI/file-executable-packer-detector) | 1 | Yeni; UPX/PECompact/… tespiti |
| [salmanmallah/packerscope](https://github.com/salmanmallah/packerscope) | 1 | 2026-10; modüler Python packer tespiti + entropi |
| [RootVandal/assay](https://github.com/RootVandal/assay) | 1 | 2026-07; PE/ELF/Mach-O triage (entropi, packer, imphash) |
| [5h4d0wn1k/m1-static-analyzer](https://github.com/5h4d0wn1k/m1-static-analyzer) (5★) · [ElenaFri/elfcheck](https://github.com/ElenaFri/elfcheck) (5★) · [suseheule-boop/file-typology-scanner](https://github.com/suseheule-boop/file-typology-scanner) (2★) | — | 2026'nın mini tespit araçları dalgası |
| [yj94/JADX-NO-MCP](https://github.com/yj94/JADX-NO-MCP) | 13 | jadx + **erken packer tespiti** + call graph (2026) |
| [Unprotect-Project/Unprotect_Submission](https://github.com/Unprotect-Project/Unprotect_Submission) | 210 | **Unprotect.it** — malware kaçınma teknikleri bilgi tabanı (2026-03'te aktif) |
| **PEiD imza ekosistemi:** [Xumeiquer/PEiD_to_Yara](https://github.com/Xumeiquer/PEiD_to_Yara) (7★) · [mcastilho/peid4yara](https://github.com/mcastilho/peid4yara) (3★) · [ElektroStudios/PEiD-File-Signatures-DB-Manager](https://github.com/ElektroStudios/PEiD-File-Signatures-DB-Manager) (5★, 2026-07) · [winest/FixUserDb](https://github.com/winest/FixUserDb) (3★, userdb temizleme) | — | PEiD userdb → YARA dönüşüm zinciri |

---

## A17) KILL — genel anti-anti-analiz araçları

| Araç | Yıldız | Not |
|---|---|---|
| [x64dbg/ScyllaHide](https://github.com/x64dbg/ScyllaHide) | 4398 | Kullanıcı-mod anti-anti-debug eklentisi (x64dbg/IDA/Olly) |
| [mrexodia/TitanHide](https://github.com/mrexodia/TitanHide) | 2977 | Kernel-mod gizleyici sürücü (2026-07'de aktif; VMP 3.10.3 fork'u: [CatCaller/TitanHide](https://github.com/CatCaller/TitanHide) 7★, 2026-03) |
| [HyperDbg/HyperDbg](https://github.com/HyperDbg/HyperDbg) | 4229 | Hipervizör tabanlı natif debugger (state-of-the-art) |
| [Air14/HyperHide](https://github.com/Air14/HyperHide) | 1681 | Hipervizör tabanlı anti-anti-debug (x64dbg eklentisi) |
| [zhaodice/qemu-anti-detection](https://github.com/zhaodice/qemu-anti-detection) | 1740 | QEMU'yu gizler — **VMP/VProtect/Themida/Enigma/Safengine + mhyprot/EAC/nProtect** anti-VM geçer; 2026-11'de aktif (fork: [GambitLatino](https://github.com/GambitLatino/qemu-anti-detection) 10★; kardeş: [proxmox-ve-anti-detection](https://github.com/zhaodice/proxmox-ve-anti-detection) 530★) |
| [0xsdeo/AntiDebug_Breaker](https://github.com/0xsdeo/AntiDebug_Breaker) | 2266 | JS ters-mühendislik: anti-debug kırıcı |
| [KiExitDispatcher/GoDefender](https://github.com/KiExitDispatcher/GoDefender) | 854 | Go için anti-VM/anti-debug/anti-sandbox **kütüphanesi** (koruma tarafını anlamak için) |
| [ThomasThelen/Anti-Debugging](https://github.com/ThomasThelen/Anti-Debugging) (633★) · [BaumFX/cpp-anti-debug](https://github.com/BaumFX/cpp-anti-debug) (590★) · [NotRequiem/antidbg](https://github.com/NotRequiem/antidbg) (358★) · [AdvDebug/AntiCrack-DotNet](https://github.com/AdvDebug/AntiCrack-DotNet) (356★) | — | Anti-debug teknik katalogları (savunma öğrenimi) |
| [HackOvert/AntiDBG](https://github.com/HackOvert/AntiDBG) | 814 | Anti-debug teknik kataloğu |
| [secrary/makin](https://github.com/secrary/makin) | 741 | Anti-debug/anti-VM numaralarını ifşa eder |
| [CheckPointSW/showstopper](https://github.com/CheckPointSW/showstopper) (227★) · [CheckPointSW/Anti-Debug-DB](https://github.com/CheckPointSW/Anti-Debug-DB) (71★) · [CheckPointSW/Evasions](https://github.com/CheckPointSW/Evasions) (448★) | — | Check Point'in anti-debug/kaçınma **ansiklopedileri** (2026'da güncel) |
| [guidedhacking/GH_AntiDebug_Bypass_Practice_Tool](https://github.com/guidedhacking/GH_AntiDebug_Bypass_Practice_Tool) (342★) · [Ricardonacif/gh-anti-debugging-bypass](https://github.com/Ricardonacif/gh-anti-debugging-bypass) (62★) | — | Anti-debug bypass antrenman araçları |
| [strivexjun/DriverInjectDll](https://github.com/strivexjun/DriverInjectDll) (540★) · [strivexjun/HideDll](https://github.com/strivexjun/HideDll) (110★) | — | Sürücü ile global DLL enjeksiyonu / DLL gizleme (XAntiDebug yazarı) |
| [lico-n/ZygiskFrida](https://github.com/lico-n/ZygiskFrida) | 1097 | Zygisk ile Frida gadget enjeksiyonu — **anti-tamper bypass** (Android; 2025-10) |
| [0xor0ne/debugoff](https://github.com/0xor0ne/debugoff) | 337 | Linux anti-debugging/anti-analysis Rust kütüphanesi |
| [A-new/aidbg](https://github.com/A-new/aidbg) | 61 | **AI-first x86/x64 komut satırı debugger**: JSONL + MCP + anti-anti-debug (ScyllaHide-tarzı) + snapshot (2026-11'de aktif; Çince) |
| [Fyyre/proxy_dll](https://github.com/Fyyre/proxy_dll) | 63 | CRT başlatmasını kullanarak korumalı uygulamalarda hook (2026-08) |
| [can1357/selene](https://github.com/can1357/selene) | 468 | Ring-2 kernel paravirtualizasyon — NoVmp yazarının araştırma platformu |
| [apkunpacker/unrasp_guard](https://github.com/apkunpacker/unrasp_guard) | 113 | Android anti-tamper/anti-Frida bypass |
| [Ishanoshada/Frida-Toolkit](https://github.com/Ishanoshada/Frida-Toolkit) | 27 | 650+ Frida script + native anti-tamper bypass (2026) |
| [KonBuku/VMDOG](https://github.com/KonBuku/VMDOG) | 64 | VMware spoof — tüm VMP sürümleri + SafeExam Browser |

---

## A18) Akademik devirtualizasyon / deobfuscation

| Repo / Kaynak | Yıldız | Not |
|---|---|---|
| [RUB-SysSec/syntia](https://github.com/RUB-SysSec/syntia) | 323 | **Syntia** — program synthesis ile deobfuscation (USENIX 2017; resmî repo) |
| [quarkslab/qsynthesis](https://github.com/quarkslab/qsynthesis) | 183 | **QSynthesis** — greybox synthesis ile assembly deobf (Quarkslab) |
| [s3team/VMHunt](https://github.com/s3team/VMHunt) | 185 | VM tabanlı korumada sanallaştırılmış bölge tespiti (+ [mrexodia/VMHunt_instracelog](https://github.com/mrexodia/VMHunt_instracelog) 19★) |
| [arnaugamez/r2syntia](https://github.com/arnaugamez/r2syntia) | 22 | Syntia ↔ radare2 entegrasyonu |
| [DenuvoSoftwareSolutions/GAMBA](https://github.com/DenuvoSoftwareSolutions/GAMBA) + [SiMBA](https://github.com/DenuvoSoftwareSolutions/SiMBA) | 257+200 | Genel/lineer MBA sadeleştirme (Denuvo resmî — devirt dünyasının referans algoritmaları) |
| [mrphrazer/msynth](https://github.com/mrphrazer/msynth) | 399 | MBA sadeleştirme framework'ü (Syntia-tabanlı) |
| Makale: *Semantic Validation of Packer Identification Tools* (2026) | — | Unpacker'ları orak olarak kullanıp packer-tespit araçlarını test/onarma çerçevesi — bu projenin "evren testleri" hedefiyle aynı damar |
| Makale: *UnSafengine64* — [MDPI Sensors 2024](https://www.mdpi.com/1424-8220/24/3/840) | — | Safengine Shielden kırma, akademik anlatım |
| Makale: Syntia (USENIX Sec 2017) · QSynthesis (USENIX Sec 2022) · PackGenome (NDSS) | — | Devirt/packer-imza hatlarının köşe taşları |

---

## A19) Son 12 ayın öne çıkanları (26.11.2025 → 26.11.2026)

> Kullanıcının isteği: "son bu yıl içinde paylaşılanlar çok güçlü" — 2025–2026 dalgası (yıldız | repo | son aktivite | alan):

| Repo | Yıldız | Son aktivite | Alan |
|---|---|---|---|
| [jehna/humanify](https://github.com/jehna/humanify) | 3313 | 2026-11-17 | JS deobf (LLM) |
| [x86rc/vmp-lazy-unpack](https://github.com/x86rc/vmp-lazy-unpack) | 500 | 2026-11-17 | VMP unpack |
| [x86rc/unthemidator](https://github.com/x86rc/unthemidator) | 473 | 2026-11-11 | Themida 3–4 unpack |
| [colby57/vid](https://github.com/colby57/vid) | 598 | 2026-08-17 | VMP İAT/PE rebuild |
| [VenTaz/Themidie](https://github.com/VenTaz/Themidie) | 585 | 2026-11-22 | Themida 3.x anti-debug bypass (x64dbg) |
| [Lil-House/Pyarmor-Static-Unpack-1shot](https://github.com/Lil-House/Pyarmor-Static-Unpack-1shot) | 709 | 2026-11-01 | PyArmor 8–9.3 statik |
| [jz0/tvm-devirt](https://github.com/jz0/tvm-devirt) | 168 | 2026-10-24 | **Tencent VM devirt** |
| [Momoko-Ayase/Senbei](https://github.com/Momoko-Ayase/Senbei) | 94 | 2026-11-18 | **CrackProof statik unpacker** |
| [NeuroSaki987/tvm-recover](https://github.com/NeuroSaki987/tvm-recover) | 88 | 2026-11-14 | TVM .tvm0 unpack + PE rewrite |
| [Adofyn1/VMPHide](https://github.com/Adofyn1/VMPHide) | 83 | 2026-09-11 | VMP anti-VM/anti-debug bypass |
| [sexyiam/VMPLift](https://github.com/sexyiam/VMPLift) | 70 | 2026-08-28 | VMP 3.8–3.10 handler lift |
| [notsnakesilent/VMPStatic](https://github.com/notsnakesilent/VMPStatic) | 180 | 2026-09-05 | VMP 1.x–3.x statik unpack |
| [YuroGod/VMPStaticUnpacker](https://github.com/YuroGod/VMPStaticUnpacker) | 153 | 2026-07-29 | VMP 3.9.5 statik |
| [kuizuo/js-deobfuscator](https://github.com/kuizuo/js-deobfuscator) | 1193 | 2026-11-08 | JS deobf (Babel AST) |
| [tiwe0/r0dump](https://github.com/tiwe0/r0dump) | 145 | 2026-11-08 | Android 16 ART DEX dumper |
| [KozDbg](https://github.com/ivanpotatoes/KozDbg) | 99 | 2026-11-17 | VMP 3.3–3.10 anti-anti-debug |
| [orca-zhang/unpack](https://github.com/orca-zhang/unpack) | 98 | 2026-11-25 | Otomatik PE unpack (Rust) |
| [romainthomas/dexprotector](https://github.com/romainthomas/dexprotector) | 97 | 2025-12-30 | DexProtector araştırması |
| [chramiq/de4vmp](https://github.com/chramiq/de4vmp) | 90 | 2026-03-14 | VMP .NET devirt |
| [sbga-tech/crackproof-unpacker](https://github.com/sbga-tech/crackproof-unpacker) | 18 | 2026-11-25 | CrackProof unpacker |
| [LaurieWired/BadUnboxing](https://github.com/LaurieWired/BadUnboxing) | 382 | 2025-08-23 | Android custom unpacker üreteci |
| [wul7chaos/vmp-reverse-skill](https://github.com/wul7chaos/vmp-reverse-skill) | 34 | 2026-09-28 | VMP devirt pipeline (IR) |
| [Fare9/Dragons-vs-VMs](https://github.com/Fare9/Dragons-vs-VMs) | 30 | 2026-10-24 | VMP analiz serisi |
| [godfearingman/thresh](https://github.com/godfearingman/thresh) | 10 | 2026-11-03 | VMP devirtualiser |
| [ReverseSec/vmpmylove](https://github.com/ReverseSec/vmpmylove) | 49 | 2026-11-07 | Çalıştırmadan VMP analizi |
| [plisskien/VMProtect-3.x-Emulator-Memory-Dumper](https://github.com/plisskien/VMProtect-3.x-Emulator-Memory-Dumper) | 11 | 2026-11-07 | Qiling/Unicorn emü-dump (3.10.4 test) |
| [UzawaReisaQwQ/codex-vmprotect-unpack-skill](https://github.com/UzawaReisaQwQ/codex-vmprotect-unpack-skill) | 6 | 2026-11-07 | AI-ajan VMP unpack skill (3.5.0–3.10.4!) |
| [7777lolonlyyou/VMProtect-LLM-SKILL](https://github.com/7777lolonlyyou/VMProtect-LLM-SKILL) | 5 | 2026-11-07 | LLM devirt workflow |
| [cockmanreal/VMP_DEVIRT](https://github.com/cockmanreal/VMP_DEVIRT) | 3 | 2026-11-06 | SMT + compiler devirt (VMP+Themida) |
| [BUnipendix/AnimeNoVMP](https://github.com/BUnipendix/AnimeNoVMP) | 3 | 2026-10-28 | NoVmp hardened fork |
| [msuiche/vmunprotect-aarch64](https://github.com/msuiche/vmunprotect-aarch64) | 3 | 2026-10-22 | Virbox/VMP aarch64 ELF unpack |
| [ivanpotatoes/VMProtect-Resource-Extractor](https://github.com/ivanpotatoes/VMProtect-Resource-Extractor) | 4 | 2026-11-16 | VMP resource extractor (3 mod) |
| [Ahora57/import_wrapper_attack](https://github.com/Ahora57/import_wrapper_attack) | 4 | 2026-11-19 | VMP 3.0–3.10.4 import saldırısı |
| [Hendi48/Magicmida](https://github.com/Hendi48/Magicmida) | 766 | 2026-05-14 | Themida unpacker |
| [aftermathlabs/themida-devirt](https://github.com/aftermathlabs/themida-devirt) | 128 | 2026-05-10 | Themida devirt |
| [Hendi48/ASpirin](https://github.com/Hendi48/ASpirin) | 28 | 2026-04-11 | ASProtect unpacker |
| [guoxing2024/magicmida-rs](https://github.com/guoxing2024/magicmida-rs) | 27 | 2026-11-24 | Magicmida Rust portu |
| [JacksonOnly/EazUnpacker](https://github.com/JacksonOnly/EazUnpacker) | 40 | 2026-11-14 | Eazfuscator unpack |
| [SychicBoy/NETReactorSlayer](https://github.com/SychicBoy/NETReactorSlayer) | 1286 | 2026-09-12 | .NET Reactor |
| [dawwinci/agile-net-devirtualizer](https://github.com/dawwinci/agile-net-devirtualizer) | 47 | 2026-08-08 | Agile.NET generic devirt |
| [Zypherion-Technologies/UnConfuserEx](https://github.com/Zypherion-Technologies/UnConfuserEx) | 48 | 2026-07-29 | ConfuserEx2 deobfuscator |
| [dib0/ConfuserNext](https://github.com/dib0/ConfuserNext) | 5 | 2026-11-04 | ConfuserEx devamı (protector!) |
| [BC-SECURITY/ConfuserEx3](https://github.com/BC-SECURITY/ConfuserEx3) | 1 | 2026-06-05 | ConfuserEx3 (protector!) |
| [jgajek/cilantro](https://github.com/jgajek/cilantro) | 6 | 2026-11-20 | .NET devirt (yeni) |
| [StylesFoundation/OpenZKM](https://github.com/stylesfoundation/OpenZKM) | 57 | 2026-10-30 | ZKM 27 rebuild |
| [DarkCreative1/zkm-deobfuscator](https://github.com/DarkCreative1/zkm-deobfuscator) | 30 | 2026-10-03 | ZKM statik deobf |
| [unleg1t/ZKM-27-Full-Deobfuscator](https://github.com/unleg1t/ZKM-27-Full-Deobfuscator) | 22 | 2026-09-27 | ZKM 27 tam deobf |
| [Skid-Technology/OpenAllatori](https://github.com/Skid-Technology/OpenAllatori) | 14 | 2026-11-02 | Allatori 9.9 paylaşımı |
| [Skid-Technology/OpenJNIC](https://github.com/Skid-Technology/OpenJNIC) | 38 | 2026-11-23 | JNIC 3.7.0 paylaşımı |
| [kboxcbh1337/kboxObfuscator](https://github.com/kboxcbh1337/kboxObfuscator) | 23 | 2026-11-15 | Java protector (JNIC+VMP) |
| [mxchu666/JnicDeobfuscator](https://github.com/mxchu666/JnicDeobfuscator) | 8 | 2026-11-16 | JNIC deobf |
| [syssec-utd/pylingual](https://github.com/syssec-utd/pylingual) | 1453 | 2026-11-18 | LLM Python decompiler |
| [extremecoders-re/nuitka-extractor](https://github.com/extremecoders-re/nuitka-extractor) | 249 | 2026-01-18 | Nuitka extractor |
| [techlinn/MemPE](https://github.com/techlinn/MemPE) | 123 | 2026-11-21 | PE memory dumper/rebuilder |
| [1-3-7/disrobe](https://github.com/1-3-7/disrobe) | 175 | 2026-11-23 | Rust unpacker/deobf |
| [mastercodeon314/KsDumper-11](https://github.com/mastercodeon314/KsDumper-11) | 601 | 2025-01-24 | KsDumper dirilişi |
| [index-login/MobileRE-Skill](https://github.com/index-login/MobileRE-Skill) | 291 | 2026-11-08 | AI-ajan mobil RE |
| [Huai-Tian/Exuvia](https://github.com/Huai-Tian/Exuvia) | 52 | 2026-11-08 | AI-ajan Android unpack pipeline |
| [ZiTanIOI/newBlackDex](https://github.com/ZiTanIOI/newBlackDex) | 142 | 2026-08-21 | BlackDex canlandırma |
| [autozw/DexProtectorTool](https://github.com/autozw/DexProtectorTool) | 31 | 2026-11-08 | DexProtector offline kurtarma |
| [xopJack/XopProtector](https://github.com/xopJack/XopProtector) | 263 | 2026-11-25 | Android protector (açık kaynak) |
| [zhidun2027/zhidun](https://github.com/zhidun2027/zhidun) | 74 | 2026-11-12 | Android protector (açık kaynak) |
| [sudfiona/NovaProtect](https://github.com/sudfiona/NovaProtect) | 64 | 2026-11-25 | PE packer (açık kaynak) |
| [iamsopotatoe-coder/TinyLoad](https://github.com/iamsopotatoe-coder/TinyLoad) | 208 | 2026-08-31 | x64 PE packer+crypter (kendi VM'i) |
| [noahware/binprotect](https://github.com/noahware/binprotect) | 360 | 2026-08-18 | bin2bin obfuscator (bölümsüz) |
| [nodiuus/nocturne](https://github.com/nodiuus/nocturne) | 180 | 2026-11-24 | bin2bin code virtualizer |
| [qusamulab/kagura](https://github.com/qusamulab/kagura) | 51 | 2026-11-25 | LLVM VM virtualization pass'i |
| [und3ath/xollvm](https://github.com/und3ath/xollvm) | 206 | 2026-11-12 | Modern LLVM obfuscator |
| [19h/morok](https://github.com/19h/morok) | 109 | 2026-11-23 | LLVM New-PM IR obfuscator |
| [Aethereux/Hikari-LLVM19](https://github.com/Aethereux/Hikari-LLVM19) | 152 | 2026-04-01 | Hikari, LLVM 19-20 |
| [eshard/obfuscator-llvm](https://github.com/eshard/obfuscator-llvm) | 415 | 2026-10-14 | eShard LLVM obfuscation pass |
| [overkazaf/D810G](https://github.com/overkazaf/D810G) | 8 | 2026-10-09 | Ghidra deobf framework'ü |
| [fkie-cad/deflate-d](https://github.com/fkie-cad/deflate-d) | 2 | 2026-10-16 | FKIE deflattener |
| [DosX-dev/obfus.h](https://github.com/DosX-dev/obfus.h) | 1889 | 2026-11-24 | C polimorfik obfuscation |
| [MulanYueh/VMProtect3.5.1](https://github.com/MulanYueh/VMProtect3.5.1) | 44 | 2026-08 | **3.5.1 kaynak aynası** |
| [eversinc33/MicroSMT](https://github.com/eversinc33/MicroSMT) | 82 | 2026-04-30 | Opaque predicate (IDA) |
| [DimaReverse/nuitka-static-unpacker](https://github.com/DimaReverse/nuitka-static-unpacker) | 139 | 2026-08-22 | Nuitka statik |
| [zhaodice/qemu-anti-detection](https://github.com/zhaodice/qemu-anti-detection) | 1740 | 2026-11-20 | Anti-VM gizleme |
| [A-new/aidbg](https://github.com/A-new/aidbg) | 61 | 2026-11-17 | AI-first debugger (anti-anti-debug) |
| [not1cyyy/PowerVM](https://github.com/not1cyyy/PowerVM) | 35 | 2026-08-07 | Anti-cheat debug hipervizörü |
| [reetamdan/hypervisor-crack-audit](https://github.com/reetamdan/hypervisor-crack-audit) | 330 | 2026-03-05 | Denuvo hypervisor auditi |
| [nathan-baggs/diamond](https://github.com/nathan-baggs/diamond) | 119 | 2026-01-09 | Denuvo hacking |
| [nckstwrt/SecuROMLoader](https://github.com/nckstwrt/SecuROMLoader) | 123 | 2026-01-16 | SecuROM uyumluluk |
| [nckstwrt/SafeDiscLoader2](https://github.com/nckstwrt/SafeDiscLoader2) | 86 | 2026-03-02 | SafeDisc uyumluluk |
| [extrant/Helldivers2-HD2-nProtect-Bypass-And-Dumper](https://github.com/extrant/Helldivers2-HD2-nProtect-Bypass-And-Dumper) | 8 | 2026-03-04 | nProtect bypass + unpack |
| [Lixense/ff-ace-anticheat-analysis](https://github.com/Lixense/ff-ace-anticheat-analysis) | 35 | 2026-09-03 | Tencent ACE analizi |
| [Ciarands/jscrambler-deobfuscator](https://github.com/Ciarands/jscrambler-deobfuscator) | 65 | 2026-11-24 | JScrambler deobf |
| [VAHPEM/rust-deobf](https://github.com/VAHPEM/rust-deobf) | 17 | 2026-11-21 | Rust deobf |
| [hakaioffsec/lyra](https://github.com/hakaioffsec/lyra) | 32 | 2026-10-10 | Rust LLVM obfuscator |
| [hACKCASCAC/ObfusHunter](https://github.com/hACKCASCAC/ObfusHunter) | 28 | 2026-05-20 | Obfus.h/anti-debug detektör |
| [yj94/JADX-NO-MCP](https://github.com/yj94/JADX-NO-MCP) | 13 | 2026-08-29 | jadx + packer tespiti |
| [horsicq/CXAPKiD](https://github.com/horsicq/CXAPKiD) | 3 | 2026-11-25 | APKiD C portu |
| [aftermathlabs/ring-1.io](https://github.com/aftermathlabs/ring-1.io) | 114 | 2026-02-07 | WASM obfuscation çözümü |
| [vmoranv/jshookmcp](https://github.com/vmoranv/jshookmcp) | 2131 | 2026-11-25 | AI-ajan RE workspace |
| [abeinb/x64dbg-MCP-Plugin](https://github.com/abeinb/x64dbg-MCP-Plugin) | 22 | 2026-07-02 | x64dbg MCP (VMP senaryoları) |
| [anpa1200/Unpacker](https://github.com/anpa1200/Unpacker) | 46 | 2026-10-28 | Tespit+unpack akışı |
| [Lucyferek-nunu/vmp-unpacker](https://github.com/Lucyferek-nunu/vmp-unpacker) | 12 | 2026-08-14 | VMP unpack + İAT |

---

## A20) Kaynak durumu özet tablosu (v2)

| Durum | Ürünler |
|---|---|
| **[AÇIK] Resmî açık kaynak** | UPX · ConfuserEx (+mkaring fork, ConfuserEx3, ConfuserNext) · KoiVM (+DarksVM/CawkVM modları) · BitMono · Obfuscar · Hydra · obfuz · Mdcrypt · AstroNet · Origami · MurkyStrings · O-LLVM/Hikari/Pluto/Armariris/goron/Polaris/DeClang/O-MVLL/dProtect/ollvm16/17/xollvm/morok/lyra/kilij/Himitsu/Taokari/eshard-obfuscator-llvm · amice · ROPfuscator · movfuscator · garble/gobfuscate/VM_Garble/ollvm-rust · Tigress (site) · javascript-obfuscator · JS-Confuser (+vm) · JSFuck · ProGuard/R8/yGuard · Nuitka · PyArmor (yalnız CLI) · PjOrion (ölü) · obfus.h / obfusheader.h / es3n1n-obfuscator / Astral-PE / ASM-Guard / BinProtect / TinyLoad / Nocturne / pe-union / Ryujin / Obsidian / YAP / PEP / AlushPacker / wvmp / rewolf-x86-virtualizer / kagura / chum / cvm.h · KiteShield/maya (ELF) · x0rro/nimcrypt/NullCrypt · BatchToApp/NET-MalwareCryptor (DosX ailesi) · XopProtector/zhidun/BlackObfuscator/AndroidShell (Android) · NovaProtect · MachObfuscator · hercules (Lua) · BeeByte **(kaynağı paylaşıldı — [TouMobSiab](https://github.com/TouMobSiab/BeeByte-Obfuscation-Source-Code-))** |
| **[LEAKED] Sızan/paylaşılan açık kaynak** | **VMProtect 3.5.1** (Aralık 2023; canlı aynalar: [MulanYueh](https://github.com/MulanYueh/VMProtect3.5.1), [WongHouLeong](https://github.com/WongHouLeong/VMProtect-Source-Code-LEAK), [GitLab](https://huihui.cat/mirrors/vmprotect-3.5.1); orijinal jmpoep DMCA'lı) · **Allatori v3.0** ([netindev/Allatori-v3.0](https://github.com/netindev/Allatori-v3.0), 2016) + 2026 paylaşımı [OpenAllatori](https://github.com/Skid-Technology/OpenAllatori) (9.9) · **JNIC 3.7.0** ([Skid-Technology/OpenJNIC](https://github.com/Skid-Technology/OpenJNIC)) + açık klonlar j2c/MyJ2C · **Binsecure 1.8.3** ([Astra-520](https://github.com/Astra-520/Binsecure-1.8.3)) · **BeeByte kaynak** (şirket kapandı) · **Molebox eski sürüm** ([sudachen](https://github.com/sudachen/Molebox)) · **Payegis 1. nesil** ([ApkProtect](https://github.com/wanchouchou/ApkProtect)) |
| **[KAPALI] Kaynak yok** | VMProtect 3.0.9–3.10.4 (3.5.1 hariç) + 3.10.5/3.10.6/3.11 · Themida/WinLicense/Code Virtualizer · Enigma Protector/EVB · VxLang (beta kapalı, Patreon) · Obsidium · ASProtect · EXECryptor · Armadillo/SoftwarePassport · SDProtector · XProtector · StarForce · Safengine Shielden · PELock (motor; SDK açık) · CrackProof · Tencent VM (TVM) · VProtect · ExeStealth · Milfuscator · HeartCrypt (PaaS) · BoxedApp · MoleBox (yeni) · PECompact · ASPack · MPRESS · NSPack · FSG/MEW/UPack/Petite/tElock/RLPack/WWPack/Neolite/eXPressor/SVKP/Morphine/Yoda/PECrypt · hXOR (kaynaklı ama ürün değil — o açık) · Sentinel HASP · CodeMeter · Denuvo · SteamStub/CEG · SecuROM · SafeDisc · SolidShield · Tages · anti-cheat sürücüleri (EAC/BE/XIGNCODE/nProtect/HackShield/mhyprot/ACE/Vanguard) · .NET Reactor · IntelliLock · Dotfuscator · Eazfuscator · SmartAssembly · Babel · Agile.NET · Spices · DeepSea · Goliath · Phoenix · DotKill · Xenocode/Postbuild · NetZ · KoiVM'in ticari paketlenişleri · DexGuard · Allatori (güncel) · Zelix KlassMaster (27!) · Stringer · DashO · JNIC (resmî) · Binsecure (güncel) · kboxObfuscator · Bangcle · Ijiami · 360 Jiagu · Tencent Legu · Baidu · SecNeo · Virbox · Yidun · Dingxiang · Kiwi · Naga · LIAPP · AppGuard · AppSealing · Promon · Arxan · DexProtector · JScrambler · JSDefender · Luraph · Paranoid · JSVMP/Ruishu · ionCube · SourceGuardian · Zend Guard · phpBolt · Nu-Coder · PyArmor (çekirdek) · Arkari (ücretli LLVM) |

---

## A21) Kaynaklar / koleksiyonlar

- [lich4/awesome-ollvm](https://github.com/lich4/awesome-ollvm) — OLLVM + IDA deobf kataloğu (Çince, 67★)
- [lmy375/awesome-vmp](https://github.com/lmy375/awesome-vmp) — VMP analiz kaynak koleksiyonu (Çince, 1096★)
- [NotPrab/.NET-Deobfuscator](https://github.com/NotPrab/.NET-Deobfuscator) (1531★) + [NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator) (1500★) — .NET protector↔araç eşleme listeleri
- [GenericException/SkidSuite](https://github.com/GenericException/SkidSuite) — Java RE araç koleksiyonu (355★)
- [Unprotect-Project/Unprotect_Submission](https://github.com/Unprotect-Project/Unprotect_Submission) + [unprotect.it](https://unprotect.it) — malware kaçınma teknikleri ansiklopedisi (210★) + [Yara-Unprotect](https://github.com/fr0gger/Yara-Unprotect)
- [TideSec/GoBypassAV](https://github.com/TideSec/GoBypassAV) — Go tabanlı免杀 (AV-bypass) teknik/araç derlemesi: 加壳 dahil (1187★, Çince)
- [AreWeAntiCheatYet](https://github.com/AreWeAntiCheatYet/AreWeAntiCheatYet) — anti-cheat oyun veritabanı (517★) · [PCGamingWiki anti-cheat listesi](https://www.pcgamingwiki.com/wiki/List_of_games_with_anti-cheat_technology)
- [packing-box](https://github.com/packing-box) org'u — peid/pypackerdetect/bintropy + paketleme araştırmaları (packing detection çalışmaları)
- `_xeroxz` blog + repolar: [git.back.engineering/_xeroxz](https://git.back.engineering/_xeroxz) (vmp2, vmprofiler — GitHub dışı)
- [DenuvoSoftwareSolutions](https://github.com/DenuvoSoftwareSolutions) — Denuvo'nun resmî GitHub org'u (GAMBA, SiMBA)
- [momo5502/denuvo-slides](https://github.com/momo5502/denuvo-slides) + [momo5502.com/slides/denuvo](https://momo5502.com/slides/denuvo) — Denuvo RE sunumu
- [Connor-Jay'ın Denuvo analiz blogu](https://connorjaydunn.github.io/blog/posts/denuvo-analysis) (Oca 2025)
- [UnSafengine64 — MDPI Sensors 2024 makalesi](https://www.mdpi.com/1424-8220/24/3/840) (S. Choi)
- [vmpsoft.com/news](https://vmpsoft.com/news) — VMProtect resmî sürüm geçmişi · [oreans.com](https://www.oreans.com) · [enigmaprotector.com](https://enigmaprotector.com/en/news.html) · [vxlang.github.io](https://vxlang.github.io/)
- [github.com/topics/vmprotect](https://github.com/topics/vmprotect) · [topics/unpacker](https://github.com/topics/unpacker) · [topics/packer](https://github.com/topics/packer)
- Forum mirası: Tuts4You "Packers & Protectors" bölümü · EXETOOLS arşivi · 0x00sec
- [aftermathlabs/bintests](https://github.com/aftermathlabs/bintests) — bin2bin doğrulama PE test korpusu (86★)

---

*Derleme: MVP_GOD_SSS_TIER_PACKER_FINDER — v2, 26.11.2026. 260+ GitHub API sorgusu, 160+ yazar/org taraması; ham veriler `scripts/gh_derin*.py` + `work/gh_data2/` altında saklanır.*
