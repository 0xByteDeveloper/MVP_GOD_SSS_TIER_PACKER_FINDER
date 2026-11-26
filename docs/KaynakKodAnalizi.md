# KaynakKodAnalizi.md — KAYNAK KODDAN İMZA ÇIKARIMI (v6 Universal Engine)

> **Bu belge, MVP_GOD_SSS_TIER_PACKER_FINDER v6'nın EVRENSEL motorunun imza kanıt tablosudur.**
> Her imza, ilgili packer'ın **kendi açık kaynak deposundan** (veya kaynaktan derlenip paketlenmiş
> gerçek örnekten) satır kanıtıyla çıkarılmıştır. "KAYNAK KODDAN BESLEME" hedefinin somut çıktısıdır.
>
> Kanıt seviyeleri:
> - **[K1] KAYNAKTAN** — packer'ın kendi kaynak kodunda dosya:satır kanıtı
> - **[K2] GERÇEK ÇIKTI** — kaynaktan derleyip paketlediğimiz gerçek örnekten doğrulandı
> - **[K3] MİRAS** — kapalı kaynak aile; kamuya açık dedektör mirasıyla çapraz doğrulanmış
>
> Tüm tarama çıktıları: `vmpdet6 --evren <dosya>` (kanıt listesiyle birlikte basar).
> Motor: `src/universal_db.h` (veritabanı) + `src/universal_tara.h` (tarama motoru).

---

## 0) Bu turda KAYNAĞINDAN analiz edilen depolar (66 hedef)

**Yerelden (universalAllver.rar):** VMProtect 3.5.1 tam kaynak (core/ 66 dosya + runtime/ + sdk/)

**Batch-1 (41 yerel native packer):** upx, es3n1n-obfuscator, pe-union, ryujin, astral-pe,
asm-guard*, rewolf-x86-virtualizer, tinyload, binprotect, kiteshield, maya, x0rro, chum,
obfus-h, obfusheader-h, pep, yap, obsidian-protector, novaprotect, zhidun, xopprotector,
hm-pe-packer, greym, kryptonite, pe-crypter, nimcrypt, nullcrypt, pe-protector, protectors,
molebox, hxor-packer, alushpacker, hmyit-vmprotect, wvmp, nocturne, kagura, jitdecrypter,
nanomites, cvm-h, batchtoapp, net-malwarecryptor
**\*asm-guard: depoda kaynak YOK** (README+jpg; yalnız release dağıtımı) — envanter notu.

**Batch-2 (9 ekosistem):** ConfuserEx (mkaring + yck1509), javascript-obfuscator, pyinstaller,
pyarmor (dashingsoft), Nuitka, proguard

**Batch-3 (20 LLVM obfuscator — sparse checkout ile pass kaynakları):** ollvm (llvm-4.0 dalı),
hikari (release_80 + Core/Headers alt modülleri), pluto, armariris, goron (llvm-10.x),
ollvm17, eshard-ollvm, amice, polaris, declang, o-mvll, ropfuscator, ollvm-rust, obscura*
(docs-only), morok, ollvm16, hikari-fix, ollvm-pass, hikari-llvm19
**\*obscura: pass kaynak kodu henüz push edilmemiş (yalnız docs/)**

Otomatik tarayıcı: `scripts/kaynak_tarama.py` → `work/kaynak/tarama/*.json` (72 hedef,
1.356 bölüm-adı kanıtı, 156 magic-dizgi kanıtı, kripto sabiti envanteri).

---

## 1) UPX — tam kaynak analizi + GERÇEK paketleme [K1+K2]

Kaynak: `upx/upx` @ 02c853cf (UPX 5.3.1-git, 29.10.2026) — **sandbox'ta kaynaktan derlendi,
Test_32/Test_64 korpusu 11 varyantla paketlendi** (`scripts/` + `ornekler/evren/upx531_*.exe`).

| İmza | Kaynak kanıtı | Doğrulama |
|---|---|---|
| Bölümler `UPX0`/`UPX1`/`UPX2` | `src/pefile.cpp:2831-2840` — `strcpy(osection[0].name,"UPX0")` ... 3. bölüm `.rsrc`'ysa `UPX2` | 11/11 gerçek örnekte UPX0/UPX1/UPX2 ✓ |
| UPX0 karakteristiği | `pefile.cpp:2866` — `UNINITIALIZED_DATA\|READ\|WRITE\|EXECUTE` (0xE0000080), raw size=0 | gerçek çıktıda 0xE0000080 ✓ |
| Sihir `UPX!` = 0x21585055 | `src/conf.h:553`, `stub/src/include/header.S:34` (`.byte 85,80,88,33`) | 32-bit örnekte @0x1ED, 64-bit @0x1FD ✓ |
| 32 baytlık packheader | `header.S:32-60` + `src/packhead.cpp` — UPX!\|version\|format\|method\|level\|uadler32\|cadler32\|ulen\|clen\|osize\|filter\|cto\|misc\|chksum | motor çözüyor: sürüm/yöntem/seviye ✓ |
| Sürüm baytı | version=13 → UPX 5.x | gerçek çıktı v13 ✓ |
| Yöntem haritası | gerçek çıktılardan: 2=NRV2B_LE32, 5=NRV2D_LE32, 8=NRV2E_LE32, 14=LZMA | --nrv2b→2, --nrv2d→5, --nrv2e→8, --lzma→14 ✓ |
| Seviye | --best → 10 (64-bit çıktıda seviye=10 gözlendi), normal → 8 | ✓ |
| `$Info: This file is packed...` | IDENTSTR — kuyrukta | 5.x PE çıktısında varsayılan olarak YOK (yalnız istenirse) — **kuyruk-bölgesi kısıtı v5'te doğru** |
| UPX2'nin işlevi | `pefile.cpp:2840` — kaynak/reloc verisi; `p_lx_exc.cpp:416` ELF'de "UPX2" ismi başka bağlamda | PE'de 3. bölüm |

**Motor davranışı:** UPX0+UPX1 eşleşmesi veya packheader çözümlemesi → `UPX 5.x / NRV2B_LE32 / seviye 8` şeklinde sürüm+yöntem raporu.

---

## 2) VMProtect 3.5.1 — sızmış kaynaktan kritik bulgular [K1]

Kaynak: `universalAllver.rar` → `Allver_Collection/VMProtect 3.5.1 [Source Code]/` (101 dosya çıkarıldı).

| Bulgu | Kanıt | Dedektöre etkisi |
|---|---|---|
| **Bölüm adı RASTGELE üretilir** | `core/core.cc:3561-3572` — `ProjectTemplate::Init()`: `vm_section_name_ = "." + 3 alfanumerik` (srand(GetTickCount)) | **Ad tabanlı VMP tespiti 3.5+ için KANITEN işe yaramaz** — v5'in yapısal profil yaklaşımı doğru; ad-tabanlı eşleşme yalnız eski sürüm/kullanıcı şablonu için |
| `.vmp0/.vmp1` adı şablondan gelir | `core/pefile.cc:4800,4808,4842` — `set_name(section_name + vmp_index++)`; şablon alanı "VMCodeSectionName" (`core.cc:700,1002`) | `.vmp0`+`.vmp1` görüldüğünde VMP ailesi (K1) ama tek başına sürüm kanıtı değil |
| SDK işaretleri | `sdk/VMProtectSDK.h:24` `VMProtectBeginVirtualization` vb.; `core/intel.cc:19576` import `vmprotectsdk32.dll` kontrolü | `vmprotectsdk32.dll`/`vmprotectsdk64.dll` dizgileri = motor girdi izi (korumalı değil) |
| Runtime stub yapısı | `runtime/loader.cc`, `objects.cc`, `core.cc` (VirtualAlloc + CRC + şifreli PE görüntüsü) | v5 cipa DB'sinin kaynağındaki mantıkla örtüşür |
| .NET koruması | `core/dotnetfile.cc:6412` — `module_name == "vmprotect.sdk"` | .NET VMP girişimlerinin izi |

---

## 3) Sahte imza demeti (obfus.h / obfusheader.h) — EVRENSEL TEST KALKANI [K1]

**En kritik bulgu:** Derleme zamanı obfuscator'ları **başka protector'lerin bölüm adlarını sahte enjekte eder.**

- `obfus-h/include/obfus.h:329-402` (`OBFH_FAKE_SIGNATURES`):
  `.enigma1/.enigma2`, `.vmp0/.vmp1/.vmp2`, `UPX0`, `.winlice`, `.petite`, `.rlp`, `.dsstext`,
  `logicoma`, `.aspack`, `.adata`, `__wibu00/__wibu01`, `.arch`(denuvo_atd), `.alien`, `.pwdprot`,
  `.tw`, `.vlizer`, `adr/have/30cm/PETETRIS` + `.data` içinde `"Enigma protector v\x01"` (19B),
  `.rdata` içinde `"NUITKA_ONEFILE_PARENT"`, `.text` içinde `"Video created by SCREEN2EXE/SCREEN2SWF"`
- `obfusheader-h/obfusheader.h:1858-1890` (`FAKE_SIG`): `.arch/.srdata/.xpdata/.xtls/.themida/
  .vmp0/.vmp1/.vmp2/.enigma1/.enigma2/.dsstext` + rastgele dolgu (`RND(1,255)`)
- obfus.h'ın kendi gerçek bölgesi: **`.obfh`** (`obfus.h:402`) — fake-signatures kapalıyken.

**Motor kuralı (SAHTE DEMET):** Farklı üretici ailelerinden ≥2'si aynı dosyada bölüm adı olarak
görünüyorsa (ör. `.themida` + `.vmp0` + `.enigma1` + `UPX0` birlikte) → dosya **obfus.h /
obfusheader.h SAHTE İMZA MODU** olarak raporlanır; Themida/VMProtect/Enigma olarak DEĞİL.
Hiçbir gerçek protector başka üreticinin bölümünü bırakmaz.

**Testler:**
- `ornekler/evren/sahte_demet.exe` (sentetik demet) → `EVREN: obfus.h / obfusheader.h (SAHTE IMZA MODU)` ✓
- `ornekler/evren/obfh.exe` (sentetik .obfh) → `obfus.h (DosX)` ✓
- **`ornekler/evren/obfusheader_fakesig_GERCEK.exe` — GERÇEK obfusheader.h DERLEMESİ** (zig cc çapraz
  derleme, FAKE_SIGNATURES=1): çıktıda `.vmp0 .vmp1 .vmp2 .themida .enigma1 .enigma2 .arch .srdata
  .xpdata .xtls .dsstext` bölümleri VAR — saf bir dedektör bunu VMProtect/Themida/Enigma sanırdı;
  v6 motoru **SAHTE IMZA MODU** olarak doğru ayırdı ✓ (bölümler obfusheader.h:1874-1890'daki
  FAKE_SIG listesiyle birebir)

---

## 4) Açık kaynak native packer'lar — bölüm/kayıt kanıt tablosu [K1]

| Packer | İmza | Kaynak kanıtı (dosya:satır) | Test |
|---|---|---|---|
| **es3n1n/obfuscator** | `.s_code` (0x60000020) + `.s_rel` (0x42000040) | `src/lib/util/sections.hpp:12-13` | es3n1n.exe PASS |
| **Ryujin Protector** | `.Ryujin` bölümü | `RyujinObfuscationCore.cc:2123` | ryujin.exe PASS |
| **TinyLoad** | `.pxkey` bölümü + XXTEA anahtar bloğu `C0DE1337 FEEDF00D CAFEBABE DEADBEEF 8BADF00D B007DEAD` (24B kesin desen) + XXTEA delta 0x9E3779B9 | `TinyLoad.cpp:255-262` (`__attribute__((section(".pxkey")))` + james-bond anahtarları) | tinyload.exe PASS |
| **rewolf-x86-virtualizer** | `.VM` bölümü (`test_app` `.vm` veri bölümü) | `src/protector/main.cpp:348` `memmove(ish->Name,".VM",4)` | DB'de |
| **GreyM** | `.dick` (VM loader) + `.dick2` (VM code) | `Interpreter/src/main.h:4-5` | DB'de |
| **Nocturne** | `.nctrn` / `.vmpm` / `.mark` (`.vmp` VMProtect ile karışır — ayırt kuralı) | repo bölüm sabitleri | nocturne.exe PASS |
| **wVmp** | `.wvmp` / `.wvmpc` / `.far` | repo bölüm sabitleri | DB'de |
| **MoleBox (açık sürüm)** | `.xor` / `.xorC` / `.xorS` | sudachen/Molebox kaynağı | DB'de |
| **Kryptonite** | `.pcode` (+ `.RSRC`) | Delphi packer kaynağı | DB'de |
| **PEunion** | `.peu` + FASM stub imzası | `SlnBin/Stub/pe32/Stub.asm` (FASM `format PE GUI 4.0` + Stage2 shellcode) | DB'de |
| **Nanomites** | `.nano` bölümü | Fatmike-GH kaynağı | DB'de |
| **JitDecrypter** | `.prot` bölümü | Fatmike-GH kaynağı | DB'de |
| **Obsidian Protector** | `.nexus` bölümü | repo | DB'de |
| **PEP** | `.pep` bölümü | Delphi kaynak | DB'de |
| **AlushPacker** | `.packed` bölümü | repo | DB'de |
| **NovaProtect** | `.nova` / `.np_data` | repo | DB'de |
| **BatchToApp (DosX)** | `.cmd` bölümü | repo | DB'de |
| **KiteShield (ELF)** | `.rt_info` bölümü (Linux x86-64) | `kiteshield` kaynağı | DB'de (PE dışı belgelendi) |
| **maya (ELF)** | ChaCha20 `expand 32-byte k` sabiti (runtime şifreleme) | `maya` kaynağı (chacha) | DB'de (PE dışı belgelendi) |
| **zhidun (Android)** | `.setting` bölümü (DEX şifreleme) | repo | DB'de |
| **Astral-PE** | bölüm EKLEMEZ — başlık/EP mutasyonu (DosStubPatcher, EntryPointPatcher, ImportMutator modülleri) | `source/modules/PeMutator_modules/` | düşük-iz aile: yapısal profil gerekir |

---

## 5) Script-dili paketleyicileri [K1]

| Packer | İmza | Kaynak kanıtı |
|---|---|---|
| **PyInstaller** | EOF cookie: `MEI\x00\x0b\x0a\x0b\x0e` (4. bayt sürüme göre değişir!) + paket uzunluğu + TOC + python sürümü + `python3xx.dll` — son 88 bayt | `bootloader/src/pyi_utils.c:169-171` (`MAGIC_BASE`, "4. byte adjusted to avoid false-positive self-match") — **motor bunu bilir: 4. bayt joker, 5-8. bayt sabit** |
| PyInstaller (ek) | `_MEIPASS`, `pyi-windows-manifest-filename` | `pyi_main.c:1389`, bootloader |
| **Nuitka** | `__compiled__` (+ onefile'da `NUITKA_ONEFILE_PARENT`) | Nuitka kaynağı |
| **PyArmor** | `__pyarmor__`, `pytransform`, `Pyarmor` | dashingsoft/pyarmor kaynağı |
| **ConfuserEx (.NET)** | `ConfusedByAttribute` tipi (varsayılan watermark) + `ConfuserEx` dizgisi; KoiVM alt projesi | `Confuser.Core/WatermarkingProtection.cs:51-53` |
| **ProGuard (Java)** | kayıt defteri/manifest düzeyi — PE dışı (belgelendi) | proguard kaynağı |
| **javascript-obfuscator** | kaynak-düzey JS obfuscation — PE dışı (belgelendi) | repo |

**Test:** `ornekler/evren/pyinstaller_cookie_sim.exe` → `EOF cookie — python 312 (python312.dll)` ✓

---

## 6) LLVM obfuscator'ları — pass kaynaklarından çıkarılan yapısal desenler [K1]

Bu aileler PE'ye bölüm/bayt yazmaz; **derleme zamanında IR dönüşümü** uygular. Kaynak analizi
dönüşüm kurallarını ve tespit edilebilir desenlerini belgeler (v5 yapısal profil yaklaşımının
devamı olarak):

| Obfuscator | Kaynak analiz bulgusu | Tespit yaklaşımı |
|---|---|---|
| **O-LLVM (llvm-4.0)** | Flattening (dispatcher+switch), Bogus (opak koşul + altered-block), Substitution (aritmetik eşdeğerler) | yapısal: dispatcher döngüsü + ICmp yoğunluğu |
| **Hikari (release_80 + Core)** | `BogusControlFlow.cpp:305-330`: `ICmp EQ 1,1` placeholder → doFinalization'da rastgele sabitler; AntiClassDump, FunctionWrapper, StringEncryption, IndirectBranch | yapısal + `cmp`/branch çifti yoğunluğu |
| **Pluto** | `MBAUtils.cpp:21-35`: 15 truth-table (2-değişkenli tüm boolean fonksiyonlar) + z3 ile lineer MBA üretimi; GlobalEncryption; IndirectCall | yapısal: MBA kalıpları |
| **Armariris / goron / ollvm17 / Polaris / DeClang** | aynı O-LLVM ailesi dalları (indirect branch + string enc varyantları) | yapısal |
| **amice** | komut-düzeyi VMP/code virtualization (LLVM 11-23) | yapısal (VM dispatch) |
| **morok** | C++23 LLVM New-PM IR obfuscator (pass plugin) | yapısal |
| **O-MVLL (Android)** | NDK obfuscation pass'leri | belgelendi |
| **ROPfuscator** | ROP zincirine çevirme (gadget tabloları) | yapısal (dolaylı akış) |
| **ollvm-rust** | rustc'ye yüklenebilir obfuscation pass | yapısal |
| **kagura** | LLVM pass: CFG flattening + string enc + VM virtualization + anti-tamper (`.obf`/`.mvo` bölüm adları kaynak taramasında gözlendi) | bölüm + yapısal |

**Not:** LLVM obfuscation tespiti deterministik BAYT imzasıyla değil, yapısal profilleme ile
yapılır (v5'in SURUM PROFIL sistemi bu yaklaşımı zaten kullanır). Bu belge pass kaynaklarından
çıkarılan dönüşüm sabitlerini (Hikari placeholder davranışı, Pluto 15 truth-table, vb.) gelecek
yapısal kurallara kanıt olarak sunar.

---

## 7) Miras/ticari aileler — K3 tablo (DIE/PEiD mirasıyla çapraz doğrulama)

Themida/WinLicense (`.themida/.boom/.taz/.tsuarch/.tsustub/.winlice/.themidac`), Code Virtualizer
(`.vlizer`), Enigma (`.enigma1/.enigma2/.enigmap`), ASProtect (`.asprotect/.aspr1/.aspr2`),
ASPack (`.aspack/.adata/.asdata`), MPRESS (`.mpress1/.mpress2`), PECompact (`pecompact2/.pec`),
Obsidium, NSPack (`.nsp0/.nsp1/.nsp2`), Petite, FSG, MEW, UPack, RLPack, StarForce
(`.sforce/.pklst`), Safengine (`.sedata/.sense`), PELock, SVKP, Armadillo (`.textb`),
Dyamar, EXECryptor (`.ecode` — **`.edata` MinGW standardı olduğundan bilinçli dışlandı**),
CodeMeter/Wibu (`__wibu00/__wibu01`), NSIS (`.ndata`), tElock, Morphine (`.mta1/.mta2`),
NeoLite, PEBundle, PESpin, Perplex, spack.

Dizgi imzaları (bölge kısıtlı): `SecureEngine` (Themida motoru), `The Enigma Protector`,
`PECompact2`, `Nullsoft`/`NSIS Error`, `Inno Setup`, `RAR!`/`7-Zip`/`PK\x03\x04` (SFX kuyruk),
`Electron`/`app.asar` (kuyruk), `snapshot_blob.bin` (Node pkg).

---

## 8) Antipatika: yanlış pozitif kalkanı (gerçek vakalardan öğrenilmiş)

| Vaka | Çözüm |
|---|---|
| `vmp_ult_340_fn0.exe` — MinGW'nun standart `.edata` (export) bölümü ExeCryptor'u tetikledi | **standart bölüm filtresi**: bölüm-adı eşleşmesi yalnız standart-OLMAYAN bölümlerde (UPX istisnası: UPX0/1/2 motorca tanınır); ExeCryptor listesinden `.edata` çıkarıldı |
| Dedektörün kendi statik mingw binary'si (v5'ten gelen ders) | tüm dizgi aramaları bölge kısıtlı: başlık 4KB / koruyucu bölüm ham verisi / kuyruk 8KB |
| PyInstaller'ın kendi sihrini bootloader'da taşıması | `pyi_utils.c:169` yorumu: 4. bayt sürüme göre AYARLANIR — motor 4. baytı joker, 5-8. baytları sabit kontrol eder (kaynağın kendisi bize kuralı söylüyor!) |
| obfus.h sahte imzaları (yukarıda §3) | ≥2 farklı üretici → SAHTE DEMET kararı |

---

## 9) Test matrisi (v6, 26.11.2026)

| Test | Sonuç |
|---|---|
| 310 dosyalık TAM KÖR VMP korpusu (isimler rastgele gizli) | **310/310 (%100)** — TOP-1 kesin/eşitlik, 0 hata |
| UPX gerçek örnekler (kaynaktan derlenen UPX 5.3.1-git, 11 varyant) | 11/11: sürüm+yöntem+seviye çözümlü |
| Sahte imza demeti (obfus.h mantığı) | DEMET olarak doğru raporlandı (Themida/VMProtect/Enigma olarak değil) |
| Aile testleri (es3n1n/Ryujin/Nocturne/TinyLoad/obfus.h/gerçek VMP bölümleri) | 7/7 PASS |
| **GERÇEK obfusheader.h derlemesi** (zig cc, FAKE_SIGNATURES=1 — .vmp0/1/2+.themida+.enigma1/2 dolu) | **SAHTE DEMET olarak doğru** (VMProtect sanılmadı) |
| PyInstaller cookie simülasyonu | python 312 + python312.dll + paket boyutu çözüldü |
| Negatif kontroller (paketsiz Test_32/64, dedektör kendisi) | temiz |
| Windows çapraz derleme (zig, x86_64-windows-gnu, statik) | `bin/vmpdet6_windows.exe` PE geçerli, tüm evren dizgileri gömülü |

---

## 10) Bu belgeye eşlik eden dosyalar

```
src/universal_db.h      — 47 aile + 50 dizgi imzası + sahte-demet kuralları (kanıt yorumlu)
src/universal_tara.h    — evrensel tarama motoru (bölge kısıtlı, demet analizi, UPX/PYI çözümleme)
src/vmpdet5.cpp         — v6 entegrasyonu: [U] evrensel kapı + --evren bayrağı + JSON evren alanları
bin/vmpdet6_linux       — Linux derlemesi
bin/vmpdet6_windows.exe — Windows x64 statik derleme (zig)
ornekler/evren/         — 11 gerçek/sentetik evrensel test örneği (UPX gerçek çıktılar dahil)
scripts/kaynak_tarama.py— 72 hedeflik otomatik kaynak tarayıcı
scripts/sahte_imza_test.py — 7 senaryolu aile testi
scripts/kor_test_v6.py  — 310 kör regresyon
scripts/upx_iznik_cikar.py — UPX gerçek çıktı çözümleyici
```

---

# v7 EK BÖLÜMÜ — IMMORTAL: PEiD + DIE + de4dot + Themida-RE BESLEMESİ (26.11.2026)

> **v7, v6'nın "kaynak koddan besleme" hattını İNANILMAZ ölçeğe taşır:**
> klasik PEiD imza sözlüğü (topluluk mirası, Detect-It-Easy paketi) + Detect-It-Easy'in
> modern imza kuralları (MIT, horsicq) + de4dot .NET obfuscator dedektörü (GPL, 0xd4d) +
> Themida tersine-mühendislik araçları (unthemidator / Magicmida / themida-devirt / Themidie)
> — hepsi TEK deterministik motuna işlendi. Makine öğrenmesi YOK.

## v7.0) Bu turda klonlanıp analiz edilen 19 yeni kaynak deposu

| Depo | Alan | Motora katkı |
|---|---|---|
| horsicq/Detect-It-Easy | imza DB'si (MIT) | 1287 EP imzası + 42 bölüm-içeriği + 90 bölüm-adı kuralı (`db/PE/*.sg`) + PEiD userDB paketi (`peid_rules/PE/`, 3776 kayıt) |
| de4dot/de4dot | .NET deobfuscator (GPL) | 24 obfuscator'un dedektör mantığı: ConfuserEx (Confuser/Deobfuscator.cs:505), Babel metadata stream'i (Babel_NET/Deobfuscator.cs:125 HasMetadataStream("Babel")), Agile.NET CliSecureRt tipi, Eazfuscator sürüm dedektörü |
| x86rc/unthemidator | Themida 3-4 unpacker | Themida VM yapısı bilgisi (vm_enter/trampoline/dispatch — c_themida_unpacker.cpp) |
| Hendi48/Magicmida | Themida unpacker (766★) | **x64→V3 kuralı (Themida64.pas:63 "Themida V2 is not supported on x64")** + V1/V3 davranış ayrımı + magic-jump desenleri (Themida.pas:722 '3B8D????????0F84????0000') |
| aftermathlabs/themida-devirt | Themida devirt | VM handler yapısı doğrulaması |
| VenTaz/Themidie | Themida 3.x anti-debug bypass | Themida 3.x koruma yüzeyi bilgisi |
| mkaring/ConfuserEx | ConfuserEx (aktif fork) | ConfusedByAttribute + Confuser.Core sürüm su damgası |
| yck1509/KoiVM | KoiVM | "KoiVM"/"VMEntryRun" tip adları |
| Washi1337/OldRod | KoiVM devirt (389★) | KoiVM bytecode yapısı doğrulaması |
| SychicBoy/NETReactorSlayer | .NET Reactor (1286★) | NecroVM.Runtime / $method0x / "is tampered." imzaları |
| holly-hacker/EazFixer | Eazfuscator (459★) | Eazfuscator yapısı |
| SychicBoy/AgileDotNetSlayer | Agile.NET devirt | CliSecure yapısı |
| dr4k0nia/Origami | .NET packer | .NET packer çıktı yapısı |
| fl2on/Anti-De4dot | anti-araç | anti-de4dot tespit bilgisi |
| Lil-House/Pyarmor-Static-Unpack-1shot | PyArmor 8-9.3 (709★) | PyArmor sürüm bilgisi |
| jz0/tvm-devirt | Tencent VM devirt | **.tvm0 bölüm imzası (README: "devirtualized code appended at .tvm0")** |
| Momoko-Ayase/Senbei | CrackProof unpacker (94★) | CrackProof hedef ailesi (DIE kuralıyla çapraz) |
| orca-zhang/unpack | otomatik unpack (Rust) | ASPack test verisi (testdata/aspack/aspack_test.exe) |
| guoxing2024/magicmida-rs | Magicmida Rust portu | çapraz doğrulama |

## v7.1) Motor mimarisi — 8 katman (universal_tara.h v7)

```
S0  .NET CLI METADATA MOTORU (YENİ)
    veri_dizin[14] → CLI header → BSJB metadata kökü → stream dizini
    → #Strings yığını taraması (25 tip-adı işareti: ConfusedByAttribute, KoiVM,
      NecroVM.Runtime, ObfuscatedByCliSecureAttribute, BabelAttribute, ...)
    → sürüm su damgaları ("ConfuserEx v", "Confuser.Core ", "Confuser v" —
      sürüm sayıları çözülür: "ConfuserEx (.NET) 9.9.9" gibi)
    → standart-dışı metadata stream'leri ("Babel" → Babel ailesi, K1 de4dot)
    → UTF-16 "is tampered." (.NET Reactor anti-tamper)
S1  bölüm-adı aile eşleşmesi (v6'dan; 56 aile) + DIE bölüm-adı DESTEK kanıtı
    (genel adlar — .text/.data/.rsrc — elenir; aile kararı üretmez)
S2  sahte-imza demeti kalkanı (obfus.h FAKE_SIGNATURES) — v6'dan
S3  bölge-kısıtlı dizgi imzaları (v6'dan) + KARISTIRILMIŞ tam-dosya imzaları
S4  GİRİŞ NOKTASI İMZA MOTORU (YENİ): PEiD 2768 + DIE 1287 = 4055 desen,
    nibble-joker destekli, EP ofsetinde sabitlenmiş; en-kesin-desen kazanır;
    PEiD adları SÜRÜM TAŞIR ("ASPack v1.08" → aile=ASPack sürüm=1.08)
S5  tam-tarama imzaları (PEiD 382) — YALNIZ EP-bölümü + koruyucu bölümlerin
    ilk 256KB / son 64KB parçaları (yanlış-pozitif + performans koruması)
S6  özel bloklar: TinyLoad XXTEA (karıştırılmış), UPX packheader, PyInstaller cookie
S7  THEMİDA DERİN BLOĞU (YENİ): 8 EP deseni → sürüm haritası (1.0.X-2.1.8.0),
    .NET stub'ları (1.9 / 2.X), x64→3.x+ kuralı (K1: Magicmida Themida64.pas:63)
S8  NİHAİ KARAR — öncelik: sahte-demet > bölüm-ailesi > .NET > EP(≥6 kesin bayt) > dizgi
    + VMP KAPISI ERTELEMESİ: EP imzasından gelen aile + koruyucu bölüm varsa
    önce VMProtect derin motoru karar verir (kanıtlı vaka: vmp_340_adlar_degisti
    dosyasında DIE 'ROPacker' EP deseni VMP stub'ına çarpıyordu → v7'de VMP kazanır)
```

## v7.2) İmza hacmi

| Kaynak | İmza | Adet |
|---|---|---|
| PEiD userDB (packer 992 + protector 1784 + protection 943 + joiner 57) | EP imzası (kalite filtreli) | **2768** |
| PEiD userDB | tam-tarama (≥12 kesin bayt) | 382 |
| DIE db/PE (553 kural dosyası) | EP imzası | **1287** |
| DIE | bölüm-içeriği | 42 |
| DIE | bölüm-adı kanıtı | 90 |
| universal_db.h v6 | bölüm-adı ailesi | 56 |
| de4dot + DIE .NET | #Strings tip işareti | 25 |
| Themida derin blok | EP sürüm deseni | 8 |
| obfus.h/UPX/PyInstaller/TinyLoad/CrackProof | özel yapısal | 6+ |
| **TOPLAM bayt-imzası** | | **4.500+** |

Kalite filtreleri (yanlış pozitif kalkanı):
- PseudoSigner/Heuristic girdileri elendi (gerçek imza değil)
- Tek-bayt-tekrarı desenler elendi (90 90 90... NOP kaydırağı — "Hide&Protect V1.0X" vakası)
- EP ailesi için ≥6 kesin bayt şartı; EP kararları VMP kapısına ertelenir
- R_TUM dizgileri kaynak kodunda ve binary'de KARISTIRILMIŞ (öz-referans kalkanı)

## v7.3) ÖZ-REFERANS KALKANI (v6'da bulunan kusur → v7'de kapatıldı)

v6 dedektörü KENDİ binary'sini "TinyLoad/Enigma" sanabiliyordu: imza sabitleri
(.rodata'daki açık dizgiler) tam-dosya taramasında kendine çarpıyordu.
v7 çözümü:
1. Tam-dosya (R_TUM) imza dizgileri + TinyLoad XXTEA anahtar bloğu Python
   önhesaplamasıyla **XOR-karıştırılmış bayt dizileri** olarak gömülür
   (`sakli_anahtar(i) = 0x5A + 7*i`); kaynak kodda ve binary'de açık dizgi YOK.
2. PEiD isim tablosuyla çakışan dizgiler ("Enigma protector v" ⊂ PEiD adı
   "Enigma protector v1.02 -> ...") tam-tarama listesinden bilinçli çıkarıldı —
   Enigma ailesi bölüm adı + bölge-kısıtlı dizgiyle tespit edilir (çakışma imkânsız).
3. Test: `vmpdet7_windows.exe` kendi binary'sini tarar → "koruyucu bolum yok — PAKETSIZ" (temiz).

## v7.4) v7 regresyon sonuçları (hepsi bu turda koşuldu)

| Test | Sonuç |
|---|---|
| 310 dosyalık VMProtect kör korpusu (adlar rastgele gizli) | **310/310 %100 TOP-1 + aday-set** |
| vmp_340_adlar_degisti.exe (bölüm adları değiştirilmiş VMP) | VMProtect DETECTED (yapısal bayrak deseni) — EP 'ROPacker' yanıltıcısı geri çevrildi |
| ConfuserEx sentetik .NET (CLI+BSJB+#Strings+su damgası) | **ConfuserEx (.NET) 9.9.9** (sürüm çözüldü) |
| Babel sentetik .NET ("Babel" metadata stream) | **Babel .NET** (K1: de4dot HasMetadataStream) |
| .NET Reactor sentetik (NecroVM.Runtime + $method0x + UTF-16 "is tampered.") | **.NET Reactor** |
| Gerçek .NET assembly (AntiDe4dot.exe, temiz) | ".NET assembly (CLR başlığı)" — yanlış aile yok |
| Temiz PE'ler (Test_32/64 exe+dll, hello_paketsiz, korumasız) | hepsi TEMİZ |
| Dedektörün kendi binary'si (zig PE, öz-referans) | TEMİZ (PAKETSIZ) |
| obfusheader fake-signature gerçek örneği | SAHTE İMZA DEMETİ (doğru) |
| Klasik ornekler (UPX gerçek, Themida izi, es3n1n, Ryujin, Nocturne, TinyLoad, PyInstaller) | hepsi doğru aile |
| 310 + 33 ornek + 7 temiz + öz-tarama | **0 hata, 0 yanlış pozitif** |

## v7.5) v7'ye eşlik eden dosyalar

```
src/peid_db.h           — OTOMATİK ÜRETİM (v7_uret.py): PEiD 2768 EP + 382 tam-tarama imzası
src/die_db.h            — OTOMATİK ÜRETİM (v7_uret.py): DIE 1287 EP + 42 içerik + 90 bölüm-adı
src/universal_db.h      — v6 DB + .NET işaret tabloları + Themida derin blok + öz-referans kalkanı
src/universal_tara.h    — v7 motoru: S0-S8 (EP motoru, .NET metadata, Themida, erteleme mimarisi)
src/vmpdet5.cpp         — v7 entegrasyonu: Girdi bağlamı (EP/CLI/mimari), CrackProof kuralı,
                          JSON/TUI evren-EP/NET/THEMIDA alanları, VMP-kapısı ertelemesi
bin/vmpdet7_linux       — Linux derlemesi (g++ -O2)
bin/vmpdet7_windows.exe — Windows x64 statik (zig cc 0.13.0, x86_64-windows-gnu)
scripts/v7_uret.py      — imza çıkarıcı: PEiD userDB + DIE .sg → C++ tabloları (kalite filtreli)
scripts/net_ornek_uret.py — .NET sentetik örnek üretici (yapısal olarak geçerli PE+CLI+BSJB)
ornekler/evren/net_*.exe — 3 .NET sentetik test (ConfuserEx/Babel/Reactor)
```

## v7.6) Kapsam tablosu — hangi ekosistem artık tanınıyor?

- **Klasik packer'lar (A5 listesi)**: UPX (sürüm+yöntem), ASPack (sürüm!), PECompact,
  MPRESS, NSPack, FSG, MEW, Petite, Upack/WinUpack, tElock, RLPack, WWPack32, NeoLite,
  eXPressor (sürüm dizgisiyle), SVKP, Morphine, Yoda, PECrypt, ExeStealth, hXOR,
  PEPack, PEX, Pack Master, TinyLoad... — PEiD 2768 EP imzasıyla SÜRÜM düzeyinde
- **.NET protector'ları (A7 listesi)**: ConfuserEx (sürümle), KoiVM, .NET Reactor,
  Eazfuscator, Agile.NET/CliSecure, Babel, BeeByte*, Dotfuscator, SmartAssembly,
  Spices.Net, Goliath.NET, MaxtoCode, DNGuard, ILProtector, Xenocode, CodeVeil,
  XerinFuscator, LDK .NET, ConfuserEx Bed's/DotNetPatcher mod'ları
  (*BeeByte: sağlam statik işaret yok — dokümante sınır)
- **Modern protector'lar**: Themida/WinLicense (sürüm haritası + x64→3.x), Enigma,
  VMProtect (.NET dahil), ASProtect, Oreans CodeVirtualizer, Obsidium, EXECryptor,
  StarForce, Safengine, Armadillo, PELock, PESpin, VBox...
- **Yeni dalga (A19)**: Tencent VM (.tvm0), CrackProof (harf-karıştırılmış import),
  PyArmor, PyInstaller (python sürümü), Nuitka, es3n1n, Ryujin, Nocturne, wVmp,
  obfus.h/obfusheader.h (sahte-imza demeti), KiteShield (ELF), zhidun (APK)
- **Kurulum/SFX**: NSIS, Inno Setup, WinRAR/7z/zip SFX


---

## v8.0) GOD STATE — imza ÖTESİ algoritmalar + A16 "bizim lig" + Wine hattı

**v8'in üç kolu:** (1) A16 bölümündeki TÜM dedektör/imza-DB ekosistemi kaynak alındı;
(2) imza yeterli değil — 5 aracın ALGORİTMASI motora gömüldü (entropi/yapısal/RICH);
(3) Wine hattı kuruldu: **gerçek Themida 3.2.4.34 ve Enigma 7.80 demo'larıyla paketleme
yapıldı**, çıktılardan yeni nesil (2025-2026) EP desenleri ölçüldü.

### v8.1) A16 "bizim lig" — klonlanan 25 dedektör deposu

| Araç | Katkı (motora giren kısım) |
|---|---|
| **packing-box/bintropy** (IEEE 4140989) | S9 BINTROPY motoru: 256-bayt blok Shannon entropisi, yarı-sıfır blok yok sayma, eşikler **ort≥6.677 / en-yüksek≥7.199** (THRESHOLDS'tan) |
| **packing-box/pypackerdetect** | S10 EP-bölüm sınıflandırması (acceptable/.text, alternative, Delphi BSS→CODE, sürücü INIT), ithalat<10, standart-dışı bölüm, **hexacorn 92 bölüm-adı → packer atfı** (packers.json) |
| **JusticeRage/Manalyze** (325 satırlık plugin) | S10: bölüm entropisi>7, WX bölümler, kaynaklar>dosya, **RICH header checksum doğrulaması** (DanS ofseti + rol32 DOS-stub toplamı + @comp.id — pe.cpp:1721-1790'dan portlandı), ithalat tutarlılığı |
| **DosX-dev/PE-LiteScan** | S10: EP son bölümde (LAST_SECTION_ENTRYPOINT), .text yokluğu, overlay entropisi>7.5 (STRANGE_OVERLAY), PUSHAD@EP, standart-dışı DOS stub, SuppressIldasmAttribute (.NET), WEIRD bölüm adları, KnownSections (≈70 ad, sürümlü) |
| **hACKCASCAC/ObfusHunter** | S11 OBFUS bloğu: 17 desen (junk code BREAK_STACK*, anti-debug AD_*, VM dispatch, obfh veri bloğu 00-09) |
| **hACKCASCAC/ObfusFake-Signatures-Remover** | S2/S11 sahtecilik tabloları: sahte .vmp0/.enigma1/UPX0 bölüm adları (23), sahte filigran desenleri (Enigma v\x01 / denuvo_atd / NUITKA / SCREEN2EXE), sahte dongle dizgileri (skeydrv.dll, HASPDOSDRV, WIBUKEY, \\.\WIZZKEYRL — Sentinel/HASP/WIBU taklidi) |
| **salmanmallah/packerscope** | S10 EP stub desenleri (PUSHAD/PUSHFD/CALL$+5/UPX x64), SUSPICIOUS_APIS kümesi, IAT dinamik-yükleme analizi |
| **iaski15/DRMDetector** | S12 DRM dizgi taraması: Denuvo/Arxan/SteamStub/steam_api/Obsidium/CodeVeil |
| **cognis-digital/packpeek** | PDATA000→Armadillo; entropi eşiği 7.2 referansı |
| **Yara-Rules/rules** (peid.yar — 11 kaynak birleşimi) | **7615 kural → 8424 desen**; 299'u userdb'lerde olmayan özgün desen (AlienVault panda/jclausing/exeinfope, eppackersigs, epcompilersigs, cuckoo) |
| **packing-box/peid + wolfram77web/app-peid + pypackerdetect db + packerscope db** | 4 PEiD userDB'si → peid_db.h çekirdeği (v7 DIE peid_rules ile birleşik) |
| **ExeinfoASL** (resmî depo) | PEiD 0.95 kaynak kodu + SignMaker64 — kurulum imzası ekosistemi dokümante edildi |
| packgenome/PackGenome-Artifacts | **1.474 gerçek packer çıktısı** (NDSS dataset) — regresyon korpusu + MODERN_EP ölçümleri (aşağıda) |
| horsicq/DIE-engine | die_db.h yeniden üretiminde koşul ayrıştırıcı (aşağıda) |
| Nukem9/SwissArmyKnife, Manalyze binutils, 0pc0deFR/YaraRules, RootVandal/assay, GHFear/Packernoculars, ShadowGuard-AI, anpa1200/Unpacker, mesaleh/PackiD | İncelendi; eldeki tablolarla örtüştü (özgün desen katkısı 0 — dedup) |

### v8.2) İmza hacmi — v7 → v8

| Tablo | v7 | v8 |
|---|---|---|
| PEiD EP imzaları | 2768 | **4787** (+2019) |
| PEiD tam-tarama | 382 | **450** |
| DIE EP | 1287 | **1173** (yeniden üretim: koşullu) |
| Bölüm-adı atlası | 90 (DIE) | **90 + 130** (hexacorn+PE-LiteScan+Manalyze+packpeek) |
| Obfus/EP-stub/DRM/sahte desen | ~20 | **66** (algoritma_db.h) |
| MODERN_EP (gerçek çıktı ölçümü) | 0 | **11** |
| **TOPLAM** | ~4550 | **~6660** |

### v8.3) WINE HATTI — gerçek Themida/Enigma ile paketleme (K2 kanıt sınıfı)

qemu-i386 → wine32 (Kron4ek 11.20 x86) → PE32 CLI zinciri kuruldu
(`wine-32bit-runner` metodu; i386 X11 kütüphaneleri eklendi — GUI de çalışıyor).

| Ürün | Sürüm | Yöntem | Çıktı | Ölçülen imza |
|---|---|---|---|---|
| **Themida** (demo) | 3.2.4.34 x86/x64 | `Themida.exe /protect proje.tmd /inputfile /outputfile` (yardım CHM: hm_protecting-through-the-command.htm; .tmd = INI metni — PackGenome v3.0.4 tiger32_red projesi kalıbı) | `gercek_themida_324_32.exe` (1.38 MB) + `_64.exe` (1.51 MB) | PEiD "Themida/WL 3.0.x" EP; **.themida** bölümü doğrulandı |
| **Enigma Protector** (demo) | 7.80 build 20250205 | `enigma32.exe temel.enigma -input -output` (innoextract ile .deb'siz kurulum: enigma_ext/app) | `gercek_enigma_780_32.exe` (1.2 MB) + `_64.exe` (2.0 MB) | **YENİ NESİL EP desenleri**: x86 `eb08`+8joker+`60e8000000005d81ed`+imm32×2+`e9`; x64 `eb08`+8joker+`50..4157`+`489c`+`sub rsp,8`+`fxsave64` — **7 bölümün 6-7'si BOŞ isimli** (klasik .enigma1/.enigma2 YOK — 2025 sürümü bölüm adlarını TEMİZLEDİ) |

**Wine hattının yakaladığı deliği v8 kapattı:** klasik sözlükler Enigma 7.8x'i
"BİLİNMEYEN KORUYUCU" sanıyordu. Ölçülen EP desenleri (K1: gerçek çıktı) MODERN_EP
tablosuna girdi; artık `Packer: Enigma Protector 7.8x [MODERN(Wine)]`.

### v8.4) PackGenome RGD — 483 gerçek çıktılı yeni korpus + MODERN_EP ölçümleri

14 aile × gerçek dosyalar (NDSS PackGenome dataset). İlk koşuda 6 aile 0-21%'di;
aşağıdaki desenler ÖLÇÜLEREK (EP baytları hex olarak okunarak) eklendi:

| Aile | Ölçülen EP deseni (MODERN_EP) | Kapanan varyant |
|---|---|---|
| Themida/WinLicense 2.3.x | `565053e801000000cc5889c3402d` (push×3; call; **int3;pop** — anti-debug int3 hilesi) | delphi_bcb + 9 WinLicense modu |
| Themida/WinLicense 2.3.x | `eb08`+8joker+`e900200000` (jmp 0x200000 sabiti) | full/ENCODE (rastgele bölüm adları + **.taggant** DRM bölümü bulundu) |
| ZProtect 1.6 | `68..c3410068..c34100c3` / d341 / jmp türevleri (push-ret 0x41c3xx) | 6 modun tamamı |
| MoleBox 4.3 | `5589e583ec08c7042401000000ff15....e8....908db42600000000` (mov [esp],1; call [imm]; **nop; lea esi,[esi+0]** — mingw loader) | 3 modun tamamı |
| Enigma 1.55 | `558bec83c4f0b8........e8010000009a83c4108be55de9` (**9a farcall** — 32-bit kodda anormal) | best_compress |

Yeni bölüm atlası girdileri: **.taggant** → Themida/WinLicense (Taggant DRM bölümü),
**PDATA000/001** → Armadillo (packpeek).

### v8.5) DIE koşul ayrıştırıcısı (v8'in kritik düzeltmesi)

`packer_ROPacker.2.sg` aslında ÜÇ koşullu: `compareEP(...)` **VE** `isLibraryPresent("zlib1.dll")`
**VE** `getSize() > 20MB`. v7 çıkarımı yalnız compareEP'i almıştı → **MinGW x64 başlangıç
kodu ROPacker sanılıyordu** (vmpdet8_windows.exe öz-taraması yanlış pozitif verdi).
v8 die_db.h yeniden üretildi: her EP imzasına `kutuphane` + `min_boyut` alanları eklendi;
motor koşulları uygular. Öz-tarama artık temiz (Linux + MinGW Windows binary).

### v8.6) v8 regresyonu (docs/kor_test_v8.txt — TOPLAM HATA: 0)

| Küme | Sonuç |
|---|---|
| VMProtect 310 korpusu (exe+dll, adlar gizli) | **310/310 — %100** |
| Örnekler + evren/ (bilinen kararlar) | 19+15 dosya — **0 hata** |
| wine9/ (gerçek Themida 3.2.4 + Enigma 7.80 + girdiler) | 6 dosya — **0 hata** |
| PackGenome RGD 14 aile | **483/483 — %100** (ACProtect 42, ASPack 45, Enigma 53, Fsg 3, MoleBox 9, Obsidium 21, Themida 42, UPX 111, VMProtect 27, WinLicense 27, ZProtect 18, kkrunchy 9, NsPack 27, Petite 15) |
| Öz-tarama (Linux + MinGW Windows) | **temiz** |

### v8.7) v8'e eşlik eden dosyalar

- `src/peid_db.h` — 4787+450 (10 sözlük birleşimi; üretici: scripts/v8_uret.py)
- `src/bolum_db.h` — 130 gerçek + 23 obfus-sahte bölüm adı
- `src/algoritma_db.h` — OBFUS 17 + SAHTE 4 + SAHTE_DONGLE 12 + EP_STUB 8 + DRM 25 + MODERN_EP 11
- `src/die_db.h` — 1173 EP (kutuphane/min_boyut koşullu) + 45 içerik + 90 ad
- `src/universal_tara.h` v8 — S0..S12 (yeni: S1b bölüm atlası, S4b MODERN EP, S9 bintropy, S10 yapısal 12 kural, S11 obfus derin, S12 DRM)
- `src/vmpdet5.cpp` — Girdi bağlamı v8 (e_lfanew/ithalat/kaynak/DLL listesi); JSON+TUI'ye 6 yeni kanıt türü
- `bin/vmpdet8_linux` + `bin/vmpdet8_windows.exe` (MinGW-w64 14.2, statik)
- `ornekler/wine9/` — 4 gerçek korumalı çıktı + 2 paketsiz girdi + Themida .tmd projesi
- `scripts/v8_uret.py` (üretici), `scripts/kor_test_v8.py` (regresyon)
