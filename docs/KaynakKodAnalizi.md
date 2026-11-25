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
