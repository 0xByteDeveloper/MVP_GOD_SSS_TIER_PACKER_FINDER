# MVP GOD SSS TIER — VMProtect Packer Finder (v7 IMMORTAL)

**Deterministik VMProtect sürüm + özellik + katman dedektörü + EVRENSEL packer motoru. Makine öğrenmesi YOK.**
Tek dosyalık bağımlılıksız C++17 — Windows + Linux — **EXE ve DLL, 32-bit ve 64-bit**.

## v7 — IMMORTAL: 4.500+ imza, HER PACKER'I ADIYLA SÖYLER

v6'nın kaynak-koddan beslenen hattı üç büyük miras sözlükle birleşti:

| Kaynak | Katkı |
|---|---|
| **PEiD userDB** (topluluk sözlüğü, DIE paketi) | 2768 EP imzası + 382 tam-tarama imzası — **sürüm düzeyinde** ("ASPack 2.12") |
| **Detect It Easy** kuralları (horsicq, MIT) | 1287 modern EP imzası + 42 bölüm-içeriği + 90 bölüm-adı |
| **de4dot** (0xd4d, GPL) | 24 .NET obfuscator dedektör bilgisi (ConfuserEx/Babel/Agile.NET/Reactor...) |
| **Themida RE araçları** (unthemidator, Magicmida, themida-devirt, Themidie) | Themida sürüm haritası (EP desenleri 1.0→2.1) + **x64→3.x kuralı** (K1: Magicmida Themida64.pas:63) |

Yeni motor katmanları (`src/universal_tara.h` v7):
- **EP İMZA MOTORU** — 4055 desen giriş noktasında eşleşir (nibble-joker destekli);
  en-kesin desen kazanır; PEiD adları sürüm taşır
- **.NET CLI METADATA MOTORU** — CLI başlık → BSJB kökü → stream dizini → #Strings
  yığını: ConfuserEx (sürüm su damgasıyla: "ConfuserEx 9.9.9"), KoiVM, .NET Reactor,
  Agile.NET, Babel ("Babel" stream'i), Dotfuscator, SmartAssembly, DNGuard,
  ILProtector, Xenocode... 25 tip işareti
- **THEMIDA DERİN BLOĞU** — 8 EP sürüm deseni + .NET stub'ları + x64→3.x+ kuralı
- **ÖZ-REFERANS KALKANI** — tam-dosya imzaları binary'de XOR-karıştırılmış gömülür;
  dedektör kendi binary'sini artık yanlış SAYMAZ (v6'da kapanmış kusur)
- **VMP KAPISI ERTELEMESİ** — EP imzası aile bulsa bile koruyucu bölümlü dosyalarda
  önce VMProtect derin motoru karar verir (bölüm adları değiştirilmiş VMP vakası)

Regresyon: **310/310 VMP kör korpusu %100** + 33 örnek + temiz PE'ler + öz-tarama:
**0 hata, 0 yanlış pozitif**. Detaylı kanıt tablosu: **[docs/KaynakKodAnalizi.md](docs/KaynakKodAnalizi.md)** (v7 bölümü).
Kullanım: `vmpdet7 --evren <dosya>` (tüm kanıt listesi: EP adayları, .NET raporu, Themida sürümü) · `--json`.

```
 ██╗   ██╗███╗   ███╗██╗     ███████╗████████╗ ██████╗ ███████╗ ██████╗ ███████╗
 ██║   ██║████╗ ████║██║     ██╔════╝╚══██╔══╝██╔═══██╗██╔════╝██╔═══██╗██╔════╝
 ██║   ██║██╔████╔██║██║     █████╗     ██║   ██║   ██║█████╗  ██║   ██║███████╗
 ╚██╗ ██╔╝██║╚██╔╝██║██║     ╚════██║    ██║   ██║   ██║██╔══╝  ██║   ██║╚════██║
  ╚████╔╝ ██║ ╚═╝ ██║███████╗███████║    ██║   ╚██████╔╝██║     ╚██████╔╝███████║
   ╚═══╝  ╚═╝     ╚═╝╚══════╝╚══════╝    ╚═╝    ╚═════╝ ╚═╝      ╚═════╝ ╚══════╝
```

## v6 — EVRENSEL MOTOR: kaynak koddan beslenen imza veritabanı

Listemizdeki açık kaynak packer'ların **kendi kaynak kodlarından** çıkarılan deterministik
izlerle (bölüm adları, sihirli baytlar, kripto sabitleri — dosya:satır kanıtı):
**47 aile + 50 dizgi imzası + sahte-imza demeti kalkanı** (`src/universal_db.h`).
UPX sürüm/yöntem/seviye çözümleme (packheader), PyInstaller EOF cookie (python sürümü),
TinyLoad XXTEA anahtar bloğu, obfus.h FAKE_SIGNATURES sahtecilik tespiti.
Detay: **[docs/KaynakKodAnalizi.md](docs/KaynakKodAnalizi.md)** — kanıt seviyeleri K1/K2/K3.
Kullanım: `vmpdet6 --evren <dosya>` (tüm kanıt listesi) · `--json` (evren alanları).

```
 ██╗   ██╗███╗   ███╗██╗     ███████╗████████╗ ██████╗ ███████╗ ██████╗ ███████╗
 ██║   ██║████╗ ████║██║     ██╔════╝╚══██╔══╝██╔═══██╗██╔════╝██╔═══██╗██╔════╝
 ██║   ██║██╔████╔██║██║     ███████╗   ██║   ██║   ██║█████╗  ██║   ██║███████╗
 ╚██╗ ██╔╝██║╚██╔╝██║██║     ╚════██║   ██║   ██║   ██║██╔══╝  ██║   ██║╚════██║
  ╚████╔╝ ██║ ╚═╝ ██║███████╗███████║   ██║   ╚██████╔╝██║     ╚██████╔╝███████║
   ╚═══╝  ╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝      ╚═════╝ ╚══════╝
```

## v5 — DÖRT AİLEDE %100 (32/64-bit EXE + DLL)

v4 yalnız 64-bit EXE'de kusursuzdu. v5, kullanıcının **GERÇEK** Test dosyalarıyla
(`orijinal.rar`: Test_32.exe, Test_32.dll, Test_64.exe, Test_64.dll) sıfırdan
kurulmuş **dört-aile korpusu** ile hepsinde kusursuzdur:

| Aile | Korpus | Kör test (adlar rastgele gizli) |
|---|---|---|
| 32-bit EXE (T32E) | 78 build × 10 sürüm | **%100 TOP-1 + aday-set** |
| 32-bit DLL (T32D) | 78 build × 10 sürüm | **%100 TOP-1 + aday-set** |
| 64-bit EXE (T64E) | 77 build × 10 sürüm | **%100 TOP-1 + aday-set** |
| 64-bit DLL (T64D) | 77 build × 10 sürüm | **%100 TOP-1 + aday-set** |
| **TOPLAM** | **310 build** | **%100 (306 kesin + 4 fn0-eşitliği), profil 310/310** |

### Mimari: aile kapısı + cipa sistemi
`makine (i386/AMD64) + DLL bayrağı` → aile kapısı → **K2 aile cipası**
((aile, sürüm, build-tipi) → bölüm boyutları, 310 profil, birebir) →
K4' göreli-marjlı profil mesafesi → OZEL VARYANT (modlanmış motor) uyarısı.

### Eşitlik sınıfı rafinasyonu (v5 bulgusu)
`Professional 3.8.1 ∥ Ultimate 3.8.4` bayt-özdeşliği **YALNIZ fn0**
(seçeneksiz saf-wrapper) yapısında geçerli — Pack/Move_Ultra yapılarında
iki sürüm **AYRIŞIR** (cipa kanıtıyla). Seçenek ya da fonksiyon koruması
varsa sürüm kesin verilir.

### DLL runtime analizi — gömülü host
`--live` DLL hedeflerinde **binary içine gömülü** LoadLibrary+Sleep host'unu
(x64+x86) yazar ve çalıştırır: DLL bellekte açılır, dökülür, otomatik yeniden
analiz edilir — sürüm atfı dahil. Linux'ta 32-bit hedefler mimari-koklayan
`wine_run.sh` üzerinden wine32 kit'ine yönlenir. Dört ailede de kanıtlandı
(`docs/runtime_canli_v5.txt`).

### Çok katman (yeni ailelerle kanıtlı)
3.9.4-iç + 3.4.0-dış çift koruması: her katman bölüm-bazlı atfedildi
(`docs/katman_negatif_v5.txt`).

### Dürüst sınırlar (belgelendi)
- Lite 3.10.4 + HEPSI kombinasyonu: motor takılıyor (Lite kusuru) — 8 build korpus dışı.
- Ult 3.6.0 belirli kombinasyonlarda BOZUK çıktı (bölüm tablosu sıfır) — 2 build, 2x kanıt.
- Ult 3.3.1 (yalnız i386 GUI): qemu-emüle wine altında çöker — VMP tespiti çalışır,
  sürüm atfı OZEL VARYANT olarak raporlanır; gerçek Windows'ta `scripts/` hattıyla DB genişletilebilir.

## Kullanım

```bash
./vmpdet7 hedef.exe                 # askeri TUI raporu (exe VEYA dll, 32/64-bit)
./vmpdet7 --evren hedef.exe         # + TÜM evrensel kanıt listesi (EP adayları, .NET, Themida)
./vmpdet7 --json c.json --dir kl/   # toplu JSON (evren/ep_imzasi/net/themida alanları dahil)
./vmpdet5 hedef.exe                 # askeri TUI raporu (exe VEYA dll, 32/64-bit)
./vmpdet5 --dir korumali_klasor/    # toplu tarama (.exe + .dll) + özet
./vmpdet5 --json cikti.json --dir kl/
./vmpdet5 --sim hedef.dll           # loader emülasyonu (kod ÇALIŞMAZ, export dahil)
./vmpdet5 --live hedef.dll          # canlı süreç + bellek dump + yeniden analiz
                                    # (DLL: gömülü host otomatik)
```

Ayrıntılı doküman: **[docs/BENIOKU_v5.md](docs/BENIOKU_v5.md)**

## Derleme

```bash
# Linux
g++ -O2 -std=c++17 -o vmpdet7 src/vmpdet5.cpp
# Windows (MinGW-w64 YA DA zig cc çapraz derleme)
x86_64-w64-mingw32-g++ -O2 -std=c++17 -static -o vmpdet7.exe src/vmpdet5.cpp -lpsapi
zig c++ -O2 -std=c++17 -target x86_64-windows-gnu -o vmpdet7.exe src/vmpdet5.cpp -lpsapi
# İmza tablolarını yeniden üretmek için (PEiD userDB + DIE .sg → C++):
python3 scripts/v7_uret.py      # src/peid_db.h + src/die_db.h (OTOMATİK ÜRETİM)
```

---

# v4 ARŞİVİ (önceki sürüm)

## Sonuçlar

| Test | Sonuç |
|---|---|
| **Sürüm kör testi (407 build, 10 sürüm, adlar rastgele gizli)** | **407/407 = %100 TOP-1** |
| Aday-set doğruluğu | 407/407 = %100 |
| Profil eşleşme | 308/308 = %100 |
| Özellik tespiti (MP/ImpProt/Pack/CheckDbg/CheckVM) | %97+ (profil bazlı) |
| Önceki sürümler | v1: %66 → v2: %96.6 → **v4: %100** |

25 build "eşitlik sınıfı" olarak raporlanır: **Professional 3.8.1 ∥ Ultimate 3.8.4**
saf-wrapper çıktıları bayt-özdeştir (894 ortak invariant pozisyonda 0 fark — kanıtlı).
Tek dosyadan kesin ayırma fiziksel olarak imkânsızdır; dürüst cevap bu sınıftır.

## Yeni Yetenekler (v4)

### [P] VMProtect DEĞİLse kesin OLUMSUZ karar
UPX (gerçek `UPX!` sihri ile), Themida/WinLicense, Enigma, ASProtect, MPRESS,
PECompact, Obsidium, ExeCryptor, nSpack, Petite, FSG, MEW, NSIS, Inno Setup,
ConfuserEx imzaları + .NET assembly tespiti. VMP imzası yoksa **asla** VMProtect denmez.

### [C] Modlanmış / özel derleme tespiti
- Bölüm adları değiştirilmiş çıktılar (script `OnAfterSaveFile` ya da modlanmış motor):
  yapı + CAPA2 aile çipleriyle sürüm **yine** bulunur + uyarı basılır.
- Hiçbir sürüm profiline uymayan VMProtect-ailesi yapısı → **ÖZEL VARYANT
  (modlanmış/rebuild motor — en yakın: X)**.
- Bilimsel bulgu: 3.4+ motorlarında çıktı içeriği derleme-başına tamamen rastgele
  (aynı sürümün build'leri arası 8/24-gram kesişimi = 0) → içerik değil YAPI imzalanır;
  bu yüzden yapıyı bozmayan modlar "yapı sürümü" olarak doğru raporlanır.

### [L] Çok katmanlı koruma
- **Çift .vmp bölüm adı** = double-protect (katman üstü katman) statik tespit.
- Bölüm-bazlı sürüm atfı (capa + capa2 aile çipleri + eski-nesil n-gram).
- UPX dış katman: "UPX (VMP değil) + iç katman gizli — runtime analizi önerilir".

### [R] Runtime modu (i4MConsoleLoader entegrasyonu)
```
--sim  dosya.exe [--dump cikis.bin]   Windows loader EMÜLASYONU (kod çalışmaz):
                                      map/reloc/import+IAT/TLS/koruma raporu
--live dosya.exe [--wait 4000]        Hedefi ÇALIŞTIRIR → bellek dökümü →
                                      dökümü otomatik yeniden analiz → belleğe
                                      gömülü iç-katman PE başlıklarını GERİ KAZANIR
```
Demo (repo içinde kayıtlı): `UPX(VMP3.9.4(VMP3.4.0(hello)))` üçlü katmanı —
statik: "UPX"; runtime: UPX bellekte açılmış + **İÇ KATMAN SÜRÜM: Ultimate 3.4.0**.

## Kullanım

```bash
./vmpdet4 hedef.exe                 # askeri TUI raporu
./vmpdet4 --dir korumali_klasor/    # toplu tarama + özet
./vmpdet4 --json cikti.json --dir kl/
./vmpdet4 --sim hedef.exe           # loader emülasyonu
./vmpdet4 --live hedef.exe          # canlı süreç analizi (Linux: wine, VMPDET_WINE ile seçilir)
```

## Derleme

```bash
# Linux
g++ -O2 -o vmpdet4_linux src/vmpdet4.cpp -std=c++17
# Windows (MinGW-w64)
g++ -O2 -o vmpdet4_windows.exe src/vmpdet4.cpp -std=c++17 -static -lpsapi
```

## Mimari (katmanlı deterministik karar)

```
[P] paketleyici imza motoru ──┬─ VMProtect imzası VAR → [C] bölüm-adı kontrolü
                              ├─ UPX! / Themida / ...   → "VMProtect DEĞİL" + paketleyici adı
                              └─ bilinmeyen bölüm       → "BİLİNMEYEN KORUYUCU" (VMP denmez)
[L] çift .vmp bölümü → katman katman sürüm atfı (capa/capa2/n-gram)
[K1] bölüm-karakteristik (bayrak deseni) sert filtre
[K2] PURE capa (raw/vsz) birebir + 3.8.x eşitlik sınıfı
[K3] eski nesil (3.0.9/3.2.0) 24-bayt n-gram imza oylaması (256+256)
[K4] yapısal profil (408 profil) — GÖRELİ marj ile keskin ayırım
[CAPA2] girdi-ailesi sürüm çipleri (Test_64 ailesi + hello ailesi gömülü)
[R] --sim loader emülasyonu / --live canlı döküm + iç-katman geri kazanımı
```

## Depo Yapısı

```
src/      vmpdet4.cpp + detektor_db.h (gömülü imza DB) + derleme betikleri
bin/      vmpdet4_windows.exe, vmpdet4_linux (hazır, test edildi)
docs/     kör test raporu (407/407), yetenek matrisi, runtime demoları, TUI örnekleri
scripts/  üretim + test hattı (VMProtect GUI otomasyonu, örnek üretici, kör test)
ornekler/ test için küçük örnek dosyalar (UPX, Themida-izi, çift/üçlü katman, ...)
```

## Test Kapsamı

- **452 build corpus** (11 VMProtect sürümü: 3.0.9 → 3.10.4, Ultimate/Lite/Professional;
  Test_64 matrisi: tek-özellik, HEPSI, Move×Virt/Mutation/Ultra×param kombinasyonları)
- Kör test: dosya adları rastgele gizlenir, tek tek taranır
- Negatif testler: paketsiz EXE'ler, gerçek UPX, UPX geri-açılmış, sentetik Themida izi
- Çok katman: çift-VMProtect (aynı/farklı sürüm), UPX dış katman, üçlü katman
- Runtime: tek/çift/üçlü katman canlı döküm + iç katman geri kazanımı

## Sınırlar (dürüst rapor)

1. Pro 3.8.1 ∥ Ult 3.8.4 saf-wrapper çıktıları bayt-özdeş → eşitlik sınıfı (fiziksel sınır).
2. Sürüm atfı girdi-ailesi profillerine dayanır; bilinmeyen ailede "özel varyant / en yakın".
3. VMProtect GUI, UPX'lenmiş girdi AÇMAZ ("Cannot open") — UPX+VMP kombinasyonu ancak
   UPX dış katman olarak oluşabilir (bu repo bu durumu da kapsar).
4. 3.3.1 i386 32-bit wine gerektirir (corpus'ta build yok).

---
GOD SSS TIER — deterministik, kanıtlı, dürüst. ML yok, bahane yok.
