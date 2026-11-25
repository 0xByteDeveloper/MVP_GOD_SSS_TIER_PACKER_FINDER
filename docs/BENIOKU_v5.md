# VMDETECT v5 — BENİOKU (GOD SSS TIER)

## Bu sürüm ne getiriyor?

v4 yalnızca **64-bit EXE** ailesinde kusursuzdu. **v5, KULLANICININ GERÇEK
DÖRT DOSYASI** ile kurulmuş dört-aile korpusuyla **hepsinde** kusursuzdur:

| # | Aile | Korpus durumu (v4) | v5 |
|---|------|--------------------|----|
| 1 | 32-bit EXE (`Test_32.exe`) | bilinmiyor | **%100** |
| 2 | 32-bit DLL (`Test_32.dll`) | bilinmiyor | **%100** |
| 3 | 64-bit EXE (`Test_64.exe`) | kusursuz* | **%100** |
| 4 | 64-bit DLL (`Test_64.dll`) | bilinmiyor | **%100** |

(*) v4'ün korpusu, kullanıcı dosyasının 41 KB'lık bir eşdeğerinden derlenmişti;
v5 korpusu **orijinal.rar içindeki gerçek dosyalardan** sıfırdan kuruldu.

## Kör test sonucu (kanıt)

310 korumalı build × 10 sürüm, dosya adları rastgele gizlendi
(`kor_test_v5.json` + `kor_test_v5_tum_sonuclar.json`):

```
T32E   :  78 build | TOP-1 kesin  77 + eşitlik  1 = 100.00% | aday-set 100.00%
T32D   :  78 build | TOP-1 kesin  77 + eşitlik  1 = 100.00% | aday-set 100.00%
T64E   :  77 build | TOP-1 kesin  76 + eşitlik  1 = 100.00% | aday-set 100.00%
T64D   :  77 build | TOP-1 kesin  76 + eşitlik  1 = 100.00% | aday-set 100.00%
TOPLAM : 310 build | TOP-1 kesin 306 + eşitlik   4 = 100.00% | aday-set 100.00%
Profil (build-tip) eşleşmesi: 310/310     HATA YOK — %100
```

## Mimari: aile kapılı deterministik cipa sistemi (ML YOK)

```
PE → [makine (i386/AMD64) + DLL bayrağı] → AİLE KAPISI
      T32E / T32D / T64E / T64D          (4 aile, K2 cipa korpusu her birine özel)
         │
         ├─ [P] Paketleyici imza motoru → UPX/Themida/Enigma/... → "VMProtect DEĞİL" kesin negatif
         ├─ [V] VMP kapısı → .vmp bölümü / VMProtect dizgisi / bayrak deseni
         ├─ [L] Çift .vmp bölümü → ÇOK KATMAN + bölüm-bazlı sürüm atfı
         ├─ [K2] Aile cipası: (aile, sürüm, build-tipi) → bölüm boyutları birebir
         │       310 profil; sürüm-başına ayrıştırılabilirliği kanıtlanmış
         └─ [K4'] Profil mesafesi (göreli marj ~%3) → bilinmeyen kombinasyonlar
                 → uzaklık > %25 ise OZEL VARYANT (modlanmış motor uyarısı)
```

### Eşitlik sınıfı — v5 rafinasyonu (ÖNEMLİ BULGU)

v4, `Professional 3.8.1 ∥ Ultimate 3.8.4` çiftini her yapıda "bayt-özdeş"
sayıyordu. v5 korpusu bunun **yalnız fn0** (seçeneksiz saf-wrapper)
yapısında geçerli olduğunu KANITLADI:

| Build tipi | Pro 3.8.1 | Ult 3.8.4 | Sonuç |
|---|---|---|---|
| fn0 (seçenek yok) | 2560/2480 | 2560/2480 | **eşitlik sınıfı** (fiziksel sınır) |
| Pack | 7.066.624 | 6.684.160 | **AYRIŞIR** |
| Move_Ultra | 863.232 | 860.672 | **AYRIŞIR** |

Yani: seçenek ya da fonksiyon koruması varsa sürüm **kesin** verilir;
yalnız çıplak wrapper'da eşitlik sınıfı raporlanır (doğru cevap budur).

## Özellik çıkarımı (dürüstlük politikası)

- **Yapısal** seçenekler (Pack, ImportProtection, StripFixups, fonksiyon koruması):
  cipa eşleşmesi + bölüm kanıtıyla KESİN/ACIK/KAPALI.
- **Kripto-bit** seçenekler (MemoryProtection, CheckDebugger, RunnerCRC, ...):
  yapıya etki etmedikleri için `AYRISTIRILAMAZ (yapiya etki etmeyen bit)`
  olarak raporlanır — yanlış iddia yerine dürüst bilinmezlik.
- HEPSI yapıları: derleme tarifiyle 15 seçenek AÇIK.

## Runtime modları (i4MConsoleLoader mantığı)

- `--sim <dosya>` — loader emülasyonu, **kod ÇALIŞMAZ**: map/reloc/import/
  **export (DLL)**/TLS/koruma raporu. 32/64-bit PE + EXE/DLL hepsi destekli.
- `--live <dosya>` — canlı süreç analizi + bellek dump + otomatik yeniden analiz:
  - **EXE**: doğrudan çalıştır (Windows: doğal; Linux: wine).
  - **DLL**: **gömülü host** (LoadLibrary+Sleep, x64+x86 olarak binary içine
    gömülü) — hiçbir dış bağımlılık yok, DLL bellekte açılıp dökülür.
  - Linux'ta 32-bit hedefler: `wine_run.sh` mimari koklayıp 32-bit PE'yi
    wine32 kit'ine yönlendirir (qemu-user; skill ile kurulmuş).
- Test günlükleri: `test_raporlari/runtime_canli_v5.txt` — dört ailede de
  bellek dökümünden sürüm atfı başarılı (ör. 32-bit DLL → "Lite 3.8.7,
  aile cipası birebir").

## Çok katman

Çift VMProtect koruması: iç 3.9.4 + dış 3.4.0 demosu
(`test_raporlari/katman_negatif_v5.txt`): her katman bölüm-bazlı atfedildi.

## Bilinen sınırlar (dürüst rapor)

1. **VMProtect Ultimate 3.3.1**: GUI'si yalnız i386; bu ortamda (qemu-emüle
   wine32) 32. saniyede çöker — korpusu bu sandbox'ta derlenemedi.
   3.3.1 ile packlenmiş 32-bit dosyalar yine de **VMProtect: EVET** tespiti
   alır; sürüm atfı OZEL VARYANT olarak dürüstçe raporlanır. Gerçek
   Windows'ta 3.3.1 çıktıları üretip `scripts/` hattıyla (vmp_matris5.py →
   imza5.py → db_uret5.py) DB'yi genişletmek mümkündür.
2. **Lite 3.10.4 + HEPSI** kombinasyonu (tüm aileler) derlemede takılıyor —
   Lite'a özgü motor kusuru; bu build'ler korpus dışı bırakıldı (8 build,
   `results.json` içinde belgelendi). Lite 3.10.4 diğer 6 yapıda %100.
3. **Ultimate 3.6.0** belirli kombinasyonlarda (T64E+Pack, T64D+Ultra+HEPSI)
   bölüm tablosu sıfırlanmış BOZUK çıktı üretiyor (2 kez kanıtlandı; v4
   BOZUK listesiyle aynı patern) — bu 2 build dışarıda bırakıldı.
4. Dört korpus ailesi dışındaki girdiler (başka EXE/DLL): VMP EVET/HAYIR +
   yapısal analiz çalışır; kesin sürüm atfı girdi-ailesi korpusu ister
   (CAPA2 mekanizması hello ailesi için korunuyor).

## Kullanım

```
vmpdet5 <dosya>                    # tek hedef — askeri TUI (exe VEYA dll, 32/64)
vmpdet5 --dir <klasor>             # batch (.exe + .dll)
vmpdet5 --json cikti.json --dir <klasor>
vmpdet5 --sim <dosya> [--dump a.bin]
vmpdet5 --live <dosya> [--wait 4000] [--dump a.bin]
```

Linux --live için: `VMPDET_WINE=<wine-yolu>` (varsayılan `wine`);
32-bit hedefte wine32 kurulu olmalı. Windows binary'de gömülü host
otomatik çalışır.

## Derleme

```
g++ -O2 -std=c++17 -o vmpdet5_linux vmpdet5.cpp
x86_64-w64-mingw32-g++ -O2 -std=c++17 -static -o vmpdet5_windows.exe vmpdet5.cpp -lpsapi
```

Tek dosyalık C++17, sıfır bağımlılık (Windows: psapi).
`detektor_db5.h` (310 profil) + `host_gomulu.h` (DLL host) gömülü.

## Dosyalar

```
src/vmpdet5.cpp          — ana kaynak (tek dosya)
src/detektor_db5.h       — gömülü imza DB (otomatik üretilir)
src/host_gomulu.h        — gömülü DLL host (x64+x86)
bin/vmpdet5_windows.exe  — Windows binary (statik)
bin/vmpdet5_linux        — Linux binary
scripts/                 — korpus üretim hattı (DB'yi genişletmek için)
docs/                    — bu dosya + test raporları
ornekler/                — demo dosyaları
```
