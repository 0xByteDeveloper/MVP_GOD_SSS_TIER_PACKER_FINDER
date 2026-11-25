# MVP GOD SSS TIER — VMProtect Packer Finder (v4)

**Deterministik VMProtect sürüm + özellik + katman dedektörü. Makine öğrenmesi YOK.**
Tek dosyalık bağımlılıksız C++17 — Windows + Linux.

```
 ██╗   ██╗███╗   ███╗██╗     ███████╗████████╗ ██████╗ ███████╗ ██████╗ ███████╗
 ██║   ██║████╗ ████║██║     ██╔════╝╚══██╔══╝██╔═══██╗██╔════╝██╔═══██╗██╔════╝
 ██║   ██║██╔████╔██║██║     ███████╗   ██║   ██║   ██║█████╗  ██║   ██║███████╗
 ╚██╗ ██╔╝██║╚██╔╝██║██║     ╚════██║   ██║   ██║   ██║██╔══╝  ██║   ██║╚════██║
  ╚████╔╝ ██║ ╚═╝ ██║███████╗███████║   ██║   ╚██████╔╝██║     ╚██████╔╝███████║
   ╚═══╝  ╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝      ╚═════╝ ╚══════╝
```

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
