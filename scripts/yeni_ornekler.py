#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""yeni_ornekler.py — Yeni yetenek test örnekleri üretir (GUI gerektirmeyenler).
Çıktılar: /home/z/my-project/work/yeni/
  01_Gercek_UPX/            — gerçek UPX ile paketlenmiş Test_64 (x64)
  02_Negatif/               — paketsiz EXE'ler (tespit edilmemeli)
  03_Themida_Izi/           — Themida imza yüzeyi sentetik örnekleri
  04_Bolum_Yeniden_Ad/      — section adları değiştirilmiş VMP build'leri
  05_Modlanmis_Motor/       — stub baytları yamanmış (modlanmış motor simülasyonu)
"""
import os, shutil, struct, subprocess, hashlib, json

KOK = "/home/z/my-project"
UPX = f"{KOK}/work/tools/upx"
YENI = f"{KOK}/work/yeni"
KAYNAK = f"{KOK}/upload/Test_64.exe"
CORPUS = f"{KOK}/work/corpus"

def sha256(p):
    h = hashlib.sha256()
    with open(p,'rb') as f:
        for blok in iter(lambda: f.read(1<<20), b''):
            h.update(blok)
    return h.hexdigest()

def pe_ayristir(veri):
    assert veri[:2] == b'MZ'
    e = struct.unpack_from('<I', veri, 0x3C)[0]
    assert veri[e:e+4] == b'PE\0\0'
    makine = struct.unpack_from('<H', veri, e+4)[0]
    bolum_sayisi = struct.unpack_from('<H', veri, e+6)[0]
    opt_boyut = struct.unpack_from('<H', veri, e+20)[0]
    opt = e + 24
    sihir = struct.unpack_from('<H', veri, opt)[0]
    giris = struct.unpack_from('<I', veri, opt+16)[0]
    bolumler = []
    bt = opt + opt_boyut
    for i in range(bolum_sayisi):
        o = bt + 40*i
        ad = veri[o:o+8].rstrip(b'\0').decode('ascii','replace')
        vsz, va, rsz, ro = struct.unpack_from('<IIII', veri, o+8)
        oz = struct.unpack_from('<I', veri, o+36)[0]
        bolumler.append({'ad':ad,'vsz':vsz,'va':va,'rsz':rsz,'ro':ro,'oz':oz})
    return {'makine':makine,'giris':giris,'sihir':sihir,'bolumler':bolumler,'e_lfanew':e,'opt':opt}

# ---------------------------------------------------------------- 01 gerçek UPX
d1 = f"{YENI}/01_Gercek_UPX"; os.makedirs(d1, exist_ok=True)
for seviye in (["--best"], ["--ultra-brute"], []):
    ad = "Test_64_upx" + ("_best" if "--best" in seviye else "_ultra" if seviye else "") + ".exe"
    hedef = os.path.join(d1, ad)
    shutil.copy(KAYNAK, hedef)
    r = subprocess.run([UPX, "-f", *seviye, "-q", hedef], capture_output=True, text=True)
    print(f"UPX {seviye}: rc={r.returncode} boyut={os.path.getsize(hedef)}")
    if r.returncode != 0:
        print("  stderr:", r.stderr[:200])

# ---------------------------------------------------------------- 02 negatifler
d2 = f"{YENI}/02_Negatif"; os.makedirs(d2, exist_ok=True)
# 2a: paketsiz Test_64
shutil.copy(KAYNAK, f"{d2}/Test_64_paketsiz.exe")
# 2b: mingw ile hello derle (farklı derleyici parmak izi)
hello_c = f"{d2}/_hello.c"
open(hello_c,'w').write('#include <stdio.h>\nint main(){printf("hello\\n");return 0;}\n')
mgcc = "/usr/bin/x86_64-w64-mingw32-gcc"
if not os.path.exists(mgcc):
    mgcc = None
    for p in (f"{KOK}/work/tools/mingw/usr/bin/x86_64-w64-mingw32-gcc",
              f"{KOK}/work/tools/mingw/usr/bin/x86_64-w64-mingw32-gcc.exe"):
        if os.path.exists(p): mgcc = p; break
if mgcc:
    r = subprocess.run([mgcc, hello_c, "-o", f"{d2}/hello_mingw.exe", "-static"],
                       capture_output=True, text=True)
    print("hello mingw rc:", r.returncode, os.path.getsize(f"{d2}/hello_mingw.exe") if r.returncode==0 else r.stderr[:150])
else:
    print("mingw yok — hello atlandı")
# 2c: UPX'lenmiş sonra geri açılmış (upx -d) — paketsiz dönmüş
kopya = f"{d2}/_roundtrip.exe"
shutil.copy(KAYNAK, kopya)
subprocess.run([UPX, "-f", "-q", kopya], capture_output=True)
r = subprocess.run([UPX, "-d", "-q", "-o", f"{d2}/Test_64_upx_geri_acilmis.exe", kopya], capture_output=True, text=True)
print("upx -d rc:", r.returncode)
os.remove(kopya)

# ---------------------------------------------------------------- 03 Themida imza yüzeyi
d3 = f"{YENI}/03_Themida_Izi"; os.makedirs(d3, exist_ok=True)
def themida_yap(kaynak, hedef, bolum_adi=b'.themida\0'):
    veri = bytearray(open(kaynak,'rb').read())
    pe = pe_ayristir(bytes(veri))
    # ilk standart-dışı hale getirilebilir bölüm: .rdata'yı .themida'ya çevir + RWX
    hedef_idx = None
    for i,b in enumerate(pe['bolumler']):
        if b['ad'] == '.rdata': hedef_idx = i; break
    if hedef_idx is None:
        for i,b in enumerate(pe['bolumler']):
            if b['ad'] not in ('.text','.data','.rsrc','.reloc'): hedef_idx = i; break
    bt = pe['opt'] + (pe['e_lfanew']+24+ - pe['opt']) # placeholder
    bt = pe['opt'] + struct.unpack_from('<H', veri, pe['e_lfanew']+20)[0]
    o = bt + 40*hedef_idx
    veri[o:o+8] = bolum_adi
    struct.pack_into('<I', veri, o+36, 0xE0000060)  # RWX
    # EP'yi o bölüme kaydır (Themida davranışı: EP protector içinde)
    ep_rva = pe['bolumler'][hedef_idx]['va'] + 0x10
    struct.pack_into('<I', veri, pe['opt']+16, ep_rva)
    # overlay'a Themida imza stringi
    veri += b'\x00' * 16 + b'Themida/WinLicense protected application\x00'
    open(hedef,'wb').write(bytes(veri))
    return len(veri)
n1 = themida_yap(KAYNAK, f"{d3}/Test_64_themida_izi.exe")
print("themida izi örnek:", n1)
# ikincisi: .boom bölüm adı varyantı (Themida eski sürüm izi)
themida_yap(KAYNAK, f"{d3}/Test_64_boom_izi.exe", b'.boom\0\0\0')

# ---------------------------------------------------------------- 04 bölüm yeniden adlandırma
d4 = f"{YENI}/04_Bolum_Yeniden_Ad"; os.makedirs(d4, exist_ok=True)
def bolum_ad_degistir(kaynak, hedef, eslesen_ondek='.vmp', yeni_ondek='sect'):
    veri = bytearray(open(kaynak,'rb').read())
    pe = pe_ayristir(bytes(veri))
    bt = pe['opt'] + struct.unpack_from('<H', veri, pe['e_lfanew']+20)[0]
    sayac = 0
    for i,b in enumerate(pe['bolumler']):
        if b['ad'].lower().startswith(eslesen_ondek):
            o = bt + 40*i
            yeni = f"{yeni_ondek}{sayac}".encode()[:8]
            yeni += b'\0' * (8 - len(yeni))
            veri[o:o+8] = yeni
            sayac += 1
    open(hedef,'wb').write(bytes(veri))
    return sayac
# 3 farklı sürümden örnekler
ornekler = [
    ("VMProtect_Ultimate_3.4.0", "Test_64_fn0.vmp.exe", "Test_64_34_adlar_degisti.exe"),
    ("VMProtect_Ultimate_3.6.0", "Test_64_fn0.vmp.exe", "Test_64_36_adlar_degisti.exe"),
    ("VMProtect_Ultimate_3.0.9", "Test_64_fn0.vmp.exe", "Test_64_309_adlar_degisti.exe"),
    ("VMProtect_Lite_3.10.4", "Test_64_fn0.vmp.exe", "Test_64_3104_adlar_degisti.exe"),
]
for surum, kaynak_ad, hedef_ad in ornekler:
    kp = os.path.join(CORPUS, surum, kaynak_ad)
    if os.path.exists(kp):
        n = bolum_ad_degistir(kp, os.path.join(d4, hedef_ad))
        print(f"{surum} -> {hedef_ad}: {n} bölüm yeniden adlandı, boyut={os.path.getsize(os.path.join(d4, hedef_ad))}")
    else:
        print(f"YOK: {kp}")

# ---------------------------------------------------------------- 05 modlanmış motor simülasyonu
d5 = f"{YENI}/05_Modlanmis_Motor"; os.makedirs(d5, exist_ok=True)
def stub_yama(kaynak, hedef, pozisyonlar):
    """koruyucu bölümün stub bölgesindeki baytları değiştirir (modlanmış motor izi).
    PE geçerliliği korunur; kod çalıştırılmayacağı için kırık olması sorun değil."""
    veri = bytearray(open(kaynak,'rb').read())
    pe = pe_ayristir(bytes(veri))
    yamalar = 0
    for b in pe['bolumler']:
        if b['ad'].lower().startswith('.vmp') and b['rsz'] > 0x800:
            # stub başlangıcı: bölüm verisinin ilk 4KB'ı — motor kodu
            taban = b['ro']
            for p in pozisyonlar:
                if p + 8 < b['rsz']:
                    # motor komut baytlarını değiştir (farklı ama geçerli komut deseni)
                    veri[taban+p] ^= 0x5A
                    veri[taban+p+1] ^= 0xA5
                    yamalar += 1
            break
    open(hedef,'wb').write(bytes(veri))
    return yamalar
# 3.4.0 / 3.6.0 / 3.10.4'ten: stub içi 24 ayrık nokta yaması
for surum, kaynak_ad, hedef_ad in [
    ("VMProtect_Ultimate_3.4.0", "Test_64_fn0.vmp.exe", "Test_64_34_modlanmis.exe"),
    ("VMProtect_Ultimate_3.6.0", "Test_64_fn0.vmp.exe", "Test_64_36_modlanmis.exe"),
    ("VMProtect_Lite_3.10.4", "Test_64_fn0.vmp.exe", "Test_64_3104_modlanmis.exe"),
    ("VMProtect_Ultimate_3.0.9", "Test_64_fn0.vmp.exe", "Test_64_309_modlanmis.exe"),
]:
    kp = os.path.join(CORPUS, surum, kaynak_ad)
    if os.path.exists(kp):
        pozisyonlar = [0x100 + i*97 for i in range(24)]
        n = stub_yama(kp, os.path.join(d5, hedef_ad), pozisyonlar)
        print(f"{hedef_ad}: {n} stub noktası yamalandı")
    else:
        print(f"YOK: {kp}")

# özet
ozet = {}
for d in sorted(os.listdir(YENI)):
    tam = os.path.join(YENI, d)
    if os.path.isdir(tam):
        ozet[d] = sorted(f for f in os.listdir(tam) if f.endswith('.exe'))
json.dump(ozet, open(f"{YENI}/uretim_ozeti.json","w"), indent=1, ensure_ascii=False)
print(json.dumps(ozet, indent=1, ensure_ascii=False))
