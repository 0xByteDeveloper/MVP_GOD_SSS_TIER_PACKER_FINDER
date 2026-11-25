#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""katman_isleri4.py — ikinci derleme oturumu işleri:
  a) 3.0.9 dış (eski nesil) + 3.4.0 iç
  b) 3.4.0 dış + 3.4.0 iç (aynı sürüm çifti)
  c) 3.9.4 wrapper + hello_mingw (Sleep 15s — runtime demo hedefi)
  d) 3.9.4 + Random Section Names script (bölüm adları rastgele — 'modlanmış' senaryo)
"""
import os, json, shutil, importlib.util

KOK = "/home/z/my-project"
ALLVER = f"{KOK}/work/allver/Allver_Collection"
YENI = f"{KOK}/work/yeni"

spec = importlib.util.spec_from_file_location("vmp_proje", f"{KOK}/scripts/vmp_proje.py")
vp = importlib.util.module_from_spec(spec); spec.loader.exec_module(vp)

isler = []

# a) 3.0.9 dış + 3.4.0 iç
d = f"{YENI}/07_Katman_VMP_VMP"
ic = os.path.join(d, "Test_64_34_ic2.exe")
shutil.copy(f"{KOK}/work/corpus/VMProtect_Ultimate_3.4.0/Test_64_fn0.vmp.exe", ic)
proje = os.path.join(d, "katman_309dis_34ic.vmp")
open(proje,"w").write(vp.proje_xml(ic, os.path.join(d, "Test_64_309dis_34ic.vmp.vmp.exe")))
isler.append({"surum_dizin": f"{ALLVER}/VMProtect Ultimate 3.0.9", "proje": proje,
              "cikti": os.path.join(d, "Test_64_309dis_34ic.vmp.vmp.exe"),
              "azami": 300, "etiket": "VMP309_dis_VMP340_ic"})

# b) 3.4.0 dış + 3.4.0 iç (aynı sürüm)
ic = os.path.join(d, "Test_64_34_ic3.exe")
shutil.copy(f"{KOK}/work/corpus/VMProtect_Ultimate_3.4.0/Test_64_fn0.vmp.exe", ic)
proje = os.path.join(d, "katman_34_34.vmp")
open(proje,"w").write(vp.proje_xml(ic, os.path.join(d, "Test_64_34_34.vmp.vmp.exe")))
isler.append({"surum_dizin": f"{ALLVER}/VMProtect Ultimate 3.4.0", "proje": proje,
              "cikti": os.path.join(d, "Test_64_34_34.vmp.vmp.exe"),
              "azami": 300, "etiket": "VMP340_dis_VMP340_ic"})

# c) 3.9.4 wrapper + hello_mingw (Sleep'li — runtime demo)
d = f"{YENI}/09_Runtime_Demo"; os.makedirs(d, exist_ok=True)
ic = os.path.join(d, "hello.exe")
shutil.copy(f"{YENI}/02_Negatif/hello_mingw.exe", ic)
proje = os.path.join(d, "katman_hello394.vmp")
open(proje,"w").write(vp.proje_xml(ic, os.path.join(d, "hello_394.vmp.exe")))
isler.append({"surum_dizin": f"{ALLVER}/VMProtect Ultimate 3.9.4", "proje": proje,
              "cikti": os.path.join(d, "hello_394.vmp.exe"),
              "azami": 300, "etiket": "VMP394_hello_runtime"})

# d) 3.9.4 + Random Section Names (script ile bölüm adları rastgele)
ic = os.path.join(d, "hello2.exe")
shutil.copy(f"{YENI}/02_Negatif/hello_mingw.exe", ic)
proje = os.path.join(d, "katman_hello_rastgele.vmp")
xml = vp.proje_xml(ic, os.path.join(d, "hello_394_rastgele_bolum.vmp.exe"))
script = '''    <Script>
        <![CDATA[function GetRandomSectionName()
	local res = ""
	for i = 1, 8 do
		res = res .. string.char(32 + math.random(string.byte("z") - 32))
	end
	return res
end

function OnAfterSaveFile()
	local file = vmprotect.core():outputArchitecture()
	for i = 1, file:segments():count() do
		segment = file:segments():item(i)
		name = GetRandomSectionName()
		segment:setName(name)
	end
end]]>
</Script>'''
# </Document> öncesine Script'i ekle
xml = xml.replace("</Document>", script + "\n</Document>")
open(proje,"w").write(xml)
isler.append({"surum_dizin": f"{ALLVER}/VMProtect Ultimate 3.9.4", "proje": proje,
              "cikti": os.path.join(d, "hello_394_rastgele_bolum.vmp.exe"),
              "azami": 300, "etiket": "VMP394_hello_rastgele_bolum"})

json.dump({"isler": isler}, open(f"{YENI}/katman_isler4.json","w"), indent=1)
for i in isler: print(i["etiket"], "->", os.path.basename(i["cikti"]))
print("iş:", len(isler))
