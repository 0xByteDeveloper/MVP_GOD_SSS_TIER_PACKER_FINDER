#!/usr/bin/env python3
# Batch-1: native PE packer/protector source repos (shallow clone, token auth)
import subprocess, os, sys, concurrent.futures as cf

REPOS = [
    # (owner/repo, target-dir)
    ("upx/upx", "upx"),
    ("es3n1n/obfuscator", "es3n1n-obfuscator"),
    ("bytecode77/pe-union", "pe-union"),
    ("keowu/Ryujin", "ryujin"),
    ("DosX-dev/Astral-PE", "astral-pe"),
    ("DosX-dev/ASM-Guard", "asm-guard"),
    ("rwfpl/rewolf-x86-virtualizer", "rewolf-x86-virtualizer"),
    ("iamsopotatoe-coder/TinyLoad", "tinyload"),
    ("noahware/binprotect", "binprotect"),
    ("GunshipPenguin/kiteshield", "kiteshield"),
    ("elfmaster/maya", "maya"),
    ("phra/x0rro", "x0rro"),
    ("jonomango/chum", "chum"),
    ("DosX-dev/obfus.h", "obfus-h"),
    ("ac3ss0r/obfusheader.h", "obfusheader-h"),
    ("NIKJOO/PEP", "pep"),
    ("undisassemble/yap", "yap"),
    ("vertigo6622/obsidian-protector", "obsidian-protector"),
    ("sudfiona/NovaProtect", "novaprotect"),
    ("zhidun2027/zhidun", "zhidun"),
    ("xopJack/XopProtector", "xopprotector"),
    ("TheAenema/hm-pe-packer", "hm-pe-packer"),
    ("greyb1t/GreyM", "greym"),
    ("ximerus/Kryptonite", "kryptonite"),
    ("jozemberi/PE-Crypter", "pe-crypter"),
    ("icyguider/nimcrypt", "nimcrypt"),
    ("0xNullSec/NullCrypt", "nullcrypt"),
    ("ATsahikian/pe-protector", "pe-protector"),
    ("rootm0s/Protectors", "protectors"),
    ("sudachen/Molebox", "molebox"),
    ("akuafif/hXOR-Packer", "hxor-packer"),
    ("Alon-Alush/AlushPacker", "alushpacker"),
    ("hmyit/VMPROTECT", "hmyit-vmprotect"),
    ("mikasaw/wvmp", "wvmp"),
    ("nodiuus/nocturne", "nocturne"),
    ("qusamulab/kagura", "kagura"),
    ("Fatmike-GH/JitDecrypter", "jitdecrypter"),
    ("Fatmike-GH/Nanomites", "nanomites"),
    ("ac3ss0r/cvm.h", "cvm-h"),
    ("DosX-dev/BatchToApp", "batchtoapp"),
    ("DosX-dev/NET-MalwareCryptor", "net-malwarecryptor"),
]

TOKEN = os.environ.get("GH_TOKEN", "")
BASE = "/home/z/my-project/work/kaynak/packers"

def clone(item):
    repo, dirname = item
    dst = os.path.join(BASE, dirname)
    if os.path.isdir(dst) and os.listdir(dst):
        return (repo, "VAR", 0)
    url = f"https://x-access-token:{TOKEN}@github.com/{repo}.git" if TOKEN else f"https://github.com/{repo}.git"
    r = subprocess.run(["git", "clone", "--depth", "1", "--single-branch", url, dst],
                       capture_output=True, text=True, timeout=420)
    if r.returncode == 0:
        return (repo, "OK", 0)
    # retry anonymous (some fine-grained PATs block clone of public? no, but keep fallback)
    r2 = subprocess.run(["git", "clone", "--depth", "1", "--single-branch", f"https://github.com/{repo}.git", dst],
                        capture_output=True, text=True, timeout=420)
    return (repo, "FAIL:" + (r.stderr or r2.stderr).strip()[:160], r.returncode)

if __name__ == "__main__":
    ok, fail = 0, []
    with cf.ThreadPoolExecutor(max_workers=6) as ex:
        for repo, status, _ in ex.map(clone, REPOS):
            if status in ("OK", "VAR"):
                ok += 1
                print(f"[{status}] {repo}")
            else:
                fail.append(repo)
                print(f"[ERR] {repo} -> {status}")
    print(f"\n=== {ok}/{len(REPOS)} cloned, {len(fail)} failed ===")
    if fail:
        print("FAILED:", ", ".join(fail))
