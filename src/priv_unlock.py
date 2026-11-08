#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
priv_unlock.py -- turn an APK that claims a platform-exclusive shared UID into one
that installs and launches on a normal (non-platform-signed) device.

Why this exists
    An app declaring android:sharedUserId="android.uid.system" can only be installed
    when signed with the platform key. Anything else fails at install time with
    INSTALL_FAILED_SHARED_USER_INCOMPATIBLE, so the process never starts and any
    runtime unpacking never happens.

What it does
    1. Rewrite the shared UID string to an equal-length alias inside the binary
       AndroidManifest.xml. Equal length means every offset and length in the
       string pool stays valid -- no aapt2/apktool rebuild, no resource churn.
    2. Rebuild the archive entry by entry, preserving compression type, timestamps
       and attributes.
    3. zipalign -p 4, then apksigner (v1+v2+v3), then verify.
    4. Optionally install, optionally spawn + dump code from process memory.

Usage
    python priv_unlock.py app.apk [app2.apk ...] [--out DIR] [--install] [--dump]
                                  [--package PKG] [--device HOST:PORT]
                                  [--build-tools DIR] [--keystore FILE] [--keep]

Exit code: 0 all succeeded, 1 something failed.
"""
import argparse, os, re, subprocess, sys, zipfile

MANIFEST = "AndroidManifest.xml"
PREFIX = b"android.uid."

# Known platform UIDs -> equal-length aliases (length must match exactly).
NAMED = {
    b"system": b"sysadm",
    b"radio": b"radix",
    b"nfc": b"nfx",
    b"phone": b"phonx",
    b"bluetooth": b"bluetootx",
}


def pick_new(val: bytes) -> bytes:
    """val is the full shared UID (android.uid.xxx); only the last segment changes."""
    head, sep, tail = val.rpartition(b".")
    if not sep:
        head, tail = b"", val
    new_tail = NAMED.get(tail)
    if new_tail is None:
        if len(tail) < 2:
            new_tail = tail
        else:
            last = tail[-1:]
            new_tail = tail[:-1] + (b"y" if last == b"x" else b"x")
    return head + sep + new_tail


def find_shared_uids(data: bytes):
    """Return [(offset, encoding, old, new)] for UTF-8 and UTF-16LE string pools."""
    out = []

    for m in re.finditer(re.escape(PREFIX), data):
        s = m.start()
        j = s
        while j < len(data) and (48 <= data[j] <= 57 or 65 <= data[j] <= 90 or
                                 97 <= data[j] <= 122 or data[j] in (46, 95)):
            j += 1
        val = data[s:j]
        out.append((s, "utf8", val, pick_new(val)))

    pat = b"".join(bytes([c, 0]) for c in PREFIX)
    for m in re.finditer(re.escape(pat), data):
        s = m.start()
        j = s
        while j + 1 < len(data) and data[j + 1] == 0 and (
                48 <= data[j] <= 57 or 65 <= data[j] <= 90 or
                97 <= data[j] <= 122 or data[j] in (46, 95)):
            j += 2
        val = data[s:j:2]
        out.append((s, "utf16", val, pick_new(val)))

    seen, uniq = set(), []
    for hit in out:
        if hit[0] in seen:
            continue
        seen.add(hit[0])
        uniq.append(hit)
    return uniq


def patch_manifest(raw: bytes):
    hits = find_shared_uids(raw)
    if not hits:
        return raw, []
    buf = bytearray(raw)
    changes = []
    for off, enc, old, new in hits:
        if len(old) != len(new):
            raise RuntimeError("length mismatch, refusing in-place patch: %r -> %r" % (old, new))
        if enc == "utf8":
            buf[off:off + len(old)] = new
        else:
            buf[off:off + len(old) * 2] = b"".join(bytes([c, 0]) for c in new)
        changes.append((enc, old.decode(), new.decode()))
    return bytes(buf), changes


def rebuild(src, dst, patched_manifest):
    zin = zipfile.ZipFile(src)
    with zipfile.ZipFile(dst, "w") as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename == MANIFEST:
                data = patched_manifest
            zi = zipfile.ZipInfo(item.filename, date_time=item.date_time)
            zi.compress_type = item.compress_type
            zi.external_attr = item.external_attr
            zi.internal_attr = item.internal_attr
            zi.create_system = item.create_system
            zout.writestr(zi, data)
    zin.close()


def find_build_tools(explicit=None):
    cands = []
    if explicit:
        cands.append(explicit)
    if os.environ.get("ANDROID_BUILD_TOOLS"):
        cands.append(os.environ["ANDROID_BUILD_TOOLS"])
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    cands += [os.path.join(here, "android-14"), os.path.join(root, "android-14")]
    sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if sdk:
        bt = os.path.join(sdk, "build-tools")
        if os.path.isdir(bt):
            for v in sorted(os.listdir(bt), reverse=True):
                cands.append(os.path.join(bt, v))
    for base in (here, root):
        try:
            for name in os.listdir(base):
                if name.startswith("android-") or name.startswith("build-tools"):
                    cands.append(os.path.join(base, name))
        except OSError:
            pass
    for c in cands:
        if not c:
            continue
        for exe in ("zipalign.exe", "zipalign"):
            if os.path.exists(os.path.join(c, exe)):
                return os.path.abspath(c)
    raise SystemExit("build-tools not found (need zipalign + apksigner); pass --build-tools")


def ensure_keystore(ks, alias="test", pw="android"):
    if os.path.exists(ks):
        return
    print("[*] generating keystore: %s" % ks)
    subprocess.check_call(["keytool", "-genkeypair", "-keystore", ks, "-storepass", pw,
                           "-keypass", pw, "-alias", alias, "-keyalg", "RSA",
                           "-keysize", "2048", "-validity", "10000",
                           "-dname", "CN=unlock, OU=local, O=local, C=CN"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    out = (p.stdout or "") + (p.stderr or "")
    if p.returncode != 0:
        print(out[-1500:])
        raise RuntimeError("command failed: %s" % cmd[0])
    return out


def read_package(apk, bt):
    for exe in ("aapt2.exe", "aapt.exe", "aapt2", "aapt"):
        path = os.path.join(bt, exe)
        if not os.path.exists(path):
            continue
        try:
            if "aapt2" in exe:
                out = run([path, "dump", "packagename", apk])
                name = out.strip().splitlines()[-1].strip()
                if re.fullmatch(r"[A-Za-z0-9_.]+", name):
                    return name
            else:
                for line in run([path, "dump", "badging", apk]).splitlines():
                    if line.startswith("package:"):
                        return line.split("name='")[1].split("'")[0]
        except Exception:
            continue
    return None


def process(src, a, bt, ks):
    outdir = a.out or os.path.dirname(os.path.abspath(src))
    os.makedirs(outdir, exist_ok=True)
    stem = os.path.splitext(os.path.basename(src))[0]
    patched = os.path.join(outdir, stem + "_unlocked.apk")
    aligned = os.path.join(outdir, stem + "_aligned.apk")

    print("\n=== %s (%d bytes)" % (os.path.basename(src), os.path.getsize(src)))
    raw = zipfile.ZipFile(src).read(MANIFEST)
    new_raw, changes = patch_manifest(raw)
    if not changes:
        print("[1/5] no android.uid.* declared -> re-sign only")
    else:
        for enc, old, new in changes:
            print("[1/5] %-5s %s -> %s (same length, %d bytes)" % (enc, old, new, len(old)))

    rebuild(src, patched, new_raw)
    print("[2/5] archive rebuilt")

    zipalign = os.path.join(bt, "zipalign.exe" if os.name == "nt" else "zipalign")
    run([zipalign, "-p", "-f", "4", patched, aligned])
    print("[3/5] zipalign -p 4")

    signer = os.path.join(bt, "apksigner.bat" if os.name == "nt" else "apksigner")
    run([signer, "sign", "--ks", ks, "--ks-pass", "pass:android", "--key-pass", "pass:android",
         "--ks-key-alias", "test", "--v1-signing-enabled", "true",
         "--v2-signing-enabled", "true", "--v3-signing-enabled", "true",
         "--out", patched, aligned])
    print("[4/5] signed v1+v2+v3")

    info = run([signer, "verify", "--print-certs", patched])
    dn = [l for l in info.splitlines() if "DN:" in l]
    print("[5/5] verified  %s" % (dn[0].split("DN:")[-1].strip() if dn else ""))

    if not a.keep:
        try:
            os.remove(aligned)
        except OSError:
            pass

    ok_install = None
    if a.install:
        try:
            out = run(["adb", "install", "-r", "-d", patched])
            ok_install = "Success" in out
            print("[+] adb install: %s" % ("Success" if ok_install else out.strip()[-300:]))
        except Exception as e:
            ok_install = False
            print("[!] install failed (device offline?): %s" % e)

    if a.dump and ok_install:
        pkg = a.package or read_package(src, bt)
        if not pkg:
            print("[!] cannot read package name, skipping dump (use --package)")
        else:
            dumpdir = os.path.join(outdir, stem + "_dumps")
            print("[+] dump %s -> %s" % (pkg, dumpdir))
            try:
                run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                  "dex_dump.py"),
                     "--package", pkg, "--device", a.device, "--out", dumpdir,
                     "--wait", str(a.wait)])
            except Exception as e:
                print("[!] dump failed: %s" % e)

    return patched, changes, ok_install


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("apks", nargs="+", help="one or more APKs")
    ap.add_argument("--out", default=None, help="output directory")
    ap.add_argument("--build-tools", default=None, help="directory holding zipalign + apksigner")
    ap.add_argument("--keystore", default=None, help="signing keystore (alias test, pass android)")
    ap.add_argument("--install", action="store_true", help="adb install after signing")
    ap.add_argument("--dump", action="store_true", help="spawn and dump after install")
    ap.add_argument("--package", default=None, help="package name (default: read from APK)")
    ap.add_argument("--device", default="127.0.0.1:27042", help="frida device")
    ap.add_argument("--wait", type=float, default=20.0, help="dump polling window, seconds")
    ap.add_argument("--keep", action="store_true", help="keep the aligned intermediate")
    a = ap.parse_args()

    bt = find_build_tools(a.build_tools)
    ks = a.keystore or os.path.join(os.path.dirname(os.path.abspath(__file__)), "unlock.jks")
    ensure_keystore(ks)
    print("build-tools: %s\nkeystore   : %s" % (bt, ks))

    results, failed = [], 0
    for src in a.apks:
        try:
            results.append(process(src, a, bt, ks))
        except Exception as e:
            failed += 1
            print("[FAIL] %s: %s" % (os.path.basename(src), e))

    print("\n---- summary ----")
    for path, changes, ok_install in results:
        tag = " ".join("%s->%s" % (o, n) for _, o, n in changes) or "(resign only)"
        print("%-45s %9d B  %s%s" % (os.path.basename(path), os.path.getsize(path), tag,
                                     "" if ok_install is None else
                                     ("  installed" if ok_install else "  install-failed")))
    print("ok %d / failed %d" % (len(results), failed))
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
