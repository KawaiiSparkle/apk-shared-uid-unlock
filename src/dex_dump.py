#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dex_dump.py -- pull every self-validating dex image out of a running Android process.

Usage
    python dex_dump.py --package com.example.app
    python dex_dump.py --package com.example.app --device 127.0.0.1:27042 --wait 30
    python dex_dump.py --package com.example.app --no-spawn     # attach to a live process

Prerequisites
    adb forward tcp:27042 tcp:27042      (frida-server/gadget listening on 27042)
    or --device <host>:<port>

A candidate only counts as a real dex when the image validates end to end:
    header_size == 0x70, endian_tag == 0x12345678,
    adler32(d[12:]) == header checksum, sha1(d[32:]) == header signature
So loader-inflated buffers and coincidental magic hits are rejected.
"""
import argparse, hashlib, json, os, struct, sys, time, zlib

try:
    import frida
except ImportError:
    sys.exit("frida is required: pip install frida")

HERE = os.path.dirname(os.path.abspath(__file__))
AGENT = os.path.join(HERE, "dex_dump.js")


def verify(d: bytes):
    if len(d) < 0x70 or d[:4] != b"dex\n":
        return None
    file_size, header_size, endian = struct.unpack_from("<III", d, 32)
    if header_size != 0x70 or endian != 0x12345678 or file_size != len(d):
        return None
    checksum = struct.unpack_from("<I", d, 8)[0]
    if zlib.adler32(d[12:]) & 0xFFFFFFFF != checksum:
        return None
    if hashlib.sha1(d[32:]).digest() != d[12:32]:
        return None
    return {
        "ver": d[4:7].decode("ascii", "ignore"),
        "strings": struct.unpack_from("<I", d, 56)[0],
        "classes": struct.unpack_from("<I", d, 96)[0],
        "sha1": hashlib.sha1(d).hexdigest(),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--package", required=True)
    ap.add_argument("--device", default="127.0.0.1:27042")
    ap.add_argument("--out", default=None)
    ap.add_argument("--wait", type=float, default=20.0, help="polling window in seconds")
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--no-spawn", action="store_true", help="attach instead of spawn")
    ap.add_argument("--no-resume", action="store_true", help="spawn and stay suspended")
    a = ap.parse_args()

    out = a.out or os.path.join(os.getcwd(), "dumps")
    os.makedirs(out, exist_ok=True)

    dev = frida.get_device_manager().add_remote_device(a.device)
    if a.no_spawn:
        pid = dev.get_process(a.package).pid
        print("[*] attaching to pid=%d" % pid)
    else:
        pid = dev.spawn([a.package])
        print("[*] spawned pid=%d (%s)" % (pid, a.package))

    session = dev.attach(pid)
    script = session.create_script(open(AGENT, encoding="utf-8").read())
    script.load()
    try:
        print("[*] agent: %s" % script.exports_sync.info())
    except Exception:
        pass
    if not a.no_spawn and not a.no_resume:
        dev.resume(pid)
        print("[*] resumed")

    got, t0 = {}, time.time()
    while time.time() < t0 + a.wait:
        time.sleep(a.interval)
        try:
            hits = script.exports_sync.scan()
        except Exception as e:
            print("[!] scan failed: %s" % e)
            continue
        for h in hits:
            key = "%s:%d" % (h["addr"], h["size"])
            if key in got:
                continue
            try:
                data = bytes(script.exports_sync.pull(h["addr"], h["size"]))
            except Exception:
                continue
            meta = verify(data)
            if not meta:
                got[key] = "invalid"
                continue
            if meta["sha1"] in {v["sha1"] for v in got.values() if isinstance(v, dict)}:
                got[key] = "duplicate"
                continue
            idx = sum(1 for v in got.values() if isinstance(v, dict)) + 1
            fn = os.path.join(out, "classes%d.dex" % idx)
            with open(fn, "wb") as f:
                f.write(data)
            got[key] = meta
            print("[+] %s  %d B  v%s strings=%d classes=%d  <- %s" %
                  (os.path.basename(fn), len(data), meta["ver"], meta["strings"],
                   meta["classes"], h["addr"]))
        if got and time.time() - t0 > 5:
            break

    valid = [v for v in got.values() if isinstance(v, dict)]
    print("\n[*] valid dex images: %d, written to %s" % (len(valid), out))
    with open(os.path.join(out, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump({"package": a.package, "pid": pid, "found": valid}, f, indent=2)
    session.detach()
    return 0 if valid else 2


if __name__ == "__main__":
    sys.exit(main())
