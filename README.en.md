# apk-shared-uid-unlock

**A pre-processing step for unpacking Android apps that claim `android.uid.system`**

[中文](./README.md) | English

---

## In one line

Rewrite a platform-exclusive `sharedUserId` with an **equal-length** alias so that an app which could never be installed on a normally-signed device installs and starts. Only a running process ever reaches the unpacking stage — so getting the process to start is the whole prerequisite.

This repository covers **that prerequisite only**: install → launch → take the code out of live memory. It contains no vendor-specific or packer-specific knowledge.

## The problem

Many OEM-bundled apps declare:

```xml
<manifest android:sharedUserId="android.uid.system" ...>
```

That declaration asks to join the system UID's shared user group. The check happens at **install time**: only packages signed with the platform key may join.

Any re-signed or third-party copy is therefore rejected before it ever runs:

```
INSTALL_FAILED_SHARED_USER_INCOMPATIBLE
```

Nothing about runtime logic is involved: if the package never installs, the process never exists, and there is nothing to analyse dynamically.

## Why an equal-length rewrite is safe

In a binary `AndroidManifest.xml` (AXML) the strings live in a string pool, and everything else refers to them by **offset and length**. If the replacement is **exactly the same number of bytes**, no offset or length has to be recomputed and the file layout is untouched — no aapt2/apktool rebuild, no resource-ID drift, no recompiled artefacts.

```
android.uid.system    (17 bytes, UTF-8)
android.uid.sysadm    (17 bytes, UTF-8)
```

After the rewrite the app runs under its **own ordinary UID** instead of the system group. It installs. It starts.

## Quick start

```bash
pip install -r requirements.txt          # frida is only needed for --dump
export ANDROID_HOME=/path/to/android-sdk # or pass --build-tools

# patch manifest -> repack -> zipalign -> sign -> verify -> install
python src/priv_unlock.py app.apk --install

# and immediately pull every self-validating dex out of memory
python src/priv_unlock.py app.apk --install --dump
```

Dump separately, from an already installed app:

```bash
adb forward tcp:27042 tcp:27042          # frida-server listening on 27042
python src/dex_dump.py --package com.example.app --out dumps
```

Batch mode:

```bash
python src/priv_unlock.py incoming/*.apk --out out/
```

## Output

| File | Meaning |
| --- | --- |
| `<name>_unlocked.apk` | patched `sharedUserId`, re-signed (v1+v2+v3) |
| `<name>_dumps/classesN.dex` | dex images recovered from memory that pass self-validation |
| `<name>_dumps/manifest.json` | version, string count, class count, SHA-1 per image |

"Real dex" is decided by validation, not by size or file name:

```
header_size == 0x70
endian_tag  == 0x12345678
adler32(d[12:]) == header.checksum
sha1(d[32:])    == header.signature
```

All four must hold before anything is written. Reassembled buffers, mutated bytes and coincidental magic hits are discarded.

## Scope and limits

**Handles**

- Apps blocked purely by `sharedUserId` at install time: they install and start
- Loaders that decrypt early in `Application.attachBaseContext` (the common case): memory is decrypted as soon as the process is alive
- "I just need the code": the dumped dex feeds straight into any static tool

**Does not handle**

- Features that genuinely need system identity: `SecurityException` is the expected outcome (see [docs/field-notes.md](docs/field-notes.md))
- Sharing the data directory with the real system app: renaming the shared UID ends that
- A shared user that already exists on the device under a different certificate: install fails with `INSTALL_FAILED_SHARED_USER_INCOMPATIBLE`; reuse the same key (`--keystore`)
- Integrity checks, anti-debugging and in-app certificate self-checks: out of scope here

## Requirements

- An `adb`-reachable Android device (must be able to run frida-server for `--dump`)
- Android SDK build-tools (`zipalign` + `apksigner`)
- A JDK (`keytool`)
- Optional: `frida` (only for `--dump`)

## Docs

- [docs/field-notes.md](docs/field-notes.md) — real-world boundaries, verbatim errors, how each was judged
- [docs/technique.md](docs/technique.md) — AXML string pool and the exact safety condition for in-place edits

## Disclaimer

For compatibility testing on your own devices, security research and teaching. Use it only on devices and samples you own or are explicitly authorised to test. It is not intended to bypass payment, DRM or licensing. The author takes no responsibility for misuse.

## License

[MIT](./LICENSE)
