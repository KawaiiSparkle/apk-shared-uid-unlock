# Field notes

Real behaviour observed while getting platform-privileged apps to run on a normal device. Errors are quoted verbatim; names of specific apps and vendors are omitted on purpose.

## 1. Install fails even after the UID rewrite

```
INSTALL_FAILED_SHARED_USER_INCOMPATIBLE: Reconciliation failed...:
Reconcile failed: Package com.example.app has no signatures that match those in
shared user android.uid.sysadm; ignoring!
```

**Cause** — the aliased shared user (`android.uid.sysadm`) already exists on the device, created by a previous install signed with a different certificate. A shared user is a *shared* identity: every member must carry the same signing certificate.

**Fix** — sign every package that will join the same alias with one keystore:

```bash
python src/priv_unlock.py a.apk --keystore keys/shared.jks
python src/priv_unlock.py b.apk --keystore keys/shared.jks
```

This is exactly the rule the platform enforces for the real `android.uid.system`. The rewrite does not remove the rule, it just moves it to an alias you control.

## 2. First framework call that needs system identity

```
java.lang.SecurityException: com.example.app was not granted this permission:
android.permission.WRITE_SETTINGS
  at ...OTAManager.setUpdateInfo(OTAManager.java:938)
```

Expected: the app used to inherit permissions from the system shared user. Now it is an ordinary UID.

Some of these are recoverable without touching the system partition, because `WRITE_SETTINGS` is gated by an app-op rather than a signature:

```bash
adb shell appops set com.example.app android:write_settings allow
```

Others (signature-level permissions, `WRITE_SECURE_SETTINGS`, binding to system services) are not, and that is the honest boundary of this technique.

## 3. Namespace guard, unrelated to the patch

```
java.lang.IllegalArgumentException: You cannot keep your settings in the secure settings.
  at android.provider.Settings$System.putStringForUser(Settings.java:4448)
```

The settings provider rejects writes to a key that belongs to the `Secure` namespace when addressed through `Settings.System`, based on the **name**, not the caller's UID. Apps written for older platforms hit this on newer ones. Nothing about the shared-UID rewrite causes or can fix it; the app would behave the same way with the platform key on that OS version.

If a specific write is cosmetic (a badge flag, a cached preference), patching it out of the bytecode is usually cheaper than chasing the framework.

## 4. frida cannot connect, but the server is alive

Symptom: `unable to connect to remote frida-server`, while on-device `/proc/net/tcp` shows the port in `LISTEN` and the server process exists.

**Cause** — device-to-host TCP is blocked or flaky (wireless debugging, per-app network policies, VPN/routing). The listener is fine; the path to it is not.

**Fix** — do not fight the network, tunnel it:

```bash
adb forward tcp:27042 tcp:27042
python src/dex_dump.py --package com.example.app --device 127.0.0.1:27042
```

## 5. The code is not where you expect it

Three findings that shaped `dex_dump.py`:

- **Not in the APK.** A loader may leave only a ~284-byte stub dex (`dex\n035`, 3 strings, 1 class) in the archive. That stub exists to satisfy the framework, not to hold code.
- **Not in the odex/vdex either.** `base.vdex` can be byte-identical to the *encrypted* payload in the APK.
- **In an anonymous heap mapping.** The decrypted images turned up inside a `[anon:libc_malloc]` region, in `rw-` protection — invisible to a scanner that only walks `r--` mappings, and invisible to a scanner that only matches `dex\n035`.

Hence: scan every protection, wildcard the version byte, and let checksum validation decide.

## 6. frida 17 dropped the built-in Java bridge

In frida 17 `typeof Java === "undefined"` inside an injected process; the ObjC/Java bridges are no longer part of the agent. Anything written as `Java.perform(...)` fails. Either ship `frida-java-bridge` through `frida-compile`, or — as here — stay purely on native memory APIs, which is all a dex dump needs.

## 7. What "verified dump" buys you

Before validating, we had a 22 MB dump containing four candidate headers. Two of them were plausible but wrong (loader scratch buffers). After applying `adler32` + `SHA-1` self-validation, exactly four images survived, and each one decompiled cleanly with the platform's own `dexdump` — including one that contained classes nobody could reach through the static path.

That is the whole argument for validating instead of guessing: the header tells you what the file claims to be, the checksum tells you whether it really is that file.
