# Technique: equal-length edits inside a binary AndroidManifest

## What is in the file

\`AndroidManifest.xml\` inside an APK is not text. It is a binary resource tree:

\`\`\`
ResChunk_header (type=0x0003 XML, headerSize, size)
  StringPool        <- every string in the document, once
  ResourceMap       <- maps attribute name indexes to resource IDs
  XML tree nodes    <- START_NAMESPACE / START_ELEMENT / END_ELEMENT / ...
\`\`\`

Attribute values that are strings do **not** store the text. They store an index into the string pool:

\`\`\`
ResXMLTree_attribute { ns, name, rawValue, typedValue }
                     rawValue = index into StringPool
\`\`\`

So \`android:sharedUserId="android.uid.system"\` is two pool entries — the attribute name and the value — plus an integer index pointing at the value.

## The string pool's two encodings

The pool header carries a \`UTF8_FLAG\`. Depending on it, each string is laid out as either:

\`\`\`
UTF-16: [u16 length] [u16 bytes...] [u16 0x0000]
UTF-8 : [u8 utf16len] [u8 utf8len] [bytes...] [0x00]
\`\`\`

A pool also holds an offset table: one 32-bit offset per string, pointing at that string's start. **Every offset after the edited string depends on the edited string's byte length.** This is why a longer or shorter replacement is not a local edit: it shifts the whole pool, invalidates the offset table, and requires rewriting sizes in every enclosing chunk header. That is the job aapt2/apktool do when they rebuild — and rebuilding is exactly what changes resource IDs, re-compresses entries and makes the output diverge from the signed original.

## The safety condition

If \`len(new) == len(old)\` **in the same encoding**, then:

- the string's own header (length fields) can be adjusted in place,
- the offset table is unchanged (same start offsets),
- every enclosing chunk keeps its \`size\`,
- the file keeps its exact length.

The edit is then a handful of bytes:

\`\`\`
android.uid.system -> android.uid.sysadm     # 2 bytes differ
\`\`\`

Everything else in the archive stays byte-identical. \`priv_unlock.py\` asserts this: it refuses any pair whose lengths differ, and a rebuild diff over a real sample shows a single changed entry out of several hundred.

## Why the alias must be different

Changing only the text would be pointless if the alias were still the same identity. \`android.uid.system\` maps to a fixed shared user created by the platform at boot; an app cannot join it without the platform certificate. The alias produces a **new, ordinary** shared user, created on first install, owned by whatever key you sign with.

The side effect is deliberate and useful: multiple packages can join your alias by sharing one keystore, reproducing the original co-installation relationship without any platform key.

## Where the interception happens in time

The framework loads the code as part of process startup:

\`\`\`
Zygote fork
  -> ActivityThread.main
    -> Instrumentation.newApplication
      -> Application.attachBaseContext   <- loaders decrypt here
        -> Application.onCreate
\`\`\`

A loader has to have plain code in memory before the first app frame runs, or the app could not start at all. That is why "the process is alive" is a sufficient signal, and why the ordering is: install first, dump second — never the other way round.
