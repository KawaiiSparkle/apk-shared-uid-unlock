// dex_dump.js -- scan every readable mapping of a live process for dex images and
// hand the whole byte ranges back to the host side for validation.
//
// Differences from a naive scanner:
//   1. Scans r--, rw-, r-x and rwx. Real (decrypted) dex often lives in an
//      anonymous heap mapping, not in a file-backed r-- mapping.
//   2. Version byte is wildcarded (035..039): many loaders rebuild dex as 039.
//   3. Validation is done on the host side (adler32 + SHA-1), so junk hits and
//      loader-modified buffers are dropped instead of written to disk.
const PATTERN = '64 65 78 0a 30 33 ?? 00';   // "dex\n03x\0"
const MAX_RANGE = 512 * 1024 * 1024;

function scanAll() {
  const out = [];
  const seen = {};
  const protos = ['r--', 'rw-', 'r-x', '--x', 'rwx'];
  for (const proto of protos) {
    let ranges = [];
    try { ranges = Process.enumerateRanges(proto); } catch (e) { continue; }
    for (const r of ranges) {
      if (r.size <= 0 || r.size > MAX_RANGE) continue;
      let hits = [];
      try { hits = Memory.scanSync(r.base, r.size, PATTERN); } catch (e) { continue; }
      for (const h of hits) {
        try {
          const fs = h.address.add(32).readU32();
          const hs = h.address.add(36).readU32();
          const et = h.address.add(40).readU32();
          if (hs !== 0x70 || et !== 0x12345678) continue;
          if (fs <= 0x70 || fs > 64 * 1024 * 1024) continue;
          const key = h.address.toString();
          if (seen[key]) continue;
          seen[key] = 1;
          let ver = '';
          try { ver = h.address.add(4).readUtf8(3); } catch (e) {}
          out.push({ addr: key, size: fs, ver: ver, base: r.base.toString() });
        } catch (e) {}
      }
    }
  }
  return out;
}

rpc.exports = {
  scan: scanAll,
  pull: function (addr, size) { return ptr(addr).readByteArray(size); },
  info: function () {
    return { pid: Process.id, arch: Process.arch, ptr: Process.pointerSize * 8 };
  }
};
