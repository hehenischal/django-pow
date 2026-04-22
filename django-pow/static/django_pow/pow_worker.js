/**
 * Django-POW Web Worker
 * ---------------------
 * Mines a nonce satisfying the Proof of Work requirement in a background thread.
 *
 * Expected message from the main thread:
 *   { challenge: string, difficulty: number, username: string, algorithm?: string }
 *
 * Posts back on success:
 *   { nonce: string, hash: string, attempts: number, durationMs: number }
 *
 * Posts back on failure / timeout:
 *   { error: "timeout" | "unsupported_algorithm", attempts: number }
 *
 * Hash preimage (must match the Django middleware):
 *   SHA-256( `${challenge}${username}${nonce}` )
 */

const PROGRESS_INTERVAL = 1000;   // log every N nonces
const BREATHE_INTERVAL  = 10_000; // yield to event loop every N nonces
const MAX_NONCE         = 10_000_000;

/**
 * Map Django algorithm names → SubtleCrypto algorithm strings.
 */
const ALGO_MAP = {
  sha256: "SHA-256",
  sha512: "SHA-512",
  md5: null,           // SubtleCrypto doesn't support MD5; handled via fallback
};

/** Tiny MD5 (RFC 1321) polyfill for environments that need it. */
function md5(input) {
  // Adapted from https://blueimp.github.io/JavaScript-MD5/ (MIT licence)
  function safeAdd(x, y) {
    const lsw = (x & 0xffff) + (y & 0xffff);
    return (((x >> 16) + (y >> 16) + (lsw >> 16)) << 16) | (lsw & 0xffff);
  }
  function bitRotateLeft(num, cnt) { return (num << cnt) | (num >>> (32 - cnt)); }
  function md5cmn(q, a, b, x, s, t) { return safeAdd(bitRotateLeft(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b); }
  function md5ff(a, b, c, d, x, s, t) { return md5cmn((b & c) | (~b & d), a, b, x, s, t); }
  function md5gg(a, b, c, d, x, s, t) { return md5cmn((b & d) | (c & ~d), a, b, x, s, t); }
  function md5hh(a, b, c, d, x, s, t) { return md5cmn(b ^ c ^ d, a, b, x, s, t); }
  function md5ii(a, b, c, d, x, s, t) { return md5cmn(c ^ (b | ~d), a, b, x, s, t); }

  const encoder = new TextEncoder();
  const bytes = encoder.encode(input);
  const len8 = bytes.length;
  const len32 = Math.ceil((len8 + 9) / 64) * 16;
  const m = new Int32Array(len32);
  for (let i = 0; i < len8; i++) m[i >> 2] |= bytes[i] << ((i % 4) * 8);
  m[len8 >> 2] |= 0x80 << ((len8 % 4) * 8);
  m[len32 - 2] = len8 * 8;

  let a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;
  for (let i = 0; i < len32; i += 16) {
    const [oa, ob, oc, od] = [a, b, c, d];
    a = md5ff(a, b, c, d, m[i],      7, -680876936);  b = md5ff(d, a, b, c, m[i+1],  12, -389564586);
    c = md5ff(c, d, a, b, m[i+2],   17,  606105819);  d = md5ff(b, c, d, a, m[i+3],  22, -1044525330);
    a = md5ff(a, b, c, d, m[i+4],    7, -176418897);  b = md5ff(d, a, b, c, m[i+5],  12,  1200080426);
    c = md5ff(c, d, a, b, m[i+6],   17, -1473231341); d = md5ff(b, c, d, a, m[i+7],  22, -45705983);
    a = md5ff(a, b, c, d, m[i+8],    7,  1770035416); b = md5ff(d, a, b, c, m[i+9],  12, -1958414417);
    c = md5ff(c, d, a, b, m[i+10],  17, -42063);      d = md5ff(b, c, d, a, m[i+11], 22, -1990404162);
    a = md5ff(a, b, c, d, m[i+12],   7,  1804603682); b = md5ff(d, a, b, c, m[i+13], 12, -40341101);
    c = md5ff(c, d, a, b, m[i+14],  17, -1502002290); d = md5ff(b, c, d, a, m[i+15], 22,  1236535329);
    a = md5gg(a, b, c, d, m[i+1],    5, -165796510);  b = md5gg(d, a, b, c, m[i+6],   9, -1069501632);
    c = md5gg(c, d, a, b, m[i+11],  14,  643717713);  d = md5gg(b, c, d, a, m[i+0],  20, -373897302);
    a = md5gg(a, b, c, d, m[i+5],    5, -701558691);  b = md5gg(d, a, b, c, m[i+10],  9,  38016083);
    c = md5gg(c, d, a, b, m[i+15],  14, -660478335);  d = md5gg(b, c, d, a, m[i+4],  20, -405537848);
    a = md5gg(a, b, c, d, m[i+9],    5,  568446438);  b = md5gg(d, a, b, c, m[i+14],  9, -1019803690);
    c = md5gg(c, d, a, b, m[i+3],   14, -187363961);  d = md5gg(b, c, d, a, m[i+8],  20,  1163531501);
    a = md5gg(a, b, c, d, m[i+13],   5, -1444681467); b = md5gg(d, a, b, c, m[i+2],   9, -51403784);
    c = md5gg(c, d, a, b, m[i+7],   14,  1735328473); d = md5gg(b, c, d, a, m[i+12], 20, -1926607734);
    a = md5hh(a, b, c, d, m[i+5],    4, -378558);     b = md5hh(d, a, b, c, m[i+8],  11, -2022574463);
    c = md5hh(c, d, a, b, m[i+11],  16,  1839030562); d = md5hh(b, c, d, a, m[i+14], 23, -35309556);
    a = md5hh(a, b, c, d, m[i+1],    4, -1530992060); b = md5hh(d, a, b, c, m[i+4],  11,  1272893353);
    c = md5hh(c, d, a, b, m[i+7],   16, -155497632);  d = md5hh(b, c, d, a, m[i+10], 23, -1094730640);
    a = md5hh(a, b, c, d, m[i+13],   4,  681279174);  b = md5hh(d, a, b, c, m[i+0],  11, -358537222);
    c = md5hh(c, d, a, b, m[i+3],   16, -722521979);  d = md5hh(b, c, d, a, m[i+6],  23,  76029189);
    a = md5hh(a, b, c, d, m[i+9],    4, -640364487);  b = md5hh(d, a, b, c, m[i+12], 11, -421815835);
    c = md5hh(c, d, a, b, m[i+15],  16,  530742520);  d = md5hh(b, c, d, a, m[i+2],  23, -995338651);
    a = md5ii(a, b, c, d, m[i+0],    6, -198630844);  b = md5ii(d, a, b, c, m[i+7],  10,  1126891415);
    c = md5ii(c, d, a, b, m[i+14],  15, -1416354905); d = md5ii(b, c, d, a, m[i+5],  21, -57434055);
    a = md5ii(a, b, c, d, m[i+12],   6,  1700485571); b = md5ii(d, a, b, c, m[i+3],  10, -1894986606);
    c = md5ii(c, d, a, b, m[i+10],  15, -1051523);    d = md5ii(b, c, d, a, m[i+1],  21, -2054922799);
    a = md5ii(a, b, c, d, m[i+8],    6,  1873313359); b = md5ii(d, a, b, c, m[i+15], 10, -30611744);
    c = md5ii(c, d, a, b, m[i+6],   15, -1560198380); d = md5ii(b, c, d, a, m[i+13], 21,  1309151649);
    a = md5ii(a, b, c, d, m[i+4],    6, -145523070);  b = md5ii(d, a, b, c, m[i+11], 10, -1120210379);
    c = md5ii(c, d, a, b, m[i+2],   15,  718787259);  d = md5ii(b, c, d, a, m[i+9],  21, -343485551);
    a = safeAdd(a, oa); b = safeAdd(b, ob); c = safeAdd(c, oc); d = safeAdd(d, od);
  }

  const out = [a, b, c, d];
  return out.map(n => {
    let hex = "";
    for (let j = 0; j < 4; j++) hex += ("0" + ((n >> (j * 8)) & 0xff).toString(16)).slice(-2);
    return hex;
  }).join("");
}


// ---------------------------------------------------------------------------
// Main worker logic
// ---------------------------------------------------------------------------

self.onmessage = async function (e) {
  const { challenge, difficulty, username, algorithm = "sha256" } = e.data;
  const startTime = Date.now();

  const diffInt = parseInt(difficulty, 10) || 4;
  const prefix = "0".repeat(diffInt);
  const encoder = new TextEncoder();
  const subtleAlgo = ALGO_MAP[algorithm.toLowerCase()];

  if (algorithm.toLowerCase() === "md5") {
    // MD5 path — synchronous, no SubtleCrypto
    let nonce = 0;
    while (nonce <= MAX_NONCE) {
      const msg = `${challenge}${username}${nonce}`;
      const hashHex = md5(msg);
      if (hashHex.startsWith(prefix)) {
        self.postMessage({ nonce: nonce.toString(), hash: hashHex, attempts: nonce + 1, durationMs: Date.now() - startTime });
        return;
      }
      nonce++;
      if (nonce % BREATHE_INTERVAL === 0) await new Promise(r => setTimeout(r, 0));
    }
    self.postMessage({ error: "timeout", attempts: nonce });
    return;
  }

  if (!subtleAlgo) {
    self.postMessage({ error: "unsupported_algorithm", attempts: 0 });
    return;
  }

  // SubtleCrypto path (SHA-256 / SHA-512)
  let nonce = 0;
  while (nonce <= MAX_NONCE) {
    const msg = `${challenge}${username}${nonce}`;
    const buf = await crypto.subtle.digest(subtleAlgo, encoder.encode(msg));
    const hashHex = Array.from(new Uint8Array(buf))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");

    if (hashHex.startsWith(prefix)) {
      self.postMessage({
        nonce: nonce.toString(),
        hash: hashHex,
        attempts: nonce + 1,
        durationMs: Date.now() - startTime,
      });
      return;
    }

    nonce++;
    if (nonce % PROGRESS_INTERVAL === 0) {
      self.postMessage({ progress: nonce });   // optional progress event
    }
    if (nonce % BREATHE_INTERVAL === 0) {
      await new Promise(r => setTimeout(r, 0));
    }
  }

  self.postMessage({ error: "timeout", attempts: nonce });
};
