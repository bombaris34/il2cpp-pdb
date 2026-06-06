// CodeView primitives: little-endian writer, record framing, LLVM string hash.

pub struct W {
    pub buf: Vec<u8>,
}
impl W {
    pub fn new() -> Self {
        W { buf: Vec::new() }
    }
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn i32(&mut self, v: i32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }
    /// NUL-terminated string.
    pub fn cstr(&mut self, s: &str) {
        self.buf.extend_from_slice(s.as_bytes());
        self.buf.push(0);
    }
    pub fn len(&self) -> usize {
        self.buf.len()
    }
}

/// Pad a CodeView record body to a 4-byte boundary using LF_PAD bytes (0xF1..0xF3).
/// Used for *type* records. `extra` accounts for bytes (e.g. the length field)
/// that precede the body but are not yet in `body`.
pub fn pad_type(body: &mut Vec<u8>) {
    let rem = body.len() % 4;
    if rem != 0 {
        let pad = 4 - rem;
        // 0xF0 | n  pattern, written high-to-low.
        for i in (1..=pad).rev() {
            body.push(0xF0 | (i as u8));
        }
    }
}

/// Symbol records align to 4 bytes with zero padding (length field includes it).
pub fn pad_sym(body: &mut Vec<u8>) {
    while body.len() % 4 != 0 {
        body.push(0);
    }
}

/// Frame a record: prepend the 2-byte length (covering kind + body), return full record.
pub fn frame(kind: u16, body: &[u8]) -> Vec<u8> {
    let len = (2 + body.len()) as u16; // kind + body, excludes the length field itself
    let mut out = Vec::with_capacity(2 + len as usize);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// LLVM/microsoft-pdb `hashStringV1` — used by the named-stream map and GSI.
pub fn hash_string_v1(s: &[u8]) -> u32 {
    let mut result: u32 = 0;
    let n_longs = s.len() / 4;
    for i in 0..n_longs {
        let off = i * 4;
        let v = u32::from_le_bytes([s[off], s[off + 1], s[off + 2], s[off + 3]]);
        result ^= v;
    }
    let mut rem = &s[n_longs * 4..];
    if rem.len() >= 2 {
        let v = u16::from_le_bytes([rem[0], rem[1]]) as u32;
        result ^= v;
        rem = &rem[2..];
    }
    if rem.len() == 1 {
        result ^= rem[0] as u32;
    }
    result |= 0x2020_2020;
    result ^= result >> 11;
    result ^= result << 16;
    result
}

// CodeView type-record record-bytes hash (for TPI hash stream), V8 variant: a
// 32-bit CRC-like over the record bytes. LLVM uses `hashBufferV8` = a SipHash-ish?
// Actually it is `CRC32`-style: see TpiHashing.cpp -> hashBufferV8 uses
// `xxHash`? We implement the documented one in M2.
