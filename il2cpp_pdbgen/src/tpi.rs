// TPI stream + TPI hash stream builder, and CodeView type-record encoders.
use crate::cv::*;

// Builtin (primitive) type indices.
pub const T_VOID: u32 = 0x0003;
pub const T_BOOL08: u32 = 0x0030;
pub const T_INT4: u32 = 0x0074;
#[allow(dead_code)]
pub const T_UINT4: u32 = 0x0075;
#[allow(dead_code)]
pub const T_INT8: u32 = 0x0076;
#[allow(dead_code)]
pub const T_UINT8: u32 = 0x0077;
#[allow(dead_code)]
pub const T_UQUAD: u32 = 0x0023;

// Leaf kinds.
const LF_POINTER: u16 = 0x1002;
const LF_PROCEDURE: u16 = 0x1008;
const LF_ARGLIST: u16 = 0x1201;
const LF_FIELDLIST: u16 = 0x1203;
const LF_ARRAY: u16 = 0x1503;
const LF_STRUCTURE: u16 = 0x1505;
const LF_UNION: u16 = 0x1506;
const LF_MEMBER: u16 = 0x150D;

// Array index type: unsigned __int64.
pub const T_UQUAD_IDX: u32 = 0x0023;

// Class property flags.
const CV_PROP_FWDREF: u16 = 0x80;
const CV_PROP_HAS_UNIQUE_NAME: u16 = 0x200;

/// Numeric leaf: inline if < 0x8000, else LF_USHORT/LF_ULONG/LF_UQUADWORD.
fn numeric(w: &mut W, v: u64) {
    if v < 0x8000 {
        w.u16(v as u16);
    } else if v <= 0xFFFF {
        w.u16(0x8002); // LF_USHORT
        w.u16(v as u16);
    } else if v <= 0xFFFF_FFFF {
        w.u16(0x8004); // LF_ULONG
        w.u32(v as u32);
    } else {
        w.u16(0x800A); // LF_UQUADWORD
        w.buf.extend_from_slice(&v.to_le_bytes());
    }
}

/// A finished type record (framed: len+kind+body+pad) plus its name for hashing.
pub struct TypeRec {
    pub bytes: Vec<u8>,
    pub kind: u16,
    pub name: Option<String>,
    pub fwdref: bool,
}

fn finish(kind: u16, mut body: Vec<u8>, name: Option<String>, fwdref: bool) -> TypeRec {
    pad_type(&mut body);
    TypeRec { bytes: frame(kind, &body), kind, name, fwdref }
}

pub fn ptr64(referent: u32) -> TypeRec {
    let mut b = W::new();
    b.u32(referent);
    b.u32(0x1000C); // 64-bit normal pointer, size 8
    finish(LF_POINTER, b.buf, None, false)
}

pub fn arglist(args: &[u32]) -> TypeRec {
    let mut b = W::new();
    b.u32(args.len() as u32);
    for &a in args {
        b.u32(a);
    }
    finish(LF_ARGLIST, b.buf, None, false)
}

pub fn procedure(ret: u32, arglist_ti: u32, nparams: u16) -> TypeRec {
    let mut b = W::new();
    b.u32(ret);
    b.u8(0); // calling convention: near C
    b.u8(0); // function attributes
    b.u16(nparams);
    b.u32(arglist_ti);
    finish(LF_PROCEDURE, b.buf, None, false)
}

pub struct Member {
    pub name: String,
    pub ty: u32,
    pub offset: u64,
}

const LF_INDEX: u16 = 0x1404;

pub fn fieldlist(members: &[Member]) -> TypeRec {
    fieldlist_cont(members, None)
}

/// Field list, optionally ending in an LF_INDEX continuation to `cont` (next fragment).
pub fn fieldlist_cont(members: &[Member], cont: Option<u32>) -> TypeRec {
    let mut b = W::new();
    for m in members {
        b.u16(LF_MEMBER);
        b.u16(3); // access = public
        b.u32(m.ty);
        numeric(&mut b, m.offset);
        b.cstr(&m.name);
        let rem = b.buf.len() % 4;
        if rem != 0 {
            for i in (1..=(4 - rem)).rev() {
                b.u8(0xF0 | i as u8);
            }
        }
    }
    if let Some(c) = cont {
        b.u16(LF_INDEX);
        b.u16(0); // padding
        b.u32(c);
    }
    finish(LF_FIELDLIST, b.buf, None, false)
}

pub fn struct_fwdref(name: &str, unique: &str) -> TypeRec {
    let mut b = W::new();
    b.u16(0); // member count
    b.u16(CV_PROP_FWDREF | CV_PROP_HAS_UNIQUE_NAME);
    b.u32(0); // field list
    b.u32(0); // derived
    b.u32(0); // vshape
    numeric(&mut b, 0); // size
    b.cstr(name);
    b.cstr(unique);
    finish(LF_STRUCTURE, b.buf, Some(name.to_string()), true)
}

pub fn struct_def(name: &str, unique: &str, count: u16, fieldlist_ti: u32, size: u64) -> TypeRec {
    let mut b = W::new();
    b.u16(count);
    b.u16(CV_PROP_HAS_UNIQUE_NAME);
    b.u32(fieldlist_ti);
    b.u32(0); // derived
    b.u32(0); // vshape
    numeric(&mut b, size);
    b.cstr(name);
    b.cstr(unique);
    finish(LF_STRUCTURE, b.buf, Some(name.to_string()), false)
}

pub fn union_fwdref(name: &str, unique: &str) -> TypeRec {
    let mut b = W::new();
    b.u16(0); // count
    b.u16(CV_PROP_FWDREF | CV_PROP_HAS_UNIQUE_NAME);
    b.u32(0); // field list
    numeric(&mut b, 0); // size
    b.cstr(name);
    b.cstr(unique);
    finish(LF_UNION, b.buf, Some(name.to_string()), true)
}

pub fn union_def(name: &str, unique: &str, count: u16, fieldlist_ti: u32, size: u64) -> TypeRec {
    let mut b = W::new();
    b.u16(count);
    b.u16(CV_PROP_HAS_UNIQUE_NAME);
    b.u32(fieldlist_ti);
    numeric(&mut b, size);
    b.cstr(name);
    b.cstr(unique);
    finish(LF_UNION, b.buf, Some(name.to_string()), false)
}

pub fn array(elem: u32, size: u64) -> TypeRec {
    let mut b = W::new();
    b.u32(elem);
    b.u32(T_UQUAD_IDX);
    numeric(&mut b, size);
    b.cstr(""); // no name
    finish(LF_ARRAY, b.buf, None, false)
}

/// Hash a type record the way LLVM does (for the TPI hash stream).
fn hash_record(r: &TypeRec, buckets: u32) -> u32 {
    let h = match r.kind {
        LF_STRUCTURE | LF_UNION if !r.fwdref => {
            if let Some(n) = &r.name {
                hash_string_v1(n.as_bytes())
            } else {
                hash_buffer_v8(&r.bytes)
            }
        }
        _ => hash_buffer_v8(&r.bytes),
    };
    h % buckets
}

// Content hash for records without a usable name (fwdrefs, pointers, arrays,
// arglists, procedures, field lists). Consumers don't recompute this — it only
// needs to DISTRIBUTE records across buckets so none overflows. We reuse the
// LLVM string hash over the framed record bytes (skipping the 2-byte length).
fn hash_buffer_v8(data: &[u8]) -> u32 {
    hash_string_v1(&data[2..])
}

pub struct TpiStreams {
    pub tpi: Vec<u8>,
    pub hash: Vec<u8>,
    pub type_index_end: u32,
}

pub fn build_tpi(records: &[TypeRec], hash_stream_index: u16) -> TpiStreams {
    const BUCKETS: u32 = 0x3FFFF;
    let disable_hash = std::env::var("DISABLE_HASH").is_ok();
    let mut recbytes = Vec::new();
    let mut hashvals = W::new();
    let mut indexoff = W::new();
    let mut last_emit: i64 = -1;
    for (i, r) in records.iter().enumerate() {
        let ti = 0x1000 + i as u32;
        // index-offset buffer entry every ~8KB
        if last_emit < 0 || (recbytes.len() as i64 - last_emit) >= 8192 {
            indexoff.u32(ti);
            indexoff.u32(recbytes.len() as u32);
            last_emit = recbytes.len() as i64;
        }
        recbytes.extend_from_slice(&r.bytes);
        hashvals.u32(hash_record(r, BUCKETS));
    }
    let type_index_end = 0x1000 + records.len() as u32;

    // Hash stream = hash values | index offsets | (no adjusters)
    let hv_off = 0u32;
    let hv_len = hashvals.len() as u32;
    let io_off = hv_len;
    let io_len = indexoff.len() as u32;
    let mut hash = Vec::new();
    hash.extend_from_slice(&hashvals.buf);
    hash.extend_from_slice(&indexoff.buf);

    // TPI header (56 bytes).
    let mut h = W::new();
    h.u32(20040203); // V80
    h.u32(56);
    h.u32(0x1000);
    h.u32(type_index_end);
    h.u32(recbytes.len() as u32);
    h.u16(hash_stream_index);
    h.u16(0xFFFF); // aux hash
    h.u32(4); // hash key size
    h.u32(BUCKETS);
    h.u32(hv_off);
    h.u32(hv_len);
    h.u32(io_off);
    h.u32(io_len);
    h.u32(0); // hash adj off
    h.u32(0); // hash adj len
    if disable_hash {
        // Emit header with no hash stream.
        let mut h2 = W::new();
        h2.u32(20040203);
        h2.u32(56);
        h2.u32(0x1000);
        h2.u32(type_index_end);
        h2.u32(recbytes.len() as u32);
        h2.u16(0xFFFF); // hash stream none
        h2.u16(0xFFFF);
        h2.u32(4);
        h2.u32(BUCKETS);
        for _ in 0..6 {
            h2.u32(0);
        }
        let mut tpi2 = h2.buf;
        tpi2.extend_from_slice(&recbytes);
        return TpiStreams { tpi: tpi2, hash: Vec::new(), type_index_end };
    }

    let mut tpi = h.buf;
    tpi.extend_from_slice(&recbytes);

    TpiStreams { tpi, hash, type_index_end }
}
