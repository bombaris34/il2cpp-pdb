// Global (GSI) and Public (PSI) symbol streams + the shared symbol record stream.
// IDA reads function names from the publics and names+prototypes from the globals
// (S_PROCREF -> module S_GPROC32). Module symbols alone are not consumed.
use crate::cv::{frame, hash_string_v1, pad_sym, W};
use crate::streams::Proc;

const S_PUB32: u16 = 0x110E;
const S_PROCREF: u16 = 0x1125;
const IPHR_HASH: u32 = 4096;

pub struct GsiStreams {
    pub symrecord: Vec<u8>,
    pub globals: Vec<u8>,
    pub publics: Vec<u8>,
}

struct Entry {
    off: u32, // offset of the record in the symbol record stream
    name_hash: u32,
    name: Vec<u8>,
}

fn s_pub32(p: &Proc) -> Vec<u8> {
    let mut b = W::new();
    b.u32(0x2); // flags: Function
    b.u32(p.off);
    b.u16(p.seg);
    b.cstr(&p.name);
    pad_sym(&mut b.buf);
    frame(S_PUB32, &b.buf)
}

fn s_procref(p: &Proc, mod_off: u32) -> Vec<u8> {
    let mut b = W::new();
    b.u32(0); // SumName checksum
    b.u32(mod_off); // offset of S_GPROC32 in module stream
    b.u16(1); // module index (1-based)
    b.cstr(&p.name);
    pad_sym(&mut b.buf);
    frame(S_PROCREF, &b.buf)
}

/// Build the GSI hash section (header + hash records + bitmap + bucket offsets).
fn build_hash(entries: &[Entry]) -> Vec<u8> {
    // bucketize
    let mut buckets: Vec<Vec<usize>> = vec![Vec::new(); IPHR_HASH as usize];
    for (i, e) in entries.iter().enumerate() {
        buckets[(e.name_hash % IPHR_HASH) as usize].push(i);
    }
    // sort each bucket: MS/LLVM comparator = shorter name first, then bytewise
    for b in buckets.iter_mut() {
        b.sort_by(|&a, &c| {
            let na = &entries[a].name;
            let nc = &entries[c].name;
            na.len().cmp(&nc.len()).then_with(|| na.cmp(nc)).then(entries[a].off.cmp(&entries[c].off))
        });
    }

    let mut hash_records = W::new();
    let mut bucket_offsets = W::new();
    let mut bitmap = vec![0u32; (IPHR_HASH as usize / 32) + 1];
    let mut rec_index: u32 = 0;
    for (bi, b) in buckets.iter().enumerate() {
        if b.is_empty() {
            continue;
        }
        bitmap[bi / 32] |= 1 << (bi % 32);
        bucket_offsets.u32(rec_index * 12); // in-memory HRFile is 12 bytes
        for &i in b {
            hash_records.u32(entries[i].off + 1); // 1-based offset
            hash_records.u32(1); // CRef
            rec_index += 1;
        }
    }

    let mut bucket_section = W::new();
    for w in &bitmap {
        bucket_section.u32(*w);
    }
    bucket_section.bytes(&bucket_offsets.buf);

    let mut out = W::new();
    out.u32(0xFFFF_FFFF); // VerSignature
    out.u32(0xF12F_091A); // VerHdr (GSIHashHeader)
    out.u32(hash_records.len() as u32); // HrSize
    out.u32(bucket_section.len() as u32); // BucketsSize
    out.bytes(&hash_records.buf);
    out.bytes(&bucket_section.buf);
    out.buf
}

pub fn build(procs: &[Proc], proc_mod_offsets: &[u32]) -> GsiStreams {
    // Symbol record stream: all S_PUB32, then all S_PROCREF. Track offsets.
    let mut sym = W::new();
    let mut pub_entries = Vec::with_capacity(procs.len());
    let mut ref_entries = Vec::with_capacity(procs.len());

    for p in procs {
        let off = sym.len() as u32;
        let rec = s_pub32(p);
        sym.bytes(&rec);
        pub_entries.push(Entry { off, name_hash: hash_string_v1(p.name.as_bytes()), name: p.name.clone().into_bytes() });
    }
    for (i, p) in procs.iter().enumerate() {
        let off = sym.len() as u32;
        let rec = s_procref(p, proc_mod_offsets[i]);
        sym.bytes(&rec);
        ref_entries.push(Entry { off, name_hash: hash_string_v1(p.name.as_bytes()), name: p.name.clone().into_bytes() });
    }

    // Globals stream = GSI hash over the S_PROCREF entries.
    let globals = build_hash(&ref_entries);

    // Publics stream = header + GSI hash over S_PUB32 + address map.
    let pub_hash = build_hash(&pub_entries);
    // address map: offsets of S_PUB32 records sorted by (segment, offset)
    let mut addr_order: Vec<usize> = (0..procs.len()).collect();
    addr_order.sort_by(|&a, &b| {
        (procs[a].seg, procs[a].off).cmp(&(procs[b].seg, procs[b].off))
    });
    let mut addrmap = W::new();
    for &i in &addr_order {
        addrmap.u32(pub_entries[i].off);
    }

    let mut publics = W::new();
    publics.u32(pub_hash.len() as u32); // SymHash size
    publics.u32(addrmap.len() as u32); // AddrMap size
    publics.u32(0); // NumThunks
    publics.u32(0); // SizeOfThunk
    publics.u16(0); // ISectThunkTable
    publics.u16(0); // Padding
    publics.u32(0); // OffThunkTable
    publics.u32(0); // NumSections
    publics.bytes(&pub_hash);
    publics.bytes(&addrmap.buf);

    GsiStreams { symrecord: sym.buf, globals, publics: publics.buf }
}
