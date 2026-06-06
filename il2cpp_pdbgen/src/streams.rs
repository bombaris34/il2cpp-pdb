use crate::cv::*;
use crate::gsi;
use crate::msf;
use crate::tpi::{self, TypeRec};

pub struct Proc {
    pub name: String,
    pub seg: u16,
    pub off: u32,
    pub size: u32,
    pub type_index: u32,
}

pub struct BuildInput {
    pub guid: [u8; 16],
    pub age: u32,
    pub procs: Vec<Proc>,
    pub types: Vec<TypeRec>,
    pub section_headers: Vec<u8>,
}

// Fixed stream indices.
const STREAM_OLD_DIR: usize = 0;
const STREAM_PDB: usize = 1;
const STREAM_TPI: usize = 2;
const STREAM_DBI: usize = 3;
const STREAM_IPI: usize = 4;
const STREAM_NAMES: usize = 5;
const STREAM_MODULE: usize = 6;
const STREAM_TPI_HASH: usize = 7;
const STREAM_GLOBALS: usize = 8;
const STREAM_PUBLICS: usize = 9;
const STREAM_SYMRECORD: usize = 10;
const STREAM_SECHDR: usize = 11;

const S_END: u16 = 0x0006;
const S_GPROC32: u16 = 0x1110;

pub fn build_pdb(input: BuildInput) -> Vec<u8> {
    let module = build_module_stream(&input.procs);
    let sym_byte_size = module.sym_byte_size;

    let mut streams: Vec<Vec<u8>> = vec![Vec::new(); 12];
    let tpi = tpi::build_tpi(&input.types, STREAM_TPI_HASH as u16);
    let gsi = gsi::build(&input.procs, &module.proc_offsets);

    streams[STREAM_OLD_DIR] = Vec::new();
    streams[STREAM_PDB] = build_pdb_info(&input.guid, input.age);
    streams[STREAM_TPI] = tpi.tpi;
    streams[STREAM_IPI] = empty_type_stream();
    streams[STREAM_NAMES] = build_names_stream();
    streams[STREAM_MODULE] = module.bytes;
    streams[STREAM_DBI] = build_dbi(
        STREAM_MODULE as u16,
        sym_byte_size,
        STREAM_GLOBALS as u16,
        STREAM_PUBLICS as u16,
        STREAM_SYMRECORD as u16,
        STREAM_SECHDR as u16,
    );
    streams[STREAM_TPI_HASH] = tpi.hash;
    streams[STREAM_GLOBALS] = gsi.globals;
    streams[STREAM_PUBLICS] = gsi.publics;
    streams[STREAM_SYMRECORD] = gsi.symrecord;
    streams[STREAM_SECHDR] = input.section_headers;

    msf::build(&streams)
}

// ---- PDB info stream (stream 1) ----
fn build_pdb_info(guid: &[u8; 16], age: u32) -> Vec<u8> {
    let mut w = W::new();
    w.u32(20000404); // Version = VC70
    w.u32(0); // Signature (timestamp)
    w.u32(age);
    w.bytes(guid);

    // Named stream map: maps "/names" -> STREAM_NAMES.
    let entries: &[(&str, u32)] = &[("/names", STREAM_NAMES as u32)];
    let (strbuf, table) = build_named_map(entries);
    w.u32(strbuf.len() as u32);
    w.bytes(&strbuf);
    w.bytes(&table);

    // Feature codes.
    w.u32(20140508); // VC140 -> signals IPI present
    w.buf
}

/// Serialize the named-stream-map hash table (LLVM `HashTable<u32>`).
fn build_named_map(entries: &[(&str, u32)]) -> (Vec<u8>, Vec<u8>) {
    // String buffer: names laid out consecutively; key = offset of the name.
    let mut strbuf = Vec::new();
    let mut offsets = Vec::new();
    for (name, _) in entries {
        offsets.push(strbuf.len() as u32);
        strbuf.extend_from_slice(name.as_bytes());
        strbuf.push(0);
    }
    let size = entries.len();
    let capacity = (size * 2).max(1);
    let mut buckets: Vec<Option<(u32, u32)>> = vec![None; capacity];
    for (i, (name, val)) in entries.iter().enumerate() {
        let mut idx = (hash_string_v1(name.as_bytes()) as usize) % capacity;
        while buckets[idx].is_some() {
            idx = (idx + 1) % capacity;
        }
        buckets[idx] = Some((offsets[i], *val));
    }

    let mut t = W::new();
    t.u32(size as u32);
    t.u32(capacity as u32);
    // Present bitvector.
    let words = (capacity + 31) / 32;
    t.u32(words as u32);
    for wi in 0..words {
        let mut word = 0u32;
        for bit in 0..32 {
            let b = wi * 32 + bit;
            if b < capacity && buckets[b].is_some() {
                word |= 1 << bit;
            }
        }
        t.u32(word);
    }
    // Deleted bitvector (empty).
    t.u32(0);
    // Entries in bucket order.
    for b in &buckets {
        if let Some((k, v)) = b {
            t.u32(*k);
            t.u32(*v);
        }
    }
    (strbuf, t.buf)
}

// ---- empty TPI/IPI header (stream 2 / 4) ----
fn empty_type_stream() -> Vec<u8> {
    let mut w = W::new();
    w.u32(20040203); // Version V80
    w.u32(56); // HeaderSize
    w.u32(0x1000); // TypeIndexBegin
    w.u32(0x1000); // TypeIndexEnd (== begin => empty)
    w.u32(0); // TypeRecordBytes
    w.u16(0xFFFF); // HashStreamIndex
    w.u16(0xFFFF); // HashAuxStreamIndex
    w.u32(4); // HashKeySize
    w.u32(0x3FFFF); // NumHashBuckets
    w.u32(0); // HashValueBufferOffset
    w.u32(0); // HashValueBufferLength
    w.u32(0); // IndexOffsetBufferOffset
    w.u32(0); // IndexOffsetBufferLength
    w.u32(0); // HashAdjBufferOffset
    w.u32(0); // HashAdjBufferLength
    w.buf
}

// ---- /names string table (stream 5), minimal empty ----
fn build_names_stream() -> Vec<u8> {
    let mut w = W::new();
    w.u32(0xEFFEEFFE); // signature
    w.u32(1); // hash version
    w.u32(1); // byte size of string buffer
    w.u8(0); // buffer = single NUL
    w.u32(1); // hash table size (buckets)
    w.u32(0); // bucket[0] = 0 (empty)
    w.u32(0); // name count
    w.buf
}

// ---- module symbol stream (stream 6) ----
struct ModuleStream {
    bytes: Vec<u8>,
    sym_byte_size: u32,
    proc_offsets: Vec<u32>, // module-stream byte offset of each proc's S_GPROC32
}

fn build_module_stream(procs: &[Proc]) -> ModuleStream {
    // Symbol substream: signature + records.
    let mut syms = W::new();
    syms.u32(4); // CV signature C13

    // Build records, tracking byte offsets so S_GPROC32.PtrEnd can point at S_END.
    let mut proc_offsets = Vec::with_capacity(procs.len());
    for p in procs {
        proc_offsets.push(syms.len() as u32); // offset of this S_GPROC32 in the module stream
        // S_GPROC32 body.
        let mut b = W::new();
        b.u32(0); // PtrParent
        b.u32(0); // PtrEnd (patched after we know S_END offset)
        b.u32(0); // PtrNext
        b.u32(p.size); // CodeSize
        b.u32(0); // DbgStart
        b.u32(0); // DbgEnd
        b.u32(p.type_index); // FunctionType
        b.u32(p.off); // CodeOffset
        b.u16(p.seg); // Segment
        b.u8(0); // Flags
        b.cstr(&p.name);
        pad_sym(&mut b.buf); // pad body so total record is 4-byte aligned, length covers it
        let mut rec = frame(S_GPROC32, &b.buf);

        // The S_END record will be written right after this proc record.
        let proc_start = syms.len();
        let end_offset = proc_start + rec.len(); // byte offset of S_END within the stream
        // Patch PtrEnd field. Record layout: [u16 len][u16 kind][u32 PtrParent][u32 PtrEnd]...
        let ptr_end_field = 2 + 2 + 4;
        rec[ptr_end_field..ptr_end_field + 4].copy_from_slice(&(end_offset as u32).to_le_bytes());
        syms.bytes(&rec);

        let endrec = frame(S_END, &[]);
        syms.bytes(&endrec);
    }

    let sym_byte_size = syms.len() as u32; // sig + records (excludes global-refs trailer)
    // Module stream = symbols + C11(0) + C13(0) + global-refs size word(0).
    let mut w = W::new();
    w.bytes(&syms.buf);
    w.u32(0); // global refs byte size
    ModuleStream { bytes: w.buf, sym_byte_size, proc_offsets }
}

// ---- DBI stream (stream 3) ----
fn build_dbi(
    module_sym_stream: u16,
    sym_byte_size: u32,
    global_stream: u16,
    public_stream: u16,
    symrecord_stream: u16,
    sechdr_stream: u16,
) -> Vec<u8> {
    // Substreams first, so we know their sizes.
    let modinfo = dbi_modinfo(module_sym_stream, sym_byte_size);
    let seccontrib = dbi_section_contrib();
    let secmap = dbi_section_map();
    let srcinfo = dbi_source_info();
    let typeserver: Vec<u8> = Vec::new();
    let ec = build_names_stream(); // EC substream is an (empty) string table
    let dbg_header = dbi_optional_dbg_header(sechdr_stream);

    let mut w = W::new();
    w.i32(-1); // VersionSignature
    w.u32(19990903); // VersionHeader V70
    w.u32(1); // Age
    w.u16(global_stream); // GlobalStreamIndex
    w.u16(36363); // BuildNumber (new-format bit set)
    w.u16(public_stream); // PublicStreamIndex
    w.u16(0); // PdbDllVersion
    w.u16(symrecord_stream); // SymRecordStreamIndex
    w.u16(0); // PdbDllRbld
    w.i32(modinfo.len() as i32);
    w.i32(seccontrib.len() as i32);
    w.i32(secmap.len() as i32);
    w.i32(srcinfo.len() as i32);
    w.i32(typeserver.len() as i32);
    w.u32(0); // MFCTypeServerIndex
    w.i32(dbg_header.len() as i32);
    w.i32(ec.len() as i32);
    w.u16(0); // Flags
    w.u16(0x8664); // MachineType AMD64
    w.u32(0); // Padding

    w.bytes(&modinfo);
    w.bytes(&seccontrib);
    w.bytes(&secmap);
    w.bytes(&srcinfo);
    w.bytes(&typeserver);
    w.bytes(&ec);
    w.bytes(&dbg_header);
    w.buf
}

fn dbi_modinfo(module_sym_stream: u16, sym_byte_size: u32) -> Vec<u8> {
    let mut w = W::new();
    w.u32(0); // Unused1
    // SectionContribEntry (28 bytes), zeroed.
    for _ in 0..28 {
        w.u8(0);
    }
    w.u16(0); // Flags
    w.u16(module_sym_stream); // ModuleSymStream
    w.u32(sym_byte_size); // SymByteSize
    w.u32(0); // C11ByteSize
    w.u32(0); // C13ByteSize
    w.u16(0); // SourceFileCount
    w.u16(0); // Padding
    w.u32(0); // Unused2
    w.u32(0); // SourceFileNameIndex
    w.u32(0); // PdbFilePathNameIndex
    w.cstr("il2cpp"); // ModuleName
    w.cstr("il2cpp"); // ObjFileName
    while w.len() % 4 != 0 {
        w.u8(0);
    }
    w.buf
}

fn dbi_section_contrib() -> Vec<u8> {
    Vec::new() // empty (matches yaml2pdb reference)
}

fn dbi_section_map() -> Vec<u8> {
    Vec::new() // empty (matches yaml2pdb reference)
}

fn dbi_source_info() -> Vec<u8> {
    let mut w = W::new();
    w.u16(1); // NumModules
    w.u16(0); // NumSourceFiles
    w.u16(0); // ModIndices[0]
    w.u16(0); // ModFileCounts[0]
    // no file name offsets, empty names buffer
    while w.len() % 4 != 0 {
        w.u8(0);
    }
    w.buf
}

fn dbi_optional_dbg_header(sechdr_stream: u16) -> Vec<u8> {
    let mut w = W::new();
    // 11 u16 stream indices; index 5 = Section Header Data.
    for i in 0..11 {
        if i == 5 {
            w.u16(sechdr_stream);
        } else {
            w.u16(0xFFFF);
        }
    }
    w.buf
}
