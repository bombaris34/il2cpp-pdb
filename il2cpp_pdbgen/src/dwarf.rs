use std::collections::{HashMap, HashSet};

use crate::tpi::TypeRec;

pub struct Function {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub type_index: u32,
}

const MODIFIER: u16 = 0x1001;
const POINTER: u16 = 0x1002;
const PROCEDURE: u16 = 0x1008;
const ARGLIST: u16 = 0x1201;
const FIELDLIST: u16 = 0x1203;
const INDEX: u16 = 0x1404;
const ARRAY: u16 = 0x1503;
const STRUCTURE: u16 = 0x1505;
const UNION: u16 = 0x1506;
const MEMBER: u16 = 0x150d;

#[derive(Clone)]
struct Member { name: String, ty: u32, offset: u64 }
#[derive(Clone)]
enum Record {
    Modifier(u32, u16),
    Pointer(u32, u8),
    Procedure(u32, u32, u16),
    Args(Vec<u32>),
    Fields(Vec<Member>, Option<u32>),
    Array(u32, u64),
    Aggregate { union: bool, name: String, unique: String, forward: bool, fields: u32, size: u64 },
}

struct Reader<'a> { data: &'a [u8], pos: usize }
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.pos.checked_add(n).ok_or("type record overflow")?;
        let result = self.data.get(self.pos..end).ok_or("truncated type record")?;
        self.pos = end;
        Ok(result)
    }
    fn u8(&mut self) -> Result<u8, String> { Ok(self.take(1)?[0]) }
    fn u16(&mut self) -> Result<u16, String> { let b = self.take(2)?; Ok(u16::from_le_bytes([b[0], b[1]])) }
    fn u32(&mut self) -> Result<u32, String> { let b = self.take(4)?; Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]])) }
    fn u64(&mut self) -> Result<u64, String> { let b = self.take(8)?; Ok(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])) }
    fn numeric(&mut self) -> Result<u64, String> {
        match self.u16()? {
            n @ 0..=0x7fff => Ok(n as u64),
            0x8002 => Ok(self.u16()? as u64),
            0x8004 => Ok(self.u32()? as u64),
            0x800a => self.u64(),
            n => Err(format!("unsupported CodeView numeric leaf {n:#x}")),
        }
    }
    fn string(&mut self) -> Result<String, String> {
        let rest = &self.data[self.pos..];
        let len = rest.iter().position(|&b| b == 0).ok_or("unterminated CodeView string")?;
        let s = String::from_utf8_lossy(&rest[..len]).into_owned();
        self.pos += len + 1;
        Ok(s)
    }
}

fn parse_record(rec: &TypeRec) -> Result<Record, String> {
    let mut r = Reader { data: rec.bytes.get(4..).ok_or("truncated CodeView record")?, pos: 0 };
    Ok(match rec.kind {
        MODIFIER => Record::Modifier(r.u32()?, r.u16()?),
        POINTER => { let ty = r.u32()?; let attr = r.u32()?; Record::Pointer(ty, ((attr >> 13) & 0x3f) as u8) }
        PROCEDURE => { let ret = r.u32()?; r.u8()?; r.u8()?; let count = r.u16()?; let args = r.u32()?; Record::Procedure(ret, args, count) }
        ARGLIST => { let n = r.u32()? as usize; if n > (r.data.len() - r.pos) / 4 { return Err("truncated argument list".into()); } let mut args = Vec::with_capacity(n); for _ in 0..n { args.push(r.u32()?); } Record::Args(args) }
        FIELDLIST => {
            let mut members = Vec::new(); let mut next = None;
            while r.pos < r.data.len() {
                if r.data[r.pos] >= 0xf0 { r.pos += 1; continue; }
                match r.u16()? {
                    MEMBER => { r.u16()?; let ty = r.u32()?; let offset = r.numeric()?; let name = r.string()?; members.push(Member { name, ty, offset }); }
                    INDEX => { r.u16()?; next = Some(r.u32()?); break; }
                    n => return Err(format!("unsupported CodeView field leaf {n:#x}")),
                }
            }
            Record::Fields(members, next)
        }
        ARRAY => { let elem = r.u32()?; r.u32()?; Record::Array(elem, r.numeric()?) }
        STRUCTURE | UNION => {
            r.u16()?; let props = r.u16()?; let fields = r.u32()?;
            if rec.kind == STRUCTURE { r.u32()?; r.u32()?; }
            let size = r.numeric()?; let name = r.string()?;
            let unique = if props & 0x200 != 0 { r.string()? } else { name.clone() };
            Record::Aggregate { union: rec.kind == UNION, name, unique, forward: props & 0x80 != 0, fields, size }
        }
        n => return Err(format!("unsupported CodeView type leaf {n:#x}")),
    })
}

fn primitive(i: u32) -> Option<(&'static str, u8, u8)> {
    Some(match i {
        0x03 => ("void", 0, 0), 0x30 => ("bool", 1, 2),
        0x70 => ("char", 1, 6), 0x68 => ("int8_t", 1, 5), 0x69 => ("uint8_t", 1, 7),
        0x72 => ("int16_t", 2, 5), 0x73 => ("uint16_t", 2, 7),
        0x74 => ("int32_t", 4, 5), 0x75 => ("uint32_t", 4, 7),
        0x76 => ("int64_t", 8, 5), 0x77 | 0x23 => ("uint64_t", 8, 7),
        0x40 => ("float", 4, 4), 0x41 => ("double", 8, 4),
        _ => return None,
    })
}
fn record(records: &[Record], ti: u32) -> Result<&Record, String> {
    let index = ti.checked_sub(0x1000).ok_or_else(|| format!("invalid type index {ti:#x}"))? as usize;
    records.get(index).ok_or_else(|| format!("missing type index {ti:#x}"))
}
fn args(records: &[Record], ti: u32, count: u16) -> Result<&[u32], String> {
    match record(records, ti)? {
        Record::Args(a) if a.len() == count as usize => Ok(a),
        _ => Err(format!("invalid argument list {ti:#x}")),
    }
}
fn members(records: &[Record], ti: u32) -> Result<Vec<Member>, String> {
    let mut result = Vec::new(); let mut current = ti; let mut seen = HashSet::new();
    while current != 0 {
        if !seen.insert(current) { return Err("cyclic field list".into()); }
        match record(records, current)? {
            Record::Fields(fields, next) => { result.extend(fields.iter().cloned()); current = next.unwrap_or(0); }
            _ => return Err(format!("invalid field list {current:#x}")),
        }
    }
    Ok(result)
}
fn type_size(records: &[Record], ti: u32, definitions: &HashMap<(bool, String), u32>, seen: &mut HashSet<u32>) -> Result<Option<u64>, String> {
    if let Some((_, size, _)) = primitive(ti) { return Ok(Some(size as u64)); }
    if !seen.insert(ti) { return Ok(None); }
    let size = match record(records, ti)? {
        Record::Pointer(_, size) => Some(*size as u64),
        Record::Modifier(ty, _) => type_size(records, *ty, definitions, seen)?,
        Record::Array(_, size) => Some(*size),
        Record::Aggregate { union, unique, forward, size, .. } => {
            if *forward { match definitions.get(&(*union, unique.clone())) { Some(&def) => type_size(records, def, definitions, seen)?, None => None } } else { Some(*size) }
        }
        _ => None,
    };
    seen.remove(&ti); Ok(size)
}

fn uleb(out: &mut Vec<u8>, mut n: u64) {
    loop { let mut b = (n & 0x7f) as u8; n >>= 7; if n != 0 { b |= 0x80; } out.push(b); if n == 0 { break; } }
}
fn abbrev(out: &mut Vec<u8>, code: u64, tag: u64, children: bool, attrs: &[(u64, u64)]) {
    uleb(out, code); uleb(out, tag); out.push(children as u8);
    for &(name, form) in attrs { uleb(out, name); uleb(out, form); }
    out.extend_from_slice(&[0, 0]);
}
fn cstring(out: &mut Vec<u8>, s: &str) -> Result<(), String> {
    if s.as_bytes().contains(&0) { return Err("NUL in DWARF name".into()); }
    out.extend_from_slice(s.as_bytes()); out.push(0); Ok(())
}
struct Writer { info: Vec<u8>, offsets: HashMap<u32, u32>, fixups: Vec<(usize, u32)> }
impl Writer {
    fn die(&mut self, code: u64) { uleb(&mut self.info, code); }
    fn reference(&mut self, ti: u32) { self.fixups.push((self.info.len(), ti)); self.info.extend_from_slice(&[0; 4]); }
    fn offset(&mut self, ti: u32) -> Result<(), String> {
        let off = u32::try_from(self.info.len()).map_err(|_| "DWARF unit exceeds 4 GiB")?;
        self.offsets.insert(ti, off); Ok(())
    }
    fn name(&mut self, name: &str) -> Result<(), String> { cstring(&mut self.info, name) }
    fn number(&mut self, n: u64) { uleb(&mut self.info, n); }
    fn param(&mut self, ty: u32) {
        if ty == 0 { self.die(18); } else { self.die(10); self.reference(ty); }
    }
}

pub fn generate(types: &[TypeRec], functions: &[Function]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let records: Vec<Record> = types.iter().map(parse_record).collect::<Result<_, _>>()?;
    let mut definitions = HashMap::new();
    for (i, rec) in records.iter().enumerate() {
        if let Record::Aggregate { union, unique, forward: false, .. } = rec {
            definitions.insert((*union, unique.clone()), 0x1000 + i as u32);
        }
    }
    // DWARF 4, 64-bit target addresses, 32-bit unit-relative DIE references.
    // Inline strings avoid a separate string table and keep all references relocatable.
    let mut ab = Vec::new();
    const STR: u64 = 0x08; const UDATA: u64 = 0x0f; const REF: u64 = 0x13;
    abbrev(&mut ab, 1, 0x11, true, &[(0x25, STR), (0x13, 0x05), (0x03, STR), (0x11, 0x01), (0x12, 0x07)]); // compile_unit
    abbrev(&mut ab, 2, 0x24, false, &[(0x03, STR), (0x0b, UDATA), (0x3e, 0x0b)]); // base_type
    abbrev(&mut ab, 3, 0x3b, false, &[(0x03, STR)]); // unspecified_type (void)
    abbrev(&mut ab, 4, 0x0f, false, &[(0x49, REF), (0x0b, UDATA)]);
    abbrev(&mut ab, 5, 0x13, true, &[(0x03, STR), (0x0b, UDATA)]);
    abbrev(&mut ab, 6, 0x17, true, &[(0x03, STR), (0x0b, UDATA)]);
    abbrev(&mut ab, 7, 0x13, false, &[(0x03, STR), (0x3c, 0x19)]);
    abbrev(&mut ab, 8, 0x17, false, &[(0x03, STR), (0x3c, 0x19)]);
    abbrev(&mut ab, 9, 0x0d, false, &[(0x03, STR), (0x49, REF), (0x38, UDATA)]);
    abbrev(&mut ab, 10, 0x05, false, &[(0x49, REF)]);
    abbrev(&mut ab, 11, 0x15, true, &[(0x49, REF)]);
    abbrev(&mut ab, 12, 0x01, true, &[(0x49, REF), (0x0b, UDATA)]);
    abbrev(&mut ab, 13, 0x21, false, &[(0x37, UDATA)]);
    abbrev(&mut ab, 14, 0x2e, true, &[(0x03, STR), (0x11, 0x01), (0x12, 0x07), (0x3f, 0x19), (0x49, REF)]);
    abbrev(&mut ab, 15, 0x2e, true, &[(0x03, STR), (0x11, 0x01), (0x12, 0x07), (0x3f, 0x19)]);
    abbrev(&mut ab, 16, 0x26, false, &[(0x49, REF)]); // const_type
    abbrev(&mut ab, 17, 0x35, false, &[(0x49, REF)]); // volatile_type
    abbrev(&mut ab, 18, 0x18, false, &[]); // unspecified_parameters (variadic)
    ab.push(0);
    let mut w = Writer { info: vec![0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 8], offsets: HashMap::new(), fixups: Vec::new() };
    w.die(1); w.name("il2cpp-pdb")?; w.info.extend_from_slice(&0x000cu16.to_le_bytes()); w.name("il2cpp")?;
    let low = functions.iter().map(|f| f.address).min().unwrap_or(0);
    let high = functions.iter().try_fold(low, |end, f| {
        f.address.checked_add(f.size).map(|n| end.max(n)).ok_or("function address range overflow")
    })?;
    w.info.extend_from_slice(&low.to_le_bytes());
    w.info.extend_from_slice(&(high - low).to_le_bytes());
    for ti in [0x03, 0x30, 0x70, 0x68, 0x69, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x23, 0x40, 0x41] {
        let (name, size, encoding) = primitive(ti).unwrap(); w.offset(ti)?;
        if ti == 3 { w.die(3); w.name(name)?; }
        else { w.die(2); w.name(name)?; w.number(size as u64); w.info.push(encoding); }
    }
    for (i, rec) in records.iter().enumerate() {
        let ti = 0x1000u32.checked_add(u32::try_from(i).map_err(|_| "too many types")?).ok_or("too many types")?;
        match rec {
            Record::Args(_) | Record::Fields(_, _) => continue,
            Record::Aggregate { union, unique, forward: true, .. } if definitions.contains_key(&(*union, unique.clone())) => continue,
            _ => {}
        }
        w.offset(ti)?;
        match rec {
            Record::Pointer(ty, size) => { w.die(4); w.reference(*ty); w.number(*size as u64); }
            Record::Modifier(ty, flags) => {
                if flags & !3 != 0 || flags & 3 == 0 {
                    return Err(format!("unsupported CodeView modifier flags {flags:#x}"));
                }
                if flags & 3 == 3 {
                    w.die(16);
                    let next = u32::try_from(w.info.len() + 4).map_err(|_| "DWARF unit exceeds 4 GiB")?;
                    w.info.extend_from_slice(&next.to_le_bytes());
                    w.die(17);
                } else {
                    w.die(if flags & 1 != 0 { 16 } else { 17 });
                }
                w.reference(*ty);
            }
            Record::Procedure(ret, list, count) => { w.die(11); w.reference(*ret); for &p in args(&records, *list, *count)? { w.param(p); } w.info.push(0); }
            Record::Array(elem, size) => {
                w.die(12); w.reference(*elem); w.number(*size);
                if let Some(element_size) = type_size(&records, *elem, &definitions, &mut HashSet::new())? {
                    if element_size != 0 && size % element_size == 0 { w.die(13); w.number(size / element_size); }
                }
                w.info.push(0);
            }
            Record::Aggregate { union, name, forward, fields, size, .. } => {
                w.die(if *forward { if *union { 8 } else { 7 } } else if *union { 6 } else { 5 }); w.name(name)?;
                if !forward { w.number(*size); for m in members(&records, *fields)? { w.die(9); w.name(&m.name)?; w.reference(m.ty); w.number(m.offset); } w.info.push(0); }
            }
            _ => unreachable!(),
        }
    }
    for (i, rec) in records.iter().enumerate() {
        if let Record::Aggregate { union, unique, forward: true, .. } = rec {
            if let Some(&def) = definitions.get(&(*union, unique.clone())) {
                let offset = *w.offsets.get(&def).ok_or("missing aggregate definition")?;
                w.offsets.insert(0x1000 + i as u32, offset);
            }
        }
    }
    for function in functions {
        let signature = if function.type_index == 0 { None } else {
            match record(&records, function.type_index)? {
                Record::Procedure(ret, list, count) => Some((*ret, args(&records, *list, *count)?)),
                _ => return Err(format!("function {} has non-procedure type", function.name)),
            }
        };
        function.address.checked_add(function.size).ok_or("function address range overflow")?;
        w.die(if signature.is_some() { 14 } else { 15 }); w.name(&function.name)?;
        w.info.extend_from_slice(&function.address.to_le_bytes()); w.info.extend_from_slice(&function.size.to_le_bytes());
        if let Some((ret, params)) = signature { w.reference(ret); for &p in params { w.param(p); } }
        w.info.push(0);
    }
    w.info.push(0);
    for (pos, ti) in w.fixups {
        let offset = w.offsets.get(&ti).ok_or_else(|| format!("missing DWARF type for CodeView index {ti:#x}"))?;
        w.info[pos..pos + 4].copy_from_slice(&offset.to_le_bytes());
    }
    let length = u32::try_from(w.info.len() - 4).map_err(|_| "DWARF unit exceeds 4 GiB")?;
    w.info[..4].copy_from_slice(&length.to_le_bytes());
    Ok(vec![("__debug_abbrev".into(), ab), ("__debug_info".into(), w.info)])
}
