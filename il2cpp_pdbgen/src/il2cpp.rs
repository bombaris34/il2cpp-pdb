// Parse il2cpp.h, compute x64 struct layouts, and emit CodeView TPI records.
#![allow(dead_code)]
use crate::tpi::{self, Member, TypeRec};
use std::collections::HashMap;

#[derive(Clone)]
struct Field {
    base: String,
    ptrs: u32,
    dims: Vec<u64>,
    name: String,
}

struct Agg {
    is_union: bool,
    align_override: Option<u32>,
    fields: Vec<Field>,
}

pub struct Types {
    pub records: Vec<TypeRec>,
    pub name_to_complete: HashMap<String, u32>,
    pub name_to_fwd: HashMap<String, u32>,
    pub layouts: HashMap<String, Layout>,
    typedefs: HashMap<String, TDef>,
    ptr_cache: HashMap<u32, u32>,
    proc_cache: HashMap<(u32, Vec<u32>), u32>,
    arglist_cache: HashMap<Vec<u32>, u32>,
}

#[derive(Clone)]
pub struct Layout {
    pub size: u64,
    pub align: u32,
    pub offsets: Vec<u64>,
}

// ---- primitive table: name -> (cv builtin index, size, align) ----
fn primitive(name: &str) -> Option<(u32, u64, u32)> {
    Some(match name {
        "void" => (0x0003, 0, 1),
        "bool" => (0x0030, 1, 1),
        "char" => (0x0070, 1, 1),
        "signed char" | "int8_t" => (0x0068, 1, 1),
        "unsigned char" | "uint8_t" => (0x0069, 1, 1),
        "short" | "short int" | "int16_t" => (0x0072, 2, 2),
        "unsigned short" | "uint16_t" | "wchar_t" => (0x0073, 2, 2),
        "int" | "int32_t" | "long" | "long int" => (0x0074, 4, 4),
        "unsigned int" | "unsigned" | "uint32_t" | "unsigned long" => (0x0075, 4, 4),
        "long long" | "long long int" | "int64_t" => (0x0076, 8, 8),
        "unsigned long long" | "uint64_t" => (0x0077, 8, 8),
        "intptr_t" => (0x0076, 8, 8),
        "uintptr_t" | "size_t" => (0x0077, 8, 8),
        "float" => (0x0040, 4, 4),
        "double" | "long double" => (0x0041, 8, 8),
        _ => return None,
    })
}

// Typedef resolution target.
#[derive(Clone)]
enum TDef {
    Prim(u32, u64, u32),
    VoidPtr, // function-pointer typedefs collapse to void*
}

pub fn parse_and_build(header: &str) -> Types {
    let mut defs: HashMap<String, Agg> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    let mut typedefs: HashMap<String, TDef> = HashMap::new();
    let mut fwd_only: Vec<String> = Vec::new();

    parse(header, &mut defs, &mut order, &mut typedefs, &mut fwd_only);
    eprintln!(
        "parsed: {} aggregates, {} typedefs, {} fwd-only",
        defs.len(),
        typedefs.len(),
        fwd_only.len()
    );

    // ---- layout pass ----
    let mut layouts: HashMap<String, Layout> = HashMap::new();
    // iterative resolution with memo + cycle guard
    let names: Vec<String> = order.clone();
    for n in &names {
        compute_layout(n, &defs, &typedefs, &mut layouts, &mut Vec::new());
    }
    eprintln!("layouts computed: {}", layouts.len());

    // ---- emit ----
    let mut records: Vec<TypeRec> = Vec::new();
    let mut name_to_fwd: HashMap<String, u32> = HashMap::new();
    let mut name_to_complete: HashMap<String, u32> = HashMap::new();

    // fwdrefs for every aggregate name + fwd-only name
    let mut all_names: Vec<(String, bool)> = Vec::new();
    for n in &order {
        all_names.push((n.clone(), defs[n].is_union));
    }
    for n in &fwd_only {
        if !defs.contains_key(n) {
            all_names.push((n.clone(), false));
        }
    }
    for (n, is_union) in &all_names {
        let ti = 0x1000 + records.len() as u32;
        let uniq = unique_name(n);
        records.push(if *is_union {
            tpi::union_fwdref(n, &uniq)
        } else {
            tpi::struct_fwdref(n, &uniq)
        });
        name_to_fwd.insert(n.clone(), ti);
    }

    // topo order of defined aggregates by by-value containment
    let topo = topo_sort(&order, &defs, &typedefs);

    let mut ptr_cache: HashMap<u32, u32> = HashMap::new();
    let mut arr_cache: HashMap<(u32, u64), u32> = HashMap::new();

    for name in &topo {
        let agg = &defs[name];
        let lay = layouts[name].clone();
        // resolve each member's type index
        let mut members: Vec<Member> = Vec::with_capacity(agg.fields.len());
        for (fi, f) in agg.fields.iter().enumerate() {
            let idx = resolve_field_index(
                f,
                &typedefs,
                &defs,
                &name_to_fwd,
                &name_to_complete,
                &mut records,
                &mut ptr_cache,
                &mut arr_cache,
                &layouts,
            );
            members.push(Member {
                name: f.name.clone(),
                ty: idx,
                offset: lay.offsets[fi],
            });
        }
        // build (possibly split) field list
        let fl_idx = build_fieldlist(&members, &mut records);
        let ti = 0x1000 + records.len() as u32;
        let uniq = unique_name(name);
        let rec = if agg.is_union {
            tpi::union_def(name, &uniq, members.len() as u16, fl_idx, lay.size)
        } else {
            tpi::struct_def(name, &uniq, members.len() as u16, fl_idx, lay.size)
        };
        records.push(rec);
        name_to_complete.insert(name.clone(), ti);
    }

    Types {
        records,
        name_to_complete,
        name_to_fwd,
        layouts,
        typedefs,
        ptr_cache,
        proc_cache: HashMap::new(),
        arglist_cache: HashMap::new(),
    }
}

impl Types {
    /// Resolve a signature type reference (base name + pointer depth) to a TPI index.
    pub fn resolve_typeref(&mut self, base: &str, ptrs: u32) -> u32 {
        if ptrs > 0 {
            let referent = if let Some((i, _, _)) = primitive(base) {
                i
            } else if let Some(td) = self.typedefs.get(base).cloned() {
                match td {
                    TDef::Prim(i, _, _) => i,
                    TDef::VoidPtr => intern_ptr(tpi::T_VOID, &mut self.records, &mut self.ptr_cache),
                }
            } else if let Some(&fi) = self.name_to_fwd.get(base) {
                fi
            } else {
                tpi::T_VOID
            };
            let mut idx = intern_ptr(referent, &mut self.records, &mut self.ptr_cache);
            for _ in 1..ptrs {
                idx = intern_ptr(idx, &mut self.records, &mut self.ptr_cache);
            }
            idx
        } else if let Some((i, _, _)) = primitive(base) {
            i
        } else if let Some(td) = self.typedefs.get(base).cloned() {
            match td {
                TDef::Prim(i, _, _) => i,
                TDef::VoidPtr => intern_ptr(tpi::T_VOID, &mut self.records, &mut self.ptr_cache),
            }
        } else if let Some(&ci) = self.name_to_complete.get(base) {
            ci
        } else if let Some(&fi) = self.name_to_fwd.get(base) {
            fi
        } else {
            tpi::T_VOID
        }
    }

    fn proc_type(&mut self, ret: u32, params: &[u32]) -> u32 {
        let key = (ret, params.to_vec());
        if let Some(&i) = self.proc_cache.get(&key) {
            return i;
        }
        let arglist = if let Some(&i) = self.arglist_cache.get(params) {
            i
        } else {
            let ti = 0x1000 + self.records.len() as u32;
            self.records.push(tpi::arglist(params));
            self.arglist_cache.insert(params.to_vec(), ti);
            ti
        };
        let ti = 0x1000 + self.records.len() as u32;
        self.records.push(tpi::procedure(ret, arglist, params.len() as u16));
        self.proc_cache.insert(key, ti);
        ti
    }

    /// Parse an Il2Cpp method signature "<ret> <name> (<params>);" into a proc type.
    pub fn sig_to_proc(&mut self, sig: &str) -> u32 {
        let p = match sig.find('(') {
            Some(p) => p,
            None => return 0,
        };
        let rp = sig.rfind(')').unwrap_or(sig.len());
        let head = &sig[..p];
        let params_str = &sig[p + 1..rp];

        let ret = match parse_field(&format!("{};", head.trim())) {
            Some(f) => self.resolve_typeref(&f.base, f.ptrs),
            None => tpi::T_VOID,
        };
        let mut params = Vec::new();
        let ps = params_str.trim();
        if !ps.is_empty() && ps != "void" {
            for part in ps.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                // function-pointer param -> void*
                if part.contains("(*") {
                    params.push(self.resolve_typeref("void", 1));
                    continue;
                }
                if let Some(f) = parse_field(&format!("{};", part)) {
                    params.push(self.resolve_typeref(&f.base, f.ptrs));
                }
            }
        }
        self.proc_type(ret, &params)
    }
}

fn unique_name(n: &str) -> String {
    format!(".?AU{}@@", n)
}

// ---------- parsing ----------
fn parse(
    header: &str,
    defs: &mut HashMap<String, Agg>,
    order: &mut Vec<String>,
    typedefs: &mut HashMap<String, TDef>,
    fwd_only: &mut Vec<String>,
) {
    let mut cur: Option<(String, Agg)> = None;
    let mut pending: Option<(String, bool, Option<u32>)> = None;

    for raw in header.lines() {
        let t = raw.trim();
        if t.is_empty() || t.starts_with("//") {
            continue;
        }
        if let Some((_, agg)) = cur.as_mut() {
            if t == "};" || t == "}" || t.starts_with('}') {
                let (name, agg) = cur.take().unwrap();
                if !defs.contains_key(&name) {
                    order.push(name.clone());
                }
                defs.insert(name, agg);
                continue;
            }
            if let Some(f) = parse_field(t) {
                agg.fields.push(f);
            }
            continue;
        }
        if pending.is_some() {
            if t.starts_with('{') {
                let (name, is_union, align) = pending.take().unwrap();
                cur = Some((name, Agg { is_union, align_override: align, fields: Vec::new() }));
                continue;
            } else {
                pending = None; // unexpected; drop
            }
        }
        if t.starts_with("typedef") {
            parse_typedef(t, typedefs);
            continue;
        }
        if t.starts_with("struct") || t.starts_with("union") {
            let is_union = t.starts_with("union");
            if t.ends_with(';') && !t.contains('{') {
                // forward decl: "struct NAME;"
                if let Some(name) = t
                    .trim_end_matches(';')
                    .split_whitespace()
                    .last()
                    .map(|s| s.to_string())
                {
                    fwd_only.push(name);
                }
                continue;
            }
            if let Some((name, align, brace)) = parse_open(t) {
                if brace {
                    cur = Some((name, Agg { is_union, align_override: align, fields: Vec::new() }));
                } else {
                    pending = Some((name, is_union, align));
                }
            }
        }
    }
}

fn parse_open(t: &str) -> Option<(String, Option<u32>, bool)> {
    // struct|union [__declspec(align(N))] NAME [{]
    let brace = t.ends_with('{');
    let body = t.trim_end_matches('{').trim();
    let mut rest = body
        .strip_prefix("struct")
        .or_else(|| body.strip_prefix("union"))?
        .trim();
    let mut align = None;
    if let Some(a) = rest.strip_prefix("__declspec(align(") {
        let end = a.find("))")?;
        align = a[..end].parse::<u32>().ok();
        rest = a[end + 2..].trim();
    }
    let name = rest.split_whitespace().next()?.to_string();
    if name.is_empty() {
        return None;
    }
    Some((name, align, brace))
}

fn parse_typedef(t: &str, typedefs: &mut HashMap<String, TDef>) {
    let body = t.trim_start_matches("typedef").trim().trim_end_matches(';');
    // function pointer typedef: contains "(*NAME)"
    if let Some(p) = body.find("(*") {
        let after = &body[p + 2..];
        if let Some(e) = after.find(')') {
            let name = after[..e].trim().to_string();
            if !name.is_empty() {
                typedefs.insert(name, TDef::VoidPtr);
            }
            return;
        }
    }
    // simple typedef: "<type> NAME"
    let toks: Vec<&str> = body.split_whitespace().collect();
    if toks.len() >= 2 {
        let name = toks[toks.len() - 1].to_string();
        let underlying = toks[..toks.len() - 1].join(" ");
        if let Some((i, s, a)) = primitive(&underlying) {
            typedefs.insert(name, TDef::Prim(i, s, a));
        }
    }
}

fn parse_field(t: &str) -> Option<Field> {
    let mut s = t.trim_end_matches(';').trim().to_string();
    if s.is_empty() {
        return None;
    }
    // function pointer field: RET (*name)(...)
    if let Some(p) = s.find("(*") {
        let after = &s[p + 2..];
        if let Some(e) = after.find(')') {
            let name = after[..e].trim().trim_start_matches('*').to_string();
            return Some(Field { base: "void".into(), ptrs: 1, dims: vec![], name });
        }
    }
    // bitfield: drop ": N"
    if let Some(c) = s.find(':') {
        s = s[..c].trim().to_string();
    }
    // array dims
    let mut dims = Vec::new();
    while let Some(open) = s.rfind('[') {
        if let Some(close) = s[open..].find(']') {
            let inner = s[open + 1..open + close].trim();
            let d: u64 = inner.parse().unwrap_or(0);
            dims.insert(0, d);
            s.replace_range(open..open + close + 1, "");
        } else {
            break;
        }
    }
    // strip const / struct / union qualifiers
    let cleaned = s
        .replace("const", " ")
        .replace("volatile", " ");
    let cleaned = cleaned.trim();
    // count pointers
    let ptrs = cleaned.matches('*').count() as u32;
    let no_star = cleaned.replace('*', " ");
    let mut toks: Vec<&str> = no_star.split_whitespace().collect();
    // drop leading struct/union keyword
    if !toks.is_empty() && (toks[0] == "struct" || toks[0] == "union" || toks[0] == "enum") {
        toks.remove(0);
    }
    if toks.len() < 2 {
        return None;
    }
    let name = toks[toks.len() - 1].to_string();
    let base = toks[..toks.len() - 1].join(" ");
    Some(Field { base, ptrs, dims, name })
}

// ---------- layout ----------
fn align_up(v: u64, a: u64) -> u64 {
    if a <= 1 {
        v
    } else {
        (v + a - 1) / a * a
    }
}

fn compute_layout(
    name: &str,
    defs: &HashMap<String, Agg>,
    typedefs: &HashMap<String, TDef>,
    out: &mut HashMap<String, Layout>,
    stack: &mut Vec<String>,
) -> (u64, u32) {
    if let Some(l) = out.get(name) {
        return (l.size, l.align);
    }
    let agg = match defs.get(name) {
        Some(a) => a,
        None => return (1, 1), // opaque used by value: shouldn't happen
    };
    if stack.iter().any(|s| s == name) {
        return (1, 1); // cycle guard
    }
    stack.push(name.to_string());

    let mut offsets = Vec::with_capacity(agg.fields.len());
    let mut max_align = 1u32;
    let mut size = 0u64;
    for f in &agg.fields {
        let (fsize, falign) = field_size_align(f, defs, typedefs, out, stack);
        if f.dims.is_empty() && f.ptrs == 0 {
            // by-value scalar/aggregate handled in fsize
        }
        if !agg.is_union {
            let off = align_up(size, falign as u64);
            offsets.push(off);
            size = off + fsize;
        } else {
            offsets.push(0);
            size = size.max(fsize);
        }
        max_align = max_align.max(falign);
    }
    if let Some(a) = agg.align_override {
        max_align = max_align.max(a);
    }
    let total = align_up(size, max_align as u64);
    stack.pop();
    out.insert(name.to_string(), Layout { size: total, align: max_align, offsets });
    (total, max_align)
}

fn field_size_align(
    f: &Field,
    defs: &HashMap<String, Agg>,
    typedefs: &HashMap<String, TDef>,
    out: &mut HashMap<String, Layout>,
    stack: &mut Vec<String>,
) -> (u64, u32) {
    let (elem_size, elem_align) = if f.ptrs > 0 {
        (8u64, 8u32)
    } else if let Some((_, s, a)) = primitive(&f.base) {
        (s, a)
    } else if let Some(td) = typedefs.get(&f.base) {
        match td {
            TDef::Prim(_, s, a) => (*s, *a),
            TDef::VoidPtr => (8, 8),
        }
    } else if defs.contains_key(&f.base) {
        compute_layout(&f.base, defs, typedefs, out, stack)
    } else {
        (1, 1) // unknown by value
    };
    let n: u64 = if f.dims.is_empty() { 1 } else { f.dims.iter().product() };
    (elem_size * n, elem_align)
}

// ---------- topo sort by by-value containment ----------
fn topo_sort(
    order: &[String],
    defs: &HashMap<String, Agg>,
    typedefs: &HashMap<String, TDef>,
) -> Vec<String> {
    // edges: name -> deps (by-value aggregates)
    let mut result = Vec::with_capacity(order.len());
    let mut state: HashMap<&str, u8> = HashMap::new(); // 0=unseen,1=onstack,2=done
    for start in order {
        if state.get(start.as_str()).copied().unwrap_or(0) == 2 {
            continue;
        }
        // iterative DFS post-order
        let mut stack: Vec<(&str, usize)> = vec![(start.as_str(), 0)];
        while let Some(&(node, idx)) = stack.last() {
            let e = state.entry(node).or_insert(0);
            if *e == 0 {
                *e = 1;
            }
            let agg = &defs[node];
            // find next by-value aggregate dep at/after idx
            let mut moved = false;
            let mut i = idx;
            while i < agg.fields.len() {
                let f = &agg.fields[i];
                i += 1;
                if f.ptrs == 0
                    && !primitive(&f.base).is_some()
                    && !typedefs.contains_key(&f.base)
                    && defs.contains_key(&f.base)
                {
                    let st = state.get(f.base.as_str()).copied().unwrap_or(0);
                    if st == 0 {
                        stack.last_mut().unwrap().1 = i;
                        stack.push((defs.get_key_value(&f.base).unwrap().0.as_str(), 0));
                        moved = true;
                        break;
                    }
                }
            }
            if !moved {
                state.insert(node, 2);
                result.push(node.to_string());
                stack.pop();
            }
        }
    }
    result
}

// ---------- field index resolution ----------
fn intern_ptr(referent: u32, records: &mut Vec<TypeRec>, cache: &mut HashMap<u32, u32>) -> u32 {
    if let Some(&i) = cache.get(&referent) {
        return i;
    }
    let ti = 0x1000 + records.len() as u32;
    records.push(tpi::ptr64(referent));
    cache.insert(referent, ti);
    ti
}

fn intern_arr(
    elem: u32,
    size: u64,
    records: &mut Vec<TypeRec>,
    cache: &mut HashMap<(u32, u64), u32>,
) -> u32 {
    if let Some(&i) = cache.get(&(elem, size)) {
        return i;
    }
    let ti = 0x1000 + records.len() as u32;
    records.push(tpi::array(elem, size));
    cache.insert((elem, size), ti);
    ti
}

fn base_value_index(
    base: &str,
    typedefs: &HashMap<String, TDef>,
    defs: &HashMap<String, Agg>,
    name_to_complete: &HashMap<String, u32>,
    name_to_fwd: &HashMap<String, u32>,
    records: &mut Vec<TypeRec>,
    ptr_cache: &mut HashMap<u32, u32>,
) -> (u32, u64) {
    // returns (type_index, element_size) for a by-value base
    if let Some((i, s, _)) = primitive(base) {
        return (i, s);
    }
    if let Some(td) = typedefs.get(base) {
        return match td {
            TDef::Prim(i, s, _) => (*i, *s),
            TDef::VoidPtr => (intern_ptr(tpi::T_VOID, records, ptr_cache), 8),
        };
    }
    if let Some(&ci) = name_to_complete.get(base) {
        // size from records not needed here; caller uses layout for arrays
        return (ci, 0);
    }
    // fallback: opaque -> its fwdref (incomplete) — only valid via pointer normally
    if let Some(&fi) = name_to_fwd.get(base) {
        return (fi, 1);
    }
    (tpi::T_VOID, 1)
}

fn resolve_field_index(
    f: &Field,
    typedefs: &HashMap<String, TDef>,
    defs: &HashMap<String, Agg>,
    name_to_fwd: &HashMap<String, u32>,
    name_to_complete: &HashMap<String, u32>,
    records: &mut Vec<TypeRec>,
    ptr_cache: &mut HashMap<u32, u32>,
    arr_cache: &mut HashMap<(u32, u64), u32>,
    layouts: &HashMap<String, Layout>,
) -> u32 {
    // element type (before array wrapping)
    let (elem_index, elem_size) = if f.ptrs > 0 {
        // pointer to base (referent). referent: aggregate->fwd, primitive->builtin, void.
        let referent = if let Some((i, _, _)) = primitive(&f.base) {
            i
        } else if let Some(td) = typedefs.get(&f.base) {
            match td {
                TDef::Prim(i, _, _) => *i,
                TDef::VoidPtr => intern_ptr(tpi::T_VOID, records, ptr_cache),
            }
        } else if let Some(&fi) = name_to_fwd.get(&f.base) {
            fi
        } else {
            tpi::T_VOID
        };
        let mut idx = intern_ptr(referent, records, ptr_cache);
        for _ in 1..f.ptrs {
            idx = intern_ptr(idx, records, ptr_cache);
        }
        (idx, 8u64)
    } else {
        let (i, s) = base_value_index(
            &f.base, typedefs, defs, name_to_complete, name_to_fwd, records, ptr_cache,
        );
        // size for aggregates from layout
        let sz = if s == 0 {
            layouts.get(&f.base).map(|l| l.size).unwrap_or(1)
        } else {
            s
        };
        (i, sz)
    };

    if f.dims.is_empty() {
        elem_index
    } else {
        let n: u64 = f.dims.iter().product();
        intern_arr(elem_index, elem_size * n, records, arr_cache)
    }
}

// ---------- field list with continuation splitting ----------
fn build_fieldlist(members: &[Member], records: &mut Vec<TypeRec>) -> u32 {
    const LIMIT: usize = 0xFF00;
    // split members into chunks that fit
    let mut chunks: Vec<&[Member]> = Vec::new();
    let mut start = 0;
    let mut acc = 0usize;
    for i in 0..members.len() {
        let m = &members[i];
        let sz = 2 + 2 + 4 + 8 + m.name.len() + 1 + 3; // approx member record size
        if acc + sz > LIMIT && i > start {
            chunks.push(&members[start..i]);
            start = i;
            acc = 0;
        }
        acc += sz;
    }
    chunks.push(&members[start..]);

    if chunks.len() == 1 {
        let ti = 0x1000 + records.len() as u32;
        records.push(tpi::fieldlist(chunks[0]));
        return ti;
    }
    // multiple: emit last first so LF_INDEX can point forward by index order.
    // We assign consecutive indices; chunk k continues to chunk k+1.
    let first_ti = 0x1000 + records.len() as u32;
    let n = chunks.len();
    for (k, ch) in chunks.iter().enumerate() {
        let cont = if k + 1 < n {
            Some(first_ti + (k as u32) + 1)
        } else {
            None
        };
        records.push(tpi::fieldlist_cont(ch, cont));
    }
    first_ti
}
