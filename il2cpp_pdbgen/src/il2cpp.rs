// Parse il2cpp.h, compute x64 struct layouts, and emit CodeView TPI records.
#![allow(dead_code)]
use crate::tpi::{self, Member, TypeRec};
use std::collections::HashMap;

#[derive(Clone)]
struct Field {
    base: String,
    ptrs: u32,
    dims: Vec<u64>,
    qualifiers: Vec<u16>,
    signature: Option<Box<FunctionSig>>,
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
    macho_abi: bool,
    ptr_cache: HashMap<u32, u32>,
    proc_cache: HashMap<(u32, Vec<u32>), u32>,
    modifier_cache: HashMap<(u32, u16), u32>,
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

// Mach-O uses LP64, while the PE type model uses Windows LLP64.
fn abi_type(name: &str, macho: bool) -> &str {
    if macho {
        match name {
            "long" | "long int" | "signed long" | "signed long int" => "int64_t",
            "unsigned long" | "unsigned long int" => "uint64_t",
            "wchar_t" => "int32_t",
            _ => name,
        }
    } else {
        name
    }
}

#[derive(Clone)]
struct FunctionSig {
    ret: Field,
    params: Vec<Field>,
}

#[derive(Clone)]
enum TDef {
    Prim(u32, u64, u32),
    Function(FunctionSig),
}

pub fn parse_and_build(header: &str, macho_abi: bool) -> Types {
    let mut defs: HashMap<String, Agg> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    let mut typedefs: HashMap<String, TDef> = HashMap::new();
    let mut fwd_only: Vec<String> = Vec::new();

    parse(header, &mut defs, &mut order, &mut typedefs, &mut fwd_only, macho_abi);
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
    let name_to_complete: HashMap<String, u32> = HashMap::new();

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

    let mut types = Types {
        records, name_to_complete, name_to_fwd, layouts, typedefs, macho_abi,
        ptr_cache: HashMap::new(), proc_cache: HashMap::new(),
        arglist_cache: HashMap::new(), modifier_cache: HashMap::new(),
    };
    let mut arr_cache: HashMap<(u32, u64), u32> = HashMap::new();

    for name in &topo {
        let agg = &defs[name];
        let lay = types.layouts[name].clone();
        // resolve each member's type index
        let mut members: Vec<Member> = Vec::with_capacity(agg.fields.len());
        for (fi, f) in agg.fields.iter().enumerate() {
            let elem = types.resolve_field(f, &mut Vec::new());
            let idx = if f.dims.is_empty() {
                elem
            } else {
                let size = field_size_align(f, &defs, &types.typedefs, &mut types.layouts, &mut Vec::new()).0;
                intern_arr(elem, size, &mut types.records, &mut arr_cache)
            };
            members.push(Member {
                name: f.name.clone(),
                ty: idx,
                offset: lay.offsets[fi],
            });
        }
        // build (possibly split) field list
        let fl_idx = build_fieldlist(&members, &mut types.records);
        let ti = 0x1000 + types.records.len() as u32;
        let uniq = unique_name(name);
        let rec = if agg.is_union {
            tpi::union_def(name, &uniq, members.len() as u16, fl_idx, lay.size)
        } else {
            tpi::struct_def(name, &uniq, members.len() as u16, fl_idx, lay.size)
        };
        types.records.push(rec);
        types.name_to_complete.insert(name.clone(), ti);
    }

    types
}

impl Types {
    /// Resolve a signature type reference (base name + pointer depth) to a TPI index.
    pub fn resolve_typeref(&mut self, base: &str, ptrs: u32) -> u32 {
        let f = Field { base: base.into(), ptrs, dims: vec![], name: String::new(),
            qualifiers: vec![], signature: None };
        self.resolve_field(&f, &mut Vec::new())
    }

    fn qualify(&mut self, ty: u32, flags: u16) -> u32 {
        if flags == 0 { return ty; }
        if let Some(&idx) = self.modifier_cache.get(&(ty, flags)) { return idx; }
        let idx = 0x1000 + self.records.len() as u32;
        self.records.push(tpi::modifier(ty, flags));
        self.modifier_cache.insert((ty, flags), idx);
        idx
    }

    fn resolve_field(&mut self, f: &Field, stack: &mut Vec<String>) -> u32 {
        let base = abi_type(&f.base, self.macho_abi);
        let mut idx = if base == "..." {
            0
        } else if let Some(sig) = &f.signature {
            self.function_pointer(sig, stack)
        } else if let Some((i, _, _)) = primitive(base) {
            i
        } else if let Some(td) = self.typedefs.get(base).cloned() {
            match td {
                TDef::Prim(i, _, _) => i,
                TDef::Function(sig) => {
                    if stack.iter().any(|s| s == base) {
                        intern_ptr(tpi::T_VOID, &mut self.records, &mut self.ptr_cache)
                    } else {
                        stack.push(base.to_string());
                        let i = self.function_pointer(&sig, stack);
                        stack.pop();
                        i
                    }
                }
            }
        } else if f.ptrs > 0 {
            self.name_to_fwd.get(base).copied().unwrap_or(tpi::T_VOID)
        } else {
            self.name_to_complete.get(base).or_else(|| self.name_to_fwd.get(base)).copied().unwrap_or(tpi::T_VOID)
        };
        idx = self.qualify(idx, f.qualifiers.first().copied().unwrap_or(0));
        for n in 0..f.ptrs {
            idx = intern_ptr(idx, &mut self.records, &mut self.ptr_cache);
            idx = self.qualify(idx, f.qualifiers.get(n as usize + 1).copied().unwrap_or(0));
        }
        idx
    }

    fn function_pointer(&mut self, sig: &FunctionSig, stack: &mut Vec<String>) -> u32 {
        let ret = self.resolve_field(&sig.ret, stack);
        let params: Vec<u32> = sig.params.iter().map(|f| self.resolve_field(f, stack)).collect();
        let proc = self.proc_type(ret, &params);
        intern_ptr(proc, &mut self.records, &mut self.ptr_cache)
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

        let ret = parse_field(head).map(|f| self.resolve_field(&f, &mut Vec::new())).unwrap_or(tpi::T_VOID);
        let params = parse_params(params_str).iter()
            .map(|f| self.resolve_field(f, &mut Vec::new())).collect::<Vec<_>>();
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
    macho_abi: bool,
) {
    let mut stack: Vec<(String, Agg)> = Vec::new();
    let mut closed: Option<String> = None;
    let mut text = String::new();
    let mut in_comment = false;
    let mut next_anon = 0u64;
    let identifiers: std::collections::HashSet<&str> = header
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .collect();

    for raw in header.lines() {
        if !in_comment && raw.trim_start().starts_with('#') {
            continue;
        }
        let mut chars = raw.chars().peekable();
        while let Some(c) = chars.next() {
            if in_comment {
                if c == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    in_comment = false;
                    text.push(' ');
                }
                continue;
            }
            if c == '/' && chars.peek() == Some(&'/') {
                break;
            }
            if c == '/' && chars.peek() == Some(&'*') {
                chars.next();
                in_comment = true;
                continue;
            }
            match c {
                '{' => {
                    let decl = text.trim();
                    let is_union = decl.strip_prefix("union")
                        .is_some_and(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace));
                    let is_struct = decl.strip_prefix("struct")
                        .is_some_and(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace));
                    if is_union || is_struct {
                        if stack.is_empty() {
                            if let Some((name, align, _)) = parse_open(decl) {
                                stack.push((name, Agg {
                                    is_union, align_override: align, fields: Vec::new(),
                                }));
                            }
                        } else {
                            // Every embedded definition gets its own type, even if it has
                            // a tag or a named member. Avoid collisions with header names.
                            let name = loop {
                                let candidate = format!("__il2cpp_anon_{}", next_anon);
                                next_anon += 1;
                                if !identifiers.contains(candidate.as_str()) && !defs.contains_key(&candidate) {
                                    break candidate;
                                }
                            };
                            let align = parse_open(&format!("{} __embedded", decl))
                                .and_then(|(_, align, _)| align);
                            stack.push((name, Agg {
                                is_union, align_override: align, fields: Vec::new(),
                            }));
                        }
                    }
                    text.clear();
                }
                '}' => {
                    text.clear();
                    if let Some((name, agg)) = stack.pop() {
                        if !defs.contains_key(&name) {
                            order.push(name.clone());
                        }
                        defs.insert(name.clone(), agg);
                        closed = Some(name);
                    }
                }
                ';' => {
                    let decl = text.trim();
                    if let Some(name) = closed.take() {
                        if let Some((_, parent)) = stack.last_mut() {
                            let field = if decl.is_empty() {
                                Some(Field {
                                    base: name,
                                    ptrs: 0,
                                    dims: Vec::new(),
                                    name: String::new(),
                                    signature: None,
                                    qualifiers: Vec::new(),
                                })
                            } else {
                                parse_field(&format!("{} {};", name, decl))
                            };
                            if let Some(field) = field {
                                parent.fields.push(field);
                            }
                        }
                    } else if let Some((_, agg)) = stack.last_mut() {
                        if let Some(mut field) = parse_field(&format!("{};", decl)) {
                            field.base = abi_type(&field.base, macho_abi).to_string();
                            agg.fields.push(field);
                        }
                    } else if decl.starts_with("typedef") {
                        parse_typedef(&format!("{};", decl), typedefs, macho_abi);
                    } else if decl.starts_with("struct ") || decl.starts_with("union ") {
                        if let Some(name) = decl.split_whitespace().last() {
                            fwd_only.push(name.to_string());
                        }
                    }
                    text.clear();
                }
                _ => text.push(c),
            }
        }
        text.push(' ');
        // Ignore unrelated top-level lines rather than letting them prefix a
        // subsequent declaration. Keep multi-line typedefs and aggregate opens.
        if stack.is_empty() && closed.is_none() {
            let t = text.trim_start();
            if !t.starts_with("typedef") && !t.starts_with("struct") && !t.starts_with("union") {
                text.clear();
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

fn parse_typedef(t: &str, typedefs: &mut HashMap<String, TDef>, macho_abi: bool) {
    let body = t.trim_start_matches("typedef").trim().trim_end_matches(';');
    if let Some((name, sig)) = parse_function_pointer(body) {
        if !name.is_empty() {
            typedefs.insert(name, TDef::Function(sig));
        }
        return;
    }
    // simple typedef: "<type> NAME"
    let toks: Vec<&str> = body.split_whitespace().collect();
    if toks.len() >= 2 {
        let name = toks[toks.len() - 1].to_string();
        let underlying = toks[..toks.len() - 1].join(" ");
        if let Some((i, s, a)) = primitive(abi_type(&underlying, macho_abi)) {
            typedefs.insert(name, TDef::Prim(i, s, a));
        }
    }
}

// Split parameters only at the outer level so callback parameters stay intact.
fn parse_params(s: &str) -> Vec<Field> {
    let s = s.trim();
    if s.is_empty() || s == "void" { return Vec::new(); }
    let mut result = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                if let Some(f) = parse_decl(&s[start..i], true) { result.push(f); }
                start = i + 1;
            }
            _ => {}
        }
    }
    if let Some(f) = parse_decl(&s[start..], true) { result.push(f); }
    result
}

fn parse_function_pointer(s: &str) -> Option<(String, FunctionSig)> {
    let p = s.find("(*")?;
    let end = s[p + 2..].find(')')? + p + 2;
    let name = s[p + 2..end].trim().to_string();
    let args = s[end + 1..].trim().strip_prefix('(')?.strip_suffix(')')?;
    let ret = parse_decl(&s[..p], true)?;
    Some((name, FunctionSig { ret, params: parse_params(args) }))
}

fn parse_field(t: &str) -> Option<Field> {
    parse_decl(t, false)
}

fn parse_decl(t: &str, unnamed: bool) -> Option<Field> {
    let mut s = t.trim().trim_end_matches(';').trim().to_string();
    if s.is_empty() { return None; }
    if s == "..." {
        return Some(Field { base: "...".into(), name: String::new(), ptrs: 0,
            dims: vec![], qualifiers: vec![], signature: None });
    }
    if let Some((name, sig)) = parse_function_pointer(&s) {
        return Some(Field { base: String::new(), ptrs: 0, dims: vec![], name,
            qualifiers: vec![], signature: Some(Box::new(sig)) });
    }
    if let Some(c) = s.find(':') { s.truncate(c); }
    let mut dims = Vec::new();
    while let Some(open) = s.rfind('[') {
        if let Some(close) = s[open..].find(']') {
            let d = s[open + 1..open + close].trim().parse().unwrap_or(0);
            dims.insert(0, d);
            s.replace_range(open..open + close + 1, "");
        } else { break; }
    }
    let parts: Vec<&str> = s.split('*').collect();
    let ptrs = (parts.len() - 1) as u32;
    let mut qualifiers = Vec::with_capacity(parts.len());
    let mut words = Vec::new();
    for part in &parts {
        let mut flags = 0;
        for word in part.split_whitespace() {
            match word {
                "const" => flags |= 1,
                "volatile" => flags |= 2,
                "struct" | "union" | "enum" => {}
                _ => words.push(word),
            }
        }
        qualifiers.push(flags);
    }
    if words.is_empty() { return None; }
    let whole = words.join(" ");
    let no_name = unnamed && (words.len() == 1 || primitive(&whole).is_some());
    let name = if no_name { String::new() } else { words.pop()?.to_string() };
    if words.is_empty() { return None; }
    Some(Field { base: words.join(" "), ptrs, dims, name, qualifiers, signature: None })
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
    let (elem_size, elem_align) = if f.ptrs > 0 || f.signature.is_some() {
        (8u64, 8u32)
    } else if let Some((_, s, a)) = primitive(&f.base) {
        (s, a)
    } else if let Some(td) = typedefs.get(&f.base) {
        match td {
            TDef::Prim(_, s, a) => (*s, *a),
            TDef::Function(_) => (8, 8),
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

#[cfg(test)]
mod tests {
    use super::parse_and_build;

    #[test]
    fn macho_layout_uses_lp64_without_changing_pe_layout() {
        let header = "struct Sample {\nlong first;\nwchar_t second;\n};\n";
        let macho = parse_and_build(header, true);
        let pe = parse_and_build(header, false);
        assert_eq!(macho.layouts["Sample"].offsets, [0, 8]);
        assert_eq!(macho.layouts["Sample"].size, 16);
        assert_eq!(pe.layouts["Sample"].offsets, [0, 4]);
        assert_eq!(pe.layouts["Sample"].size, 8);
    }
}

#[cfg(test)]
mod nested_layout_tests {
    use super::{parse, parse_and_build};
    use std::collections::HashMap;

    #[test]
    fn nested_and_adjacent_anonymous_aggregates_preserve_outer_layout() {
        let header = r#"
            struct MethodInfo
            {
                void* methodPointer;
                union {
                    void* invoker;
                    struct
                    {
                        uint32_t first;
                        union { uint64_t wide; uint32_t narrow; };
                    };
                };
                union
                {
                    uint32_t token;
                    uint64_t metadata;
                };
                uint32_t flags;
            };
        "#;
        let mut defs = HashMap::new();
        let mut order = Vec::new();
        parse(header, &mut defs, &mut order, &mut HashMap::new(), &mut Vec::new(), true);
        let outer = &defs["MethodInfo"];
        assert_eq!(outer.fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
                   ["methodPointer", "", "", "flags"]);
        let first_union = &outer.fields[1].base;
        let second_union = &outer.fields[2].base;
        assert_ne!(first_union, second_union);
        assert!(defs[first_union].is_union);
        assert!(defs[second_union].is_union);
        let nested_struct = &defs[first_union].fields[1];
        assert_eq!(nested_struct.name, "");
        assert!(!defs[&nested_struct.base].is_union);
        let inner_union = &defs[&nested_struct.base].fields[1];
        assert_eq!(inner_union.name, "");
        assert!(defs[&inner_union.base].is_union);

        for macho in [false, true] {
            let types = parse_and_build(header, macho);
            assert_eq!(types.layouts["MethodInfo"].offsets, [0, 8, 24, 32]);
            assert_eq!(types.layouts["MethodInfo"].size, 40);
            assert_eq!(types.layouts[first_union].offsets, [0, 0]);
            assert_eq!(types.layouts[second_union].offsets, [0, 0]);
            assert_eq!(types.layouts[&inner_union.base].offsets, [0, 0]);
        }
    }

    #[test]
    fn named_embedded_members_and_synthetic_name_collisions() {
        let header = r#"
            struct __il2cpp_anon_0 { uint8_t value; };
            struct Container { union { uint32_t a; uint64_t b; } named;
                struct { uint16_t a; uint16_t b; } items[2];
                uint8_t tail; };
        "#;
        let mut defs = HashMap::new();
        parse(header, &mut defs, &mut Vec::new(), &mut HashMap::new(), &mut Vec::new(), false);
        let fields = &defs["Container"].fields;
        assert_eq!(fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
                   ["named", "items", "tail"]);
        assert_ne!(fields[0].base, "__il2cpp_anon_0");
        assert_ne!(fields[0].base, fields[1].base);
        assert_eq!(fields[1].dims, [2]);
        let types = parse_and_build(header, false);
        assert_eq!(types.layouts["Container"].offsets, [0, 8, 16]);
        assert_eq!(types.layouts["Container"].size, 24);
    }
}

#[cfg(test)]
mod function_pointer_tests {
    use super::{parse_and_build, Types};

    fn rec(types: &Types, idx: u32, kind: u16) -> &[u8] {
        let r = &types.records[(idx - 0x1000) as usize];
        assert_eq!(r.kind, kind);
        &r.bytes
    }

    fn word(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    fn procedure(types: &Types, ptr: u32) -> (u32, Vec<u32>) {
        let proc = word(rec(types, ptr, 0x1002), 4);
        let p = rec(types, proc, 0x1008);
        let ret = word(p, 4);
        let args = rec(types, word(p, 12), 0x1201);
        let count = word(args, 4) as usize;
        (ret, (0..count).map(|i| word(args, 8 + i * 4)).collect())
    }

    #[test]
    fn callback_typedefs_preserve_signatures_and_pointer_layout() {
        let header = "\
struct MethodInfo;
typedef int (*Inner)(const MethodInfo*, void*);
typedef void* (*Outer)(Inner, const char*, unsigned int);
struct Holder {
    Outer callback;
    int (*inline_callback)(const MethodInfo*, void*);
    int tail;
};";
        for macho in [false, true] {
            let mut types = parse_and_build(header, macho);
            assert_eq!(types.layouts["Holder"].offsets, [0, 8, 16]);
            assert_eq!(types.layouts["Holder"].size, 24);
            let outer = types.resolve_typeref("Outer", 0);
            let (ret, args) = procedure(&types, outer);
            assert_eq!(word(rec(&types, ret, 0x1002), 4), 3);
            assert_eq!(args.len(), 3);
            assert_eq!(args[2], 0x75);
            let (inner_ret, inner_args) = procedure(&types, args[0]);
            assert_eq!(inner_ret, 0x74);
            assert_eq!(inner_args.len(), 2);
            let const_info = word(rec(&types, inner_args[0], 0x1002), 4);
            let modifier = rec(&types, const_info, 0x1001);
            assert_eq!(word(modifier, 4), types.name_to_fwd["MethodInfo"]);
            assert_eq!(&modifier[8..10], &1u16.to_le_bytes());
            assert_eq!(word(rec(&types, inner_args[1], 0x1002), 4), 3);
            let const_char = word(rec(&types, args[1], 0x1002), 4);
            assert_eq!(word(rec(&types, const_char, 0x1001), 4), 0x70);
            let inner = types.resolve_typeref("Inner", 0);
            assert_eq!(inner, args[0]);
            let holder = rec(&types, types.name_to_complete["Holder"], 0x1505);
            let fields = rec(&types, word(holder, 8), 0x1203);
            assert_eq!(word(fields, 8), outer);
            assert_eq!(word(fields, 28), inner);
        }
    }

    #[test]
    fn method_signatures_keep_unnamed_and_inline_callback_parameters() {
        let mut types = parse_and_build("struct MethodInfo;", false);
        let proc = types.sig_to_proc("void Run(const MethodInfo*, int (*cb)(void*, int), ...);");
        let p = rec(&types, proc, 0x1008);
        let args = rec(&types, word(p, 12), 0x1201);
        assert_eq!(word(args, 4), 3);
        let first = word(args, 8);
        let modifier = word(rec(&types, first, 0x1002), 4);
        assert_eq!(word(rec(&types, modifier, 0x1001), 4), types.name_to_fwd["MethodInfo"]);
        let (ret, callback_args) = procedure(&types, word(args, 12));
        assert_eq!(ret, 0x74);
        assert_eq!(callback_args.len(), 2);
        assert_eq!(callback_args[1], 0x74);
        assert_eq!(word(args, 16), 0);
    }
}
