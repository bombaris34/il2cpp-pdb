// il2cpp_pdbgen — native PDB writer for Il2CppDumper output.
#![allow(dead_code, unused_variables)]
mod cv;
mod dwarf;
mod gsi;
mod il2cpp;
mod msf;
mod macho;
mod pe;
mod streams;
mod tpi;

use serde::Deserialize;
use streams::*;

#[derive(Deserialize)]
struct Method {
    #[serde(rename = "Address")]
    address: u64,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Signature")]
    signature: Option<String>,
}

#[derive(Deserialize)]
struct Script {
    #[serde(rename = "ScriptMethod")]
    script_method: Vec<Method>,
    #[serde(rename = "Addresses")]
    addresses: Vec<u64>,
}

fn usage() -> ! {
    eprintln!(
        "il2cpp_pdbgen — generate PDB (PE) or dSYM (Mach-O) symbols\n\
         \n\
         usage:\n\
         \x20 il2cpp_pdbgen <dir>\n\
         \x20 il2cpp_pdbgen <binary> <il2cpp.h> <script.json> [output] [--slice <index>]\n\
         \n\
         For universal Mach-O binaries, --slice is a zero-based architecture index.\n\
         Directory mode expects GameAssembly.dll, il2cpp.h and script.json."
    );
    std::process::exit(2);
}

fn main() {
    let t0 = std::time::Instant::now();
    let mut a: Vec<String> = std::env::args().collect();
    let slice = if let Some(i) = a.iter().position(|x| x == "--slice") {
        if i + 2 != a.len() { usage(); }
        let index = a[i + 1].parse::<usize>().unwrap_or_else(|_| usage());
        a.truncate(i);
        Some(index)
    } else {
        None
    };
    let (dll, header_path, json_path, explicit_out) = match a.len() {
        // single directory containing the standard Il2CppDumper outputs + the DLL
        2 => {
            let d = std::path::Path::new(&a[1]);
            let dll = d.join("GameAssembly.dll");
            let stem = dll.file_stem().and_then(|s| s.to_str()).unwrap_or("GameAssembly");
            (
                dll.to_string_lossy().into_owned(),
                d.join("il2cpp.h").to_string_lossy().into_owned(),
                d.join("script.json").to_string_lossy().into_owned(),
                Some(d.join(format!("{stem}.pdb")).to_string_lossy().into_owned()),
            )
        }
        4 | 5 => {
            let dll = a[1].clone();
            let out = if a.len() == 5 { Some(a[4].clone()) } else { None };
            (dll, a[2].clone(), a[3].clone(), out)
        }
        _ => usage(),
    };

    use std::io::Read;
    let mut magic = [0u8; 4];
    std::fs::File::open(&dll).expect("open binary").read_exact(&mut magic).expect("read binary magic");
    let is_pe = &magic[..2] == b"MZ";
    let out_path = explicit_out.unwrap_or_else(|| {
        let p = std::path::Path::new(&dll);
        if is_pe {
            p.with_extension("pdb").to_string_lossy().into_owned()
        } else {
            format!("{}.dSYM", p.display())
        }
    });
    if !is_pe {
        generate_macho(&dll, &header_path, &json_path, &out_path, slice, t0);
        return;
    }
    if slice.is_some() {
        eprintln!("--slice is only valid for Mach-O binaries");
        std::process::exit(2);
    }

    // 1. PE: sections + auto-match GUID/age.
    let pe = pe::parse(&dll);
    eprintln!("PE: {} sections, RSDS={} (age={})", pe.sections.len(), pe.has_rsds, pe.age);

    // 2. Types from il2cpp.h.
    let header = std::fs::read_to_string(&header_path).expect("read il2cpp.h");
    let mut types = il2cpp::parse_and_build(&header, false);
    eprintln!("types: {} records in {:?}", types.records.len(), t0.elapsed());

    // 3. script.json.
    let f = std::io::BufReader::new(std::fs::File::open(&json_path).expect("open script.json"));
    let script: Script = serde_json::from_reader(f).unwrap();
    eprintln!("script.json: {} methods, {} addresses in {:?}", script.script_method.len(), script.addresses.len(), t0.elapsed());

    let mut addrs = script.addresses.clone();
    addrs.sort_unstable();
    addrs.dedup();
    let code_size = |rva: u64, sec_end: u32| -> u32 {
        let cap = sec_end as u64 - rva;
        let j = addrs.partition_point(|&a| a <= rva);
        let mut s = if j < addrs.len() { addrs[j] - rva } else { cap };
        if s == 0 { s = 1; }
        if s > cap { s = cap; }
        if s > 0x200000 { s = 0x200000; }
        s as u32
    };

    // 4. Build procs, wiring FunctionType from signatures.
    let mut procs = Vec::with_capacity(script.script_method.len());
    let mut typed = 0u64;
    for m in &script.script_method {
        let rva = m.address as u32;
        let (seg, off, sec_end) = match pe.seg_off(rva) {
            Some(x) => x,
            None => continue,
        };
        let size = code_size(m.address, sec_end);
        let type_index = match &m.signature {
            Some(s) if !s.is_empty() => {
                let ti = types.sig_to_proc(s);
                if ti != 0 { typed += 1; }
                ti
            }
            _ => 0,
        };
        procs.push(Proc { name: m.name.clone(), seg, off, size, type_index });
    }
    eprintln!("procs: {} ({} typed), types now {} records, {:?}", procs.len(), typed, types.records.len(), t0.elapsed());

    // 5. Emit PDB.
    let pdb = build_pdb(BuildInput {
        guid: pe.guid,
        age: pe.age,
        procs,
        types: types.records,
        section_headers: pe.section_headers,
    });
    std::fs::write(&out_path, &pdb).expect("write pdb");
    eprintln!("wrote {} ({} MB) in {:?}", out_path, pdb.len() / 1_000_000, t0.elapsed());
}

fn generate_macho(binary: &str, header_path: &str, json_path: &str, output: &str, slice: Option<usize>, start: std::time::Instant) {
    let macho = macho::parse(binary, slice).unwrap_or_else(|e| { eprintln!("Mach-O: {e}"); std::process::exit(1) });
    let header = std::fs::read_to_string(header_path).expect("read il2cpp.h");
    let mut types = il2cpp::parse_and_build(&header, true);
    let input = std::io::BufReader::new(std::fs::File::open(json_path).expect("open script.json"));
    let script: Script = serde_json::from_reader(input).expect("parse script.json");
    let mut addresses = script.addresses;
    addresses.sort_unstable();
    addresses.dedup();
    let mut functions = Vec::with_capacity(script.script_method.len());
    for method in script.script_method {
        let Some(address) = macho.base.checked_add(method.address) else { continue };
        let Some((_, section_end)) = macho.executable_sections.iter()
            .find(|&&(begin, end)| address >= begin && address < end) else { continue };
        let next = addresses.partition_point(|&a| a <= method.address);
        let end = addresses.get(next).and_then(|a| macho.base.checked_add(*a))
            .unwrap_or(*section_end).min(*section_end);
        let size = end.saturating_sub(address).min(0x20_0000);
        let type_index = method.signature.as_deref().filter(|s| !s.is_empty())
            .map(|s| types.sig_to_proc(s)).unwrap_or(0);
        functions.push(dwarf::Function { name: method.name, address, size, type_index });
    }
    eprintln!("Mach-O: {} functions, {} type records", functions.len(), types.records.len());
    let sections = dwarf::generate(&types.records, &functions)
        .unwrap_or_else(|e| { eprintln!("DWARF: {e}"); std::process::exit(1) });
    let name = std::path::Path::new(binary).file_name().and_then(|n| n.to_str()).expect("binary name");
    macho.write_dsym(output, name, sections)
        .unwrap_or_else(|e| { eprintln!("dSYM: {e}"); std::process::exit(1) });
    eprintln!("wrote {output} in {:?}", start.elapsed());
}
