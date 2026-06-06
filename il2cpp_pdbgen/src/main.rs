// il2cpp_pdbgen — native PDB writer for Il2CppDumper output.
#![allow(dead_code, unused_variables)]
mod cv;
mod gsi;
mod il2cpp;
mod msf;
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
        "il2cpp_pdbgen — generate a PDB from Il2CppDumper output (x64 PE only)\n\
         \n\
         usage:\n\
         \x20 il2cpp_pdbgen <dir>                       outputs <dir>\\<dll-name>.pdb\n\
         \x20 il2cpp_pdbgen <dll> <il2cpp.h> <script.json> [out.pdb]\n\
         \n\
         <dir> mode expects GameAssembly.dll, il2cpp.h and script.json in that directory."
    );
    std::process::exit(2);
}

fn main() {
    let t0 = std::time::Instant::now();
    let a: Vec<String> = std::env::args().collect();
    let (dll, header_path, json_path, out_path) = match a.len() {
        // single directory containing the standard Il2CppDumper outputs + the DLL
        2 => {
            let d = std::path::Path::new(&a[1]);
            let dll = d.join("GameAssembly.dll");
            let stem = dll.file_stem().and_then(|s| s.to_str()).unwrap_or("GameAssembly");
            (
                dll.to_string_lossy().into_owned(),
                d.join("il2cpp.h").to_string_lossy().into_owned(),
                d.join("script.json").to_string_lossy().into_owned(),
                d.join(format!("{stem}.pdb")).to_string_lossy().into_owned(),
            )
        }
        4 | 5 => {
            let dll = a[1].clone();
            let out = if a.len() == 5 {
                a[4].clone()
            } else {
                let p = std::path::Path::new(&dll);
                let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("GameAssembly");
                p.with_file_name(format!("{stem}.pdb")).to_string_lossy().into_owned()
            };
            (dll, a[2].clone(), a[3].clone(), out)
        }
        _ => usage(),
    };

    // 1. PE: sections + auto-match GUID/age.
    let pe = pe::parse(&dll);
    eprintln!("PE: {} sections, RSDS={} (age={})", pe.sections.len(), pe.has_rsds, pe.age);

    // 2. Types from il2cpp.h.
    let header = std::fs::read_to_string(&header_path).expect("read il2cpp.h");
    let mut types = il2cpp::parse_and_build(&header);
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
