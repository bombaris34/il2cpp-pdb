// Minimal PE reader: section table + CodeView (RSDS) debug info for GUID/age match.

pub struct Section {
    pub vaddr: u32,
    pub vsize: u32,
    pub seg: u16,
}

pub struct PeInfo {
    pub sections: Vec<Section>,
    pub guid: [u8; 16],
    pub age: u32,
    pub has_rsds: bool,
    pub section_headers: Vec<u8>, // raw IMAGE_SECTION_HEADER array (nsec * 40 bytes)
}

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

pub fn parse(path: &str) -> PeInfo {
    let b = std::fs::read(path).expect("read PE");
    let e = u32le(&b, 0x3C) as usize;
    assert_eq!(&b[e..e + 4], b"PE\0\0", "bad PE sig");
    let nsec = u16le(&b, e + 6) as usize;
    let optsize = u16le(&b, e + 20) as usize;
    let opt = e + 24;
    let pe32plus = u16le(&b, opt) == 0x20B;
    let dd_off = opt + if pe32plus { 112 } else { 96 };
    let debug_rva = u32le(&b, dd_off + 6 * 8);
    let debug_size = u32le(&b, dd_off + 6 * 8 + 4);

    let sec_off = opt + optsize;
    let mut sections = Vec::new();
    for i in 0..nsec {
        let s = sec_off + i * 40;
        let vsize = u32le(&b, s + 8);
        let vaddr = u32le(&b, s + 12);
        sections.push(Section { vaddr, vsize, seg: (i + 1) as u16 });
    }

    let rva_to_off = |rva: u32| -> Option<usize> {
        for s in &sections {
            if rva >= s.vaddr && rva < s.vaddr + s.vsize {
                // need raw pointer; re-read from headers
            }
        }
        // use raw pointer table for file offset
        for i in 0..nsec {
            let so = sec_off + i * 40;
            let vsize = u32le(&b, so + 8);
            let vaddr = u32le(&b, so + 12);
            let rawptr = u32le(&b, so + 20);
            if rva >= vaddr && rva < vaddr + vsize {
                return Some((rawptr + (rva - vaddr)) as usize);
            }
        }
        None
    };

    let mut guid = [0u8; 16];
    let mut age = 1u32;
    let mut has_rsds = false;
    if debug_rva != 0 {
        if let Some(off) = rva_to_off(debug_rva) {
            let n = debug_size as usize / 28;
            for i in 0..n {
                let ent = off + i * 28;
                let dtype = u32le(&b, ent + 12);
                let dsize = u32le(&b, ent + 16) as usize;
                let drptr = u32le(&b, ent + 24) as usize;
                if dtype == 2 {
                    let cv = &b[drptr..drptr + dsize];
                    if &cv[0..4] == b"RSDS" {
                        guid.copy_from_slice(&cv[4..20]);
                        age = u32le(cv, 20);
                        has_rsds = true;
                    }
                }
            }
        }
    }

    let section_headers = b[sec_off..sec_off + nsec * 40].to_vec();
    PeInfo { sections, guid, age, has_rsds, section_headers }
}

impl PeInfo {
    /// RVA -> (segment, offset-in-section, section-end-rva)
    pub fn seg_off(&self, rva: u32) -> Option<(u16, u32, u32)> {
        for s in &self.sections {
            if rva >= s.vaddr && rva < s.vaddr + s.vsize {
                return Some((s.seg, rva - s.vaddr, s.vaddr + s.vsize));
            }
        }
        None
    }
}
