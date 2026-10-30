use std::collections::HashSet;
use std::path::{Component, Path};

const MH_MAGIC_64: u32 = 0xfeedfacf;
const MH_DSYM: u32 = 0xa;
const LC_SEGMENT_64: u32 = 0x19;
const LC_UUID: u32 = 0x1b;
const CPU_X86_64: u32 = 0x01000007;
const CPU_ARM64: u32 = 0x0100000c;

/// Addresses are absolute VM addresses; executable ranges are half-open.
pub struct MachO {
    pub base: u64,
    pub text_start: u64,
    pub text_end: u64,
    pub executable_sections: Vec<(u64, u64)>,
    pub cpu_type: u32,
    pub cpu_subtype: u32,
    pub uuid: [u8; 16],
    /// Index of the selected architecture in a universal file, or zero for a thin file.
    pub slice: usize,
    segments: Vec<Vec<u8>>,
}

fn bytes(data: &[u8], off: usize, len: usize) -> Result<&[u8], String> {
    let end = off.checked_add(len).ok_or("Mach-O offset overflow")?;
    data.get(off..end).ok_or_else(|| "truncated Mach-O".to_string())
}

fn u32_at(data: &[u8], off: usize, big: bool) -> Result<u32, String> {
    let b: [u8; 4] = bytes(data, off, 4)?.try_into().unwrap();
    Ok(if big { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) })
}

fn u64_at(data: &[u8], off: usize, big: bool) -> Result<u64, String> {
    let b: [u8; 8] = bytes(data, off, 8)?.try_into().unwrap();
    Ok(if big { u64::from_be_bytes(b) } else { u64::from_le_bytes(b) })
}

fn usize_of(value: u64) -> Result<usize, String> {
    usize::try_from(value).map_err(|_| "Mach-O value does not fit in memory".to_string())
}

fn name_is(field: &[u8], name: &[u8]) -> bool {
    field.split(|&c| c == 0).next() == Some(name)
}

/// Parse a little-endian 64-bit Mach-O or a selected architecture of a universal file.
pub fn parse(path: &str, slice: Option<usize>) -> Result<MachO, String> {
    let source = std::fs::canonicalize(path).map_err(|e| format!("cannot resolve {path}: {e}"))?;
    let data = std::fs::read(&source).map_err(|e| format!("cannot read {path}: {e}"))?;
    let magic = bytes(&data, 0, 4)?;
    let fat = match magic {
        [0xca, 0xfe, 0xba, 0xbe] => Some((true, false)),
        [0xbe, 0xba, 0xfe, 0xca] => Some((false, false)),
        [0xca, 0xfe, 0xba, 0xbf] => Some((true, true)),
        [0xbf, 0xba, 0xfe, 0xca] => Some((false, true)),
        _ => None,
    };
    let selected = slice.unwrap_or(0);
    let (image, fat_cpu) = if let Some((big, wide)) = fat {
        let count = u32_at(&data, 4, big)? as usize;
        if count == 0 { return Err("universal Mach-O has no slices".into()); }
        if slice.is_none() && count != 1 {
            return Err("universal Mach-O has multiple slices; select one explicitly".into());
        }
        if selected >= count { return Err(format!("slice {selected} is out of range (count {count})")); }
        let entry_size = if wide { 32usize } else { 20usize };
        let table_size = count.checked_mul(entry_size).ok_or("fat table size overflow")?;
        bytes(&data, 8, table_size)?;
        let entry = 8 + selected * entry_size;
        let cpu = u32_at(&data, entry, big)?;
        let subtype = u32_at(&data, entry + 4, big)?;
        let (offset, size) = if wide {
            (u64_at(&data, entry + 8, big)?, u64_at(&data, entry + 16, big)?)
        } else {
            (u32_at(&data, entry + 8, big)? as u64, u32_at(&data, entry + 12, big)? as u64)
        };
        let offset = usize_of(offset)?;
        let size = usize_of(size)?;
        if offset < 8 + table_size { return Err("fat slice overlaps architecture table".into()); }
        (bytes(&data, offset, size)?, Some((cpu, subtype)))
    } else {
        if selected != 0 { return Err("thin Mach-O only has slice 0".into()); }
        (data.as_slice(), None)
    };

    if u32_at(image, 0, false)? != MH_MAGIC_64 {
        return Err("expected a little-endian 64-bit Mach-O slice".into());
    }
    bytes(image, 0, 32)?;
    let cpu_type = u32_at(image, 4, false)?;
    let cpu_subtype = u32_at(image, 8, false)?;
    if cpu_type != CPU_X86_64 && cpu_type != CPU_ARM64 {
        return Err(format!("unsupported Mach-O CPU type 0x{cpu_type:08x}"));
    }
    if let Some((cpu, subtype)) = fat_cpu {
        if (cpu, subtype) != (cpu_type, cpu_subtype) {
            return Err("fat architecture does not match slice header".into());
        }
    }
    let ncmds = u32_at(image, 16, false)? as usize;
    let sizeofcmds = u32_at(image, 20, false)? as usize;
    let commands = bytes(image, 32, sizeofcmds)?;
    if ncmds > sizeofcmds / 8 { return Err("invalid Mach-O load command count".into()); }
    let mut pos = 0usize;
    let mut uuid = None;
    let mut base = None;
    let mut executable_sections = Vec::new();
    let mut segments = Vec::new();
    for _ in 0..ncmds {
        let cmd = u32_at(commands, pos, false)?;
        let size = u32_at(commands, pos + 4, false)? as usize;
        if size < 8 || size % 8 != 0 { return Err("invalid Mach-O load command size".into()); }
        let c = bytes(commands, pos, size)?;
        match cmd {
            LC_UUID => {
                if size != 24 || uuid.is_some() { return Err("invalid or duplicate LC_UUID".into()); }
                uuid = Some(bytes(c, 8, 16)?.try_into().unwrap());
            }
            LC_SEGMENT_64 => {
                if size < 72 { return Err("truncated LC_SEGMENT_64".into()); }
                let vmaddr = u64_at(c, 24, false)?;
                let vmsize = u64_at(c, 32, false)?;
                let vmend = vmaddr.checked_add(vmsize).ok_or("segment VM range overflow")?;
                let fileoff = u64_at(c, 40, false)?;
                let filesize = u64_at(c, 48, false)?;
                bytes(image, usize_of(fileoff)?, usize_of(filesize)?)?;
                let nsects = u32_at(c, 64, false)? as usize;
                let sections_size = nsects.checked_mul(80).ok_or("section count overflow")?;
                if 72usize.checked_add(sections_size) != Some(size) {
                    return Err("invalid LC_SEGMENT_64 section table size".into());
                }
                if name_is(&c[8..24], b"__TEXT") {
                    if base.replace(vmaddr).is_some() { return Err("duplicate __TEXT segment".into()); }
                }
                let mut mapped = c.to_vec();
                mapped[40..56].fill(0);
                for i in 0..nsects {
                    let s = 72 + i * 80;
                    let addr = u64_at(c, s + 32, false)?;
                    let len = u64_at(c, s + 40, false)?;
                    let end = addr.checked_add(len).ok_or("section VM range overflow")?;
                    if addr < vmaddr || end > vmend { return Err("section outside segment VM range".into()); }
                    let flags = u32_at(c, s + 64, false)?;
                    let kind = flags & 0xff;
                    let offset = u32_at(c, s + 48, false)? as u64;
                    if len != 0 && kind != 1 && kind != 0xc && kind != 0x12 {
                        let fileend = offset.checked_add(len).ok_or("section file range overflow")?;
                        let segment_end = fileoff.checked_add(filesize).ok_or("segment file range overflow")?;
                        if offset < fileoff || fileend > segment_end {
                            return Err("section outside segment file range".into());
                        }
                        bytes(image, usize_of(offset)?, usize_of(len)?)?;
                    }
                    if len != 0 && flags & 0x80000400 != 0 {
                        executable_sections.push((addr, end));
                    }
                    // A dSYM retains the original VM mapping but not the original section bytes.
                    mapped[s + 48..s + 52].fill(0);
                    mapped[s + 56..s + 64].fill(0);
                }
                // The generated DWARF segment replaces any existing one.
                if !name_is(&c[8..24], b"__DWARF") { segments.push(mapped); }
            }
            _ => {}
        }
        pos += size;
    }
    if pos != sizeofcmds { return Err("load commands do not fill sizeofcmds".into()); }
    let uuid = uuid.ok_or("Mach-O is missing LC_UUID")?;
    let base = base.ok_or("Mach-O is missing __TEXT segment")?;
    executable_sections.sort_unstable();
    let text_start = executable_sections.first().ok_or("Mach-O has no executable sections")?.0;
    let text_end = executable_sections.iter().map(|r| r.1).max().unwrap();
    Ok(MachO { base, text_start, text_end, executable_sections, cpu_type, cpu_subtype, uuid, slice: selected, segments })
}

fn put_u32(out: &mut Vec<u8>, n: u32) { out.extend_from_slice(&n.to_le_bytes()); }
fn put_u64(out: &mut Vec<u8>, n: u64) { out.extend_from_slice(&n.to_le_bytes()); }
fn put_name(out: &mut Vec<u8>, name: &str) {
    out.extend_from_slice(name.as_bytes());
    out.resize(out.len() + 16 - name.len(), 0);
}
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}

impl MachO {
    /// Write a dSYM bundle containing the selected architecture and generated DWARF sections.
    pub fn write_dsym(&self, path: &str, binary_name: &str, sections: Vec<(String, Vec<u8>)>) -> Result<(), String> {
        let mut components = Path::new(binary_name).components();
        if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() || binary_name.contains('\0') {
            return Err("binary name must be a single file name".into());
        }
        let mut names = HashSet::new();
        for (name, _) in &sections {
            if !name.starts_with("__debug_") || name.len() > 16 || !name.is_ascii() || name.as_bytes().contains(&0) || !names.insert(name) {
                return Err(format!("invalid or duplicate DWARF section name: {name}"));
            }
        }
        let nsects = u32::try_from(sections.len()).map_err(|_| "too many DWARF sections")?;
        let dwarf_cmd_size = 72usize.checked_add(sections.len().checked_mul(80).ok_or("DWARF section table overflow")?).ok_or("DWARF command size overflow")?;
        let original_size = self.segments.iter().try_fold(0usize, |n, s| n.checked_add(s.len()).ok_or("load command size overflow"))?;
        let commands_size = original_size.checked_add(24).and_then(|n| n.checked_add(dwarf_cmd_size)).ok_or("load command size overflow")?;
        let commands_u32 = u32::try_from(commands_size).map_err(|_| "load commands too large")?;
        let dwarf_cmd_u32 = u32::try_from(dwarf_cmd_size).map_err(|_| "DWARF command too large")?;
        let ncmds = u32::try_from(self.segments.len()).ok().and_then(|n| n.checked_add(2)).ok_or("too many load commands")?;
        let data_offset = 32usize.checked_add(commands_size).ok_or("file size overflow")?;
        let mut data_size = 0usize;
        for (_, data) in &sections { data_size = data_size.checked_add(data.len()).ok_or("DWARF data size overflow")?; }
        let end = data_offset.checked_add(data_size).ok_or("file size overflow")?;
        if end > u32::MAX as usize { return Err("DWARF sections exceed Mach-O section offset limit".into()); }
        let mut out = Vec::with_capacity(end);
        put_u32(&mut out, MH_MAGIC_64);
        put_u32(&mut out, self.cpu_type);
        put_u32(&mut out, self.cpu_subtype);
        put_u32(&mut out, MH_DSYM);
        put_u32(&mut out, ncmds);
        put_u32(&mut out, commands_u32);
        put_u32(&mut out, 0);
        put_u32(&mut out, 0);
        for segment in &self.segments { out.extend_from_slice(segment); }
        put_u32(&mut out, LC_UUID);
        put_u32(&mut out, 24);
        out.extend_from_slice(&self.uuid);
        put_u32(&mut out, LC_SEGMENT_64);
        put_u32(&mut out, dwarf_cmd_u32);
        put_name(&mut out, "__DWARF");
        put_u64(&mut out, 0);
        put_u64(&mut out, 0);
        put_u64(&mut out, data_offset as u64);
        put_u64(&mut out, data_size as u64);
        put_u32(&mut out, 0);
        put_u32(&mut out, 0);
        put_u32(&mut out, nsects);
        put_u32(&mut out, 0);
        let mut offset = data_offset;
        for (name, data) in &sections {
            put_name(&mut out, name);
            put_name(&mut out, "__DWARF");
            put_u64(&mut out, 0);
            put_u64(&mut out, data.len() as u64);
            put_u32(&mut out, offset as u32);
            put_u32(&mut out, 0);
            put_u32(&mut out, 0);
            put_u32(&mut out, 0);
            put_u32(&mut out, 0x02000000); // S_ATTR_DEBUG
            put_u32(&mut out, 0);
            put_u32(&mut out, 0);
            put_u32(&mut out, 0);
            offset += data.len();
        }
        for (_, data) in sections { out.extend_from_slice(&data); }
        let bundle = Path::new(path);
        if let Some(parent) = bundle.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|e| format!("cannot create dSYM parent directory: {e}"))?;
        }
        std::fs::create_dir(bundle).map_err(|e| format!("cannot create new dSYM bundle (existing bundles are not overwritten): {e}"))?;
        let dwarf_dir = bundle.join("Contents/Resources/DWARF");
        let output = dwarf_dir.join(binary_name);
        std::fs::create_dir_all(&dwarf_dir).map_err(|e| format!("cannot create dSYM bundle contents: {e}"))?;
        let escaped = xml_escape(binary_name);
        let plist = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>CFBundleDevelopmentRegion</key><string>English</string>\n  <key>CFBundleIdentifier</key><string>com.apple.xcode.dsym.{escaped}</string>\n  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>\n  <key>CFBundlePackageType</key><string>dSYM</string>\n  <key>CFBundleSignature</key><string>????</string>\n  <key>CFBundleVersion</key><string>1</string>\n</dict>\n</plist>\n");
        std::fs::write(bundle.join("Contents/Info.plist"), plist).map_err(|e| format!("cannot write dSYM Info.plist: {e}"))?;
        std::fs::write(&output, out).map_err(|e| format!("cannot write dSYM Mach-O: {e}"))?;
        Ok(())
    }
}
