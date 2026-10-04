//! A small, bounds-checked ELF reader (header, PT_INTERP, DT_NEEDED,
//! DT_RUNPATH/DT_RPATH) and the shared-library search it enables.

use crate::{path, sys};
use std::path::Path;
use std::time::Instant;
use tracewhy_core::{EnvSnapshot, FactKind, LibraryCandidate};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfSummary {
    pub class: u8,
    pub machine: String,
    pub interpreter: Option<String>,
    pub needed: Vec<String>,
    pub runpath: Vec<String>,
}

pub fn machine_name(m: u16) -> String {
    match m {
        3 => "i386".into(),
        8 => "mips".into(),
        20 => "ppc".into(),
        21 => "ppc64".into(),
        22 => "s390x".into(),
        40 => "arm".into(),
        62 => "x86_64".into(),
        183 => "aarch64".into(),
        243 => "riscv64".into(),
        258 => "loongarch64".into(),
        n => format!("machine-{n}"),
    }
}

/// Normalize `uname -m` to ELF machine naming.
pub fn host_machine() -> String {
    match sys::machine().as_deref() {
        Some("i686" | "i586" | "i486" | "i386") => "i386".into(),
        Some("armv7l" | "armv6l" | "armv8l") => "arm".into(),
        Some("arm64") => "aarch64".into(),
        Some(m) => m.to_string(),
        None => "unknown".into(),
    }
}

struct Reader<'a> {
    b: &'a [u8],
    le: bool,
}

impl Reader<'_> {
    fn u16(&self, o: usize) -> Option<u16> {
        let s = self.b.get(o..o.checked_add(2)?)?;
        let a = [s[0], s[1]];
        Some(if self.le {
            u16::from_le_bytes(a)
        } else {
            u16::from_be_bytes(a)
        })
    }
    fn u32(&self, o: usize) -> Option<u32> {
        let s = self.b.get(o..o.checked_add(4)?)?;
        let a = [s[0], s[1], s[2], s[3]];
        Some(if self.le {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        })
    }
    fn u64(&self, o: usize) -> Option<u64> {
        let s = self.b.get(o..o.checked_add(8)?)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Some(if self.le {
            u64::from_le_bytes(a)
        } else {
            u64::from_be_bytes(a)
        })
    }
    fn word(&self, o: usize, is64: bool) -> Option<u64> {
        if is64 {
            self.u64(o)
        } else {
            self.u32(o).map(u64::from)
        }
    }
    fn cstr(&self, o: usize) -> Option<String> {
        let rest = self.b.get(o..)?;
        let end = rest.iter().position(|c| *c == 0)?;
        Some(String::from_utf8_lossy(&rest[..end]).into_owned())
    }
}

/// Parse an in-memory ELF image. Returns `None` for non-ELF data.
pub fn parse_elf(b: &[u8]) -> Option<ElfSummary> {
    if b.get(..4)? != b"\x7fELF" {
        return None;
    }
    let is64 = match b.get(4)? {
        1 => false,
        2 => true,
        _ => return None,
    };
    let le = *b.get(5)? == 1;
    let r = Reader { b, le };
    let machine = machine_name(r.u16(18)?);
    let (phoff, phentsize, phnum) = if is64 {
        (
            usize::try_from(r.u64(32)?).ok()?,
            usize::from(r.u16(54)?),
            usize::from(r.u16(56)?),
        )
    } else {
        (
            r.u32(28)? as usize,
            usize::from(r.u16(42)?),
            usize::from(r.u16(44)?),
        )
    };
    let mut interpreter = None;
    let mut loads: Vec<(u64, u64, u64)> = Vec::new(); // vaddr, offset, filesz
    let mut dynamic: Option<(usize, usize)> = None;
    for i in 0..phnum.min(256) {
        let ph = phoff.checked_add(i.checked_mul(phentsize)?)?;
        let p_type = r.u32(ph)?;
        let at = |n: usize| ph.checked_add(n);
        let (offset, vaddr, filesz) = if is64 {
            (r.u64(at(8)?)?, r.u64(at(16)?)?, r.u64(at(32)?)?)
        } else {
            (
                u64::from(r.u32(at(4)?)?),
                u64::from(r.u32(at(8)?)?),
                u64::from(r.u32(at(16)?)?),
            )
        };
        match p_type {
            1 => loads.push((vaddr, offset, filesz)),
            2 => dynamic = Some((usize::try_from(offset).ok()?, usize::try_from(filesz).ok()?)),
            3 => interpreter = usize::try_from(offset).ok().and_then(|o| r.cstr(o)),
            _ => {}
        }
    }
    let mut needed = Vec::new();
    let mut runpath = Vec::new();
    if let Some((doff, dsz)) = dynamic {
        let ent = if is64 { 16 } else { 8 };
        let mut strtab = None;
        let mut needed_off = Vec::new();
        let mut run_off = Vec::new();
        for i in 0..(dsz / ent).min(4096) {
            let o = doff.checked_add(i * ent)?;
            let tag = r.word(o, is64)?;
            let val = r.word(o.checked_add(ent / 2)?, is64)?;
            match tag {
                0 => break,
                1 => needed_off.push(val),
                5 => strtab = Some(val),
                15 | 29 => run_off.push(val),
                _ => {}
            }
        }
        // DT_STRTAB is a virtual address; map it to a file offset via PT_LOAD.
        if let Some(sv) = strtab {
            if let Some(&(va, off, _)) = loads.iter().find(|(va, _, sz)| {
                sv >= *va && va.checked_add(*sz).map(|end| sv < end).unwrap_or(false)
            }) {
                let base = (sv - va)
                    .checked_add(off)
                    .and_then(|b| usize::try_from(b).ok())?;
                let at = |n: u64| usize::try_from(n).ok().and_then(|n| base.checked_add(n));
                needed = needed_off
                    .iter()
                    .filter_map(|n| at(*n).and_then(|o| r.cstr(o)))
                    .collect();
                for o in run_off {
                    if let Some(s) = at(o).and_then(|o| r.cstr(o)) {
                        runpath.extend(s.split(':').filter(|x| !x.is_empty()).map(String::from));
                    }
                }
            }
        }
    }
    Some(ElfSummary {
        class: if is64 { 64 } else { 32 },
        machine,
        interpreter,
        needed,
        runpath,
    })
}

fn read_head(path: &str, max: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    let f = std::fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    f.take(max as u64).read_to_end(&mut buf).ok()?;
    Some(buf)
}

/// Read enough of a binary to parse its headers and dynamic section.
fn read_elf(path: &str) -> Option<ElfSummary> {
    // Dynamic sections and string tables live near the start of typical binaries.
    let buf = read_head(path, 4 << 20)?;
    parse_elf(&buf)
}

pub fn investigate(path: &str, env: &EnvSnapshot) -> Vec<FactKind> {
    let mut out = vec![FactKind::HostArchitecture {
        machine: host_machine(),
    }];
    match read_elf(path) {
        Some(s) => {
            if let Some(i) = &s.interpreter {
                out.push(path::path_status(i));
            }
            out.push(FactKind::ElfInfo {
                path: path.to_string(),
                class: s.class,
                machine: s.machine,
                interpreter: s.interpreter,
                needed: s.needed,
                runpath: s.runpath,
            });
        }
        None => {
            if let Some(f) = path::interpreter_fact(path, env) {
                out.push(f);
            } else if let Some(head) = read_head(path, 4) {
                out.push(FactKind::NotElf {
                    path: path.to_string(),
                    magic: Some(head.iter().map(|b| format!("{b:02x}")).collect()),
                });
            }
        }
    }
    out
}

fn ld_so_conf_dirs(file: &str, depth: u32, out: &mut Vec<String>) {
    if depth > 4 {
        return;
    }
    let Ok(text) = std::fs::read_to_string(file) else {
        return;
    };
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if let Some(pat) = line.strip_prefix("include ") {
            let pat = pat.trim();
            // Only the common `dir/*.conf` glob form is supported.
            if let Some((dir, suffix)) = pat.rsplit_once("/*") {
                if let Ok(rd) = std::fs::read_dir(dir) {
                    let mut files: Vec<String> = rd
                        .flatten()
                        .map(|e| e.path().to_string_lossy().into_owned())
                        .filter(|p| p.ends_with(suffix))
                        .collect();
                    files.sort();
                    for f in files {
                        ld_so_conf_dirs(&f, depth + 1, out);
                    }
                }
            } else {
                ld_so_conf_dirs(pat, depth + 1, out);
            }
        } else if line.starts_with('/') {
            out.push(line.to_string());
        }
    }
}

/// Directories the dynamic loader searches for `executable`'s libraries.
pub fn search_dirs(
    exe: Option<&ElfSummary>,
    exe_path: Option<&str>,
    env: &EnvSnapshot,
) -> Vec<String> {
    let mut dirs = Vec::new();
    if let Some(llp) = env.get("LD_LIBRARY_PATH") {
        dirs.extend(llp.split(':').filter(|d| !d.is_empty()).map(String::from));
    }
    if let (Some(e), Some(p)) = (exe, exe_path) {
        let origin = Path::new(p)
            .parent()
            .map(|d| d.to_string_lossy().into_owned())
            .unwrap_or_default();
        for r in &e.runpath {
            dirs.push(r.replace("$ORIGIN", &origin).replace("${ORIGIN}", &origin));
        }
    }
    ld_so_conf_dirs("/etc/ld.so.conf", 0, &mut dirs);
    let arch = host_machine();
    let triple = match arch.as_str() {
        "x86_64" => "x86_64-linux-gnu",
        "aarch64" => "aarch64-linux-gnu",
        "i386" => "i386-linux-gnu",
        "arm" => "arm-linux-gnueabihf",
        _ => "",
    };
    for d in ["/lib", "/usr/lib", "/lib64", "/usr/lib64"] {
        if !triple.is_empty() {
            dirs.push(format!("{d}/{triple}"));
        }
        dirs.push(d.to_string());
    }
    let mut seen = std::collections::HashSet::new();
    dirs.retain(|d| seen.insert(d.clone()));
    dirs
}

/// Where `lib` could be loaded from, and copies outside the search path.
pub fn search_library(
    lib: &str,
    executable: Option<&str>,
    env: &EnvSnapshot,
    cwd: &Path,
    deadline: Instant,
) -> Vec<FactKind> {
    let exe = executable.and_then(read_elf);
    let want_machine = exe
        .as_ref()
        .map(|e| e.machine.clone())
        .unwrap_or_else(host_machine);
    let want_class = exe.as_ref().map(|e| e.class);
    let dirs = search_dirs(exe.as_ref(), executable, env);
    let mut found = Vec::new();
    for d in &dirs {
        let p = format!("{d}/{lib}");
        if std::fs::metadata(&p).is_ok() {
            let s = read_elf(&p);
            let compatible = s
                .as_ref()
                .map(|s| {
                    s.machine == want_machine && want_class.map(|c| c == s.class).unwrap_or(true)
                })
                .unwrap_or(false);
            found.push(LibraryCandidate {
                path: p,
                machine: s.map(|s| s.machine),
                compatible,
            });
        }
    }
    let mut elsewhere = Vec::new();
    if found.is_empty() {
        let mut roots: Vec<std::path::PathBuf> =
            vec!["/opt".into(), "/usr/local".into(), cwd.to_path_buf()];
        if let Some(e) = executable.and_then(|e| Path::new(e).parent()) {
            roots.push(e.to_path_buf());
            if let Some(pp) = e.parent() {
                roots.push(pp.to_path_buf());
            }
        }
        let mut budget = 50_000usize;
        for r in roots {
            find_file(&r, lib, 5, &mut budget, deadline, &mut elsewhere);
        }
        elsewhere.sort();
        elsewhere.dedup();
        elsewhere.retain(|p| !dirs.iter().any(|d| *p == format!("{d}/{lib}")));
        elsewhere.truncate(5);
    }
    vec![FactKind::LibrarySearch {
        library: lib.to_string(),
        search_dirs: dirs,
        found,
        found_elsewhere: elsewhere,
    }]
}

fn find_file(
    dir: &Path,
    name: &str,
    depth: u32,
    budget: &mut usize,
    deadline: Instant,
    out: &mut Vec<String>,
) {
    if depth == 0 || *budget == 0 || Instant::now() >= deadline || out.len() >= 5 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        if *budget == 0 {
            return;
        }
        *budget -= 1;
        let Ok(ft) = e.file_type() else { continue };
        let p = e.path();
        if ft.is_dir() {
            let n = e.file_name();
            let n = n.to_string_lossy();
            if n.starts_with('.') || n == "node_modules" || n == "proc" || n == "target" {
                continue;
            }
            find_file(&p, name, depth - 1, budget, deadline, out);
        } else if e.file_name().to_string_lossy() == name {
            out.push(p.to_string_lossy().into_owned());
        }
    }
}

#[cfg(test)]
mod tests;
