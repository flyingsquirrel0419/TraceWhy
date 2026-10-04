//! Thin, safe wrappers around the few libc calls investigators need.

use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracewhy_core::FactKind;

/// `access(2)` as the current user.
pub fn access(path: &str, mode: libc::c_int) -> bool {
    let Ok(c) = CString::new(path) else {
        return false;
    };
    // SAFETY: `c` is a valid NUL-terminated string for the duration of the call.
    unsafe { libc::access(c.as_ptr(), mode) == 0 }
}

pub struct Vfs {
    pub total_bytes: u64,
    pub avail_bytes: u64,
    pub total_inodes: u64,
    pub free_inodes: u64,
    pub read_only: bool,
    pub noexec: bool,
}

pub fn statvfs(path: &str) -> Option<Vfs> {
    let c = CString::new(path).ok()?;
    // SAFETY: zeroed statvfs is a valid out-parameter; `c` outlives the call.
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c.as_ptr(), &mut s) };
    if rc != 0 {
        return None;
    }
    let frsize = if s.f_frsize > 0 {
        s.f_frsize
    } else {
        s.f_bsize
    } as u64;
    Some(Vfs {
        total_bytes: (s.f_blocks as u64).saturating_mul(frsize),
        avail_bytes: (s.f_bavail as u64).saturating_mul(frsize),
        total_inodes: s.f_files as u64,
        free_inodes: s.f_favail as u64,
        read_only: s.f_flag & libc::ST_RDONLY != 0,
        noexec: s.f_flag & libc::ST_NOEXEC != 0,
    })
}

/// `uname -m`.
pub fn machine() -> Option<String> {
    // SAFETY: zeroed utsname is a valid out-parameter.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut u) } != 0 {
        return None;
    }
    let bytes: Vec<u8> = u
        .machine
        .iter()
        .take_while(|c| **c != 0)
        // c_char is i8 on x86_64 and u8 on aarch64.
        .map(|c| u8::from_ne_bytes(c.to_ne_bytes()))
        .collect();
    String::from_utf8(bytes).ok()
}

pub fn nofile_limit() -> Option<(u64, u64)> {
    // SAFETY: zeroed rlimit is a valid out-parameter.
    let mut r: libc::rlimit = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut r) } != 0 {
        return None;
    }
    Some((r.rlim_cur as u64, r.rlim_max as u64))
}

/// Addresses assigned to local interfaces.
pub fn local_addresses() -> Vec<IpAddr> {
    let mut out = Vec::new();
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs allocates a list we walk read-only and then free.
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return out;
    }
    let mut cur = ifap;
    while !cur.is_null() {
        // SAFETY: `cur` is a valid node of the list returned by getifaddrs.
        let ifa = unsafe { &*cur };
        if !ifa.ifa_addr.is_null() {
            // SAFETY: ifa_addr points to a sockaddr whose family tells its real type.
            let family = i32::from(unsafe { (*ifa.ifa_addr).sa_family });
            if family == libc::AF_INET {
                let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                out.push(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    sin.sin_addr.s_addr,
                ))));
            } else if family == libc::AF_INET6 {
                let sin6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                out.push(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)));
            }
        }
        cur = ifa.ifa_next;
    }
    // SAFETY: freeing the list obtained above exactly once.
    unsafe { libc::freeifaddrs(ifap) };
    out.sort();
    out.dedup();
    out
}

/// User name for a uid, from /etc/passwd.
pub fn user_name(uid: u32) -> Option<String> {
    let text = std::fs::read_to_string("/etc/passwd").ok()?;
    text.lines().find_map(|l| {
        let mut it = l.split(':');
        let name = it.next()?;
        let _pw = it.next()?;
        let id: u32 = it.next()?.parse().ok()?;
        (id == uid).then(|| name.to_string())
    })
}

/// `name (uid N)` of the effective user.
pub fn current_user() -> String {
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    match user_name(uid) {
        Some(n) => format!("{n} (uid {uid})"),
        None => format!("uid {uid}"),
    }
}

/// Privilege facts for the current process (inherited by the traced command
/// unless it is a setuid or file-capability binary).
pub fn privileges(executable: Option<&str>) -> Vec<FactKind> {
    let mut out = vec![FactKind::Property {
        key: "privileges.user".into(),
        subject: "current".into(),
        value: current_user(),
        description: format!("The command ran as {}", current_user()),
    }];
    let cap_eff = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("CapEff:"))
                .and_then(|l| u64::from_str_radix(l.split_whitespace().nth(1)?, 16).ok())
        });
    if let Some(caps) = cap_eff {
        // CAP_NET_BIND_SERVICE is capability bit 10.
        let has = caps & (1 << 10) != 0;
        out.push(FactKind::Property {
            key: "privileges.cap_net_bind_service".into(),
            subject: "current".into(),
            value: has.to_string(),
            description: if has {
                "The process has CAP_NET_BIND_SERVICE".into()
            } else {
                "The process lacks CAP_NET_BIND_SERVICE".into()
            },
        });
    }
    if let Some(exe) = executable {
        if has_file_capabilities(exe) {
            out.push(FactKind::Property {
                key: "privileges.file_capabilities".into(),
                subject: "current".into(),
                value: exe.to_string(),
                description: format!("{exe} has file capabilities (set with setcap)"),
            });
        }
    }
    if let Ok(v) = std::fs::read_to_string("/proc/sys/net/ipv4/ip_unprivileged_port_start") {
        let v = v.trim().to_string();
        out.push(FactKind::Property {
            key: "privileges.unprivileged_port_start".into(),
            subject: "current".into(),
            description: format!(
                "Ports below {v} require privileges (net.ipv4.ip_unprivileged_port_start)"
            ),
            value: v,
        });
    }
    out
}

/// Whether `path` carries a `security.capability` extended attribute.
pub fn has_file_capabilities(path: &str) -> bool {
    let (Ok(p), Ok(name)) = (CString::new(path), CString::new("security.capability")) else {
        return false;
    };
    // SAFETY: valid C strings; a null buffer with size 0 only queries the length.
    let n = unsafe { libc::getxattr(p.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
    n > 0
}
