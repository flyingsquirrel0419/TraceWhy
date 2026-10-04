//! Socket handling: connect/bind bookkeeping and DNS payload decoding.

use super::util::protocol_from;
use super::Normalizer;
use crate::args::{all_strings, parse_fd, parse_sockaddr, parse_socket_annotation, port_of, FdArg};
use crate::dns;
use crate::parse::{RawRecord, Syscall};
use tracewhy_event::{Endpoint, Errno, EventKind, Protocol};

impl Normalizer {
    pub(super) fn sock_protocol(&self, g: u32, fd: Option<&FdArg>) -> Protocol {
        if let Some(f) = fd {
            if let Some(ann) = &f.annotation {
                let p = protocol_from(ann, "");
                if p != Protocol::Other {
                    return p;
                }
            }
            if let Some(n) = f.fd {
                if let Some(p) = self.socks.get(&(g, n)).and_then(|s| s.protocol) {
                    return p;
                }
            }
        }
        Protocol::Other
    }

    pub(super) fn connect(
        &mut self,
        rec: &RawRecord,
        pid: u32,
        sc: &Syscall,
        args: &[&str],
        err: Option<Errno>,
    ) {
        let Some(endpoint) = args.get(1).and_then(|a| parse_sockaddr(a)) else {
            return;
        };
        let fdarg = args.first().and_then(|a| parse_fd(a));
        let g = self.group(pid);
        let mut protocol = self.sock_protocol(g, fdarg.as_ref());
        if protocol == Protocol::Other && matches!(endpoint, Endpoint::Unix { .. }) {
            protocol = Protocol::Unix;
        }
        let fd = fdarg.and_then(|f| f.fd);
        match err {
            None if sc.ret.value == Some(0) => {
                if let Some(fd) = fd {
                    let st = self.socks.entry((g, fd)).or_default();
                    st.peer = Some(endpoint.clone());
                    st.protocol.get_or_insert(protocol);
                }
                self.push(rec, EventKind::Connected { endpoint, protocol });
            }
            Some(e) if e.is("EINPROGRESS") || e.is("EAGAIN") => {
                if let Some(fd) = fd {
                    let st = self.socks.entry((g, fd)).or_default();
                    st.pending = Some(endpoint.clone());
                    st.protocol.get_or_insert(protocol);
                }
                self.push(rec, EventKind::ConnectPending { endpoint, protocol });
            }
            Some(e) if e.is("EINTR") || e.is("EALREADY") || e.is("EISCONN") => {}
            Some(error) => self.push(
                rec,
                EventKind::ConnectFailed {
                    endpoint,
                    protocol,
                    error,
                },
            ),
            None => {}
        }
    }

    pub(super) fn is_dns_fd(&self, pid: u32, fd: Option<&FdArg>) -> bool {
        let Some(f) = fd else { return false };
        if let Some(ann) = &f.annotation {
            if let Some((proto, _, Some(peer))) = parse_socket_annotation(ann) {
                if proto.starts_with("UDP") || proto.starts_with("TCP") {
                    return port_of(&peer) == Some(53);
                }
            }
        }
        f.fd.and_then(|n| self.socks.get(&(self.group(pid), n)))
            .and_then(|s| s.peer.as_ref())
            .and_then(|p| p.port())
            == Some(53)
    }

    pub(super) fn maybe_dns(&mut self, rec: &RawRecord, pid: u32, sc: &Syscall, args: &[&str]) {
        let fdarg = args.first().and_then(|a| parse_fd(a));
        let explicit_53 = sc.args.contains("htons(53)");
        if !explicit_53 && !self.is_dns_fd(pid, fdarg.as_ref()) {
            return;
        }
        if sc.ret.errno.is_some() {
            return;
        }
        let server = fdarg
            .and_then(|f| f.fd)
            .and_then(|n| self.socks.get(&(self.group(pid), n)))
            .and_then(|s| s.peer.clone());
        let mut seen = Vec::new();
        for buf in all_strings(&sc.args) {
            // TCP DNS prefixes a 2-byte length.
            let candidates: [&[u8]; 2] = [&buf, buf.get(2..).unwrap_or(&[])];
            for c in candidates {
                if let Some(m) = dns::decode(c) {
                    let key = (m.id, m.response);
                    if seen.contains(&key) {
                        break;
                    }
                    seen.push(key);
                    let kind = if m.response {
                        EventKind::DnsAnswer {
                            hostname: m.name,
                            qtype: m.qtype,
                            rcode: m.rcode,
                            addresses: m.addresses,
                        }
                    } else {
                        EventKind::DnsQuery {
                            hostname: m.name,
                            qtype: m.qtype,
                            server: server.clone(),
                        }
                    };
                    self.push(rec, kind);
                    break;
                }
            }
        }
    }
}
