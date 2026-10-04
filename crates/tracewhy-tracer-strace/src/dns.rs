//! Minimal DNS wire-format decoder for packets captured in syscall buffers.
//!
//! Only what TraceWhy needs: the question name/type and, for responses, the
//! response code and A/AAAA answers. All reads are bounds-checked; truncated
//! packets decode as far as possible.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracewhy_event::DnsRcode;

#[derive(Debug, Clone, PartialEq)]
pub struct DnsMessage {
    pub id: u16,
    pub response: bool,
    pub rcode: DnsRcode,
    pub name: String,
    pub qtype: String,
    pub addresses: Vec<IpAddr>,
}

pub fn decode(buf: &[u8]) -> Option<DnsMessage> {
    if buf.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qd = u16::from_be_bytes([buf[4], buf[5]]);
    let an = u16::from_be_bytes([buf[6], buf[7]]);
    let opcode = (flags >> 11) & 0xf;
    if qd != 1 || opcode != 0 {
        return None;
    }
    let response = flags & 0x8000 != 0;
    let rcode = DnsRcode::from_code((flags & 0xf) as u8);
    let (name, mut pos) = read_name(buf, 12)?;
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_graphic()) {
        return None;
    }
    let qtype_n = u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]);
    pos += 4;
    let qtype = match qtype_n {
        1 => "A".to_string(),
        28 => "AAAA".to_string(),
        5 => "CNAME".to_string(),
        15 => "MX".to_string(),
        16 => "TXT".to_string(),
        33 => "SRV".to_string(),
        65 => "HTTPS".to_string(),
        n => format!("TYPE{n}"),
    };
    let mut addresses = Vec::new();
    if response {
        for _ in 0..an {
            let Some((_, p)) = read_name(buf, pos) else {
                break;
            };
            let Some(hdr) = buf.get(p..p + 10) else { break };
            let rtype = u16::from_be_bytes([hdr[0], hdr[1]]);
            let rdlen = usize::from(u16::from_be_bytes([hdr[8], hdr[9]]));
            let start = p + 10;
            let Some(rdata) = buf.get(start..start + rdlen) else {
                break;
            };
            match (rtype, rdlen) {
                (1, 4) => addresses.push(IpAddr::V4(Ipv4Addr::new(
                    rdata[0], rdata[1], rdata[2], rdata[3],
                ))),
                (28, 16) => {
                    let mut o = [0u8; 16];
                    o.copy_from_slice(rdata);
                    addresses.push(IpAddr::V6(Ipv6Addr::from(o)));
                }
                _ => {}
            }
            pos = start + rdlen;
        }
    }
    Some(DnsMessage {
        id,
        response,
        rcode,
        name,
        qtype,
        addresses,
    })
}

fn read_name(buf: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut end_pos = None;
    let mut jumps = 0;
    loop {
        let len = *buf.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xc0 == 0xc0 {
            let ptr = ((len & 0x3f) << 8) | (*buf.get(pos + 1)? as usize);
            if end_pos.is_none() {
                end_pos = Some(pos + 2);
            }
            jumps += 1;
            if jumps > 16 || ptr >= buf.len() {
                return None;
            }
            pos = ptr;
            continue;
        }
        if len > 63 {
            return None;
        }
        let label = buf.get(pos + 1..pos + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos += 1 + len;
        if labels.len() > 127 {
            return None;
        }
    }
    Some((labels.join("."), end_pos.unwrap_or(pos)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::unescape;

    #[test]
    fn decodes_query_and_nxdomain() {
        let q =
            unescape(r"\366\301\1 \0\1\0\0\0\0\0\1\2db\7invalid\0\0\1\0\1\0\0)\4\260\0\0\0\0\0\0");
        let m = decode(&q).unwrap();
        assert!(!m.response);
        assert_eq!(m.name, "db.invalid");
        assert_eq!(m.qtype, "A");
        let r = unescape(
            r"\366\301\205\243\0\1\0\0\0\0\0\1\2db\7invalid\0\0\1\0\1\0\0)\377\326\0\0\0\0\0\0",
        );
        let m = decode(&r).unwrap();
        assert!(m.response);
        assert_eq!(m.rcode, DnsRcode::NxDomain);
    }

    #[test]
    fn decodes_answers_with_compression() {
        let mut p = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        p.extend_from_slice(b"\x02db\x08internal\x00\x00\x01\x00\x01");
        p.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 4]);
        let m = decode(&p).unwrap();
        assert_eq!(m.name, "db.internal");
        assert_eq!(m.rcode, DnsRcode::NoError);
        assert_eq!(m.addresses, vec!["10.0.0.4".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn rejects_garbage() {
        assert!(decode(b"").is_none());
        assert!(decode(b"hello world, this is not dns").is_none());
        let mut p = vec![0, 0, 0x81, 0x80, 0, 1, 0, 5, 0, 0, 0, 0, 0xc0, 12];
        p.extend_from_slice(&[0; 4]);
        let _ = decode(&p);
    }
}
