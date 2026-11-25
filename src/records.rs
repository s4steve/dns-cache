//! Local records ("synthetic answers"): names answered from your own files instead of upstream.
//!
//! ```text
//! nas.home      A      192.168.1.10
//! nas.home      AAAA   fd00::10
//! www.home      CNAME  nas.home
//! nas.home      TXT    "any text"
//! 192.168.1.11  printer.home printer.lan     # hosts-style shorthand for A/AAAA
//! ```
//! PTR records are generated for every address; the first name listed for an address wins.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use hickory_server::proto::rr::rdata::{A, AAAA, CNAME, PTR, TXT};
use hickory_server::proto::rr::{Name, RData, Record, RecordType};
use tracing::warn;

use crate::lists::{Parsed, normalize};

// ponytail: one TTL for every local record; add a per-line TTL if anyone needs to tune it.
pub const TTL: u32 = 300;
const MAX_CHAIN: usize = 8;

/// Records by normalised owner name, in file order.
#[derive(Default)]
pub struct Records(HashMap<Box<str>, Vec<Record>>);

/// Answer for a name that has local records.
pub enum Local {
    /// Records of the requested type; empty means the name exists but has no such record (NODATA).
    Done(Vec<Record>),
    /// A CNAME chain whose target isn't local: resolve the target upstream and append.
    Upstream(Vec<Record>, Name),
    /// CNAMEs pointing at each other.
    Loop,
}

impl Parsed for Records {
    const KIND: &'static str = "records";

    fn parse(text: &str) -> Self {
        let mut r = Records::default();
        let mut addrs = Vec::new();
        for (i, line) in text.lines().enumerate() {
            if let Err(e) = r.parse_line(line, &mut addrs) {
                warn!(line = i + 1, error = %e, text = line.trim(), "skipping record");
            }
        }
        for (key, rrs) in &mut r.0 {
            if rrs.iter().any(|rr| rr.record_type() == RecordType::CNAME) && rrs.len() > 1 {
                warn!(name = %key, "a CNAME can't share its name with other records; keeping only the CNAME");
                let first = rrs.iter().position(|rr| rr.record_type() == RecordType::CNAME).unwrap();
                rrs.swap(0, first);
                rrs.truncate(1);
            }
        }
        for (ip, name) in addrs {
            let rev = Name::from(ip);
            let key: Box<str> = normalize(&rev.to_ascii()).unwrap_or_default().into();
            r.0.entry(key).or_insert_with(|| vec![Record::from_rdata(rev, TTL, RData::PTR(PTR(name)))]);
        }
        r
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

/// First word of `s` and the rest, trimmed.
fn word(s: &str) -> (&str, &str) {
    let s = s.trim_start();
    let end = s.find(char::is_whitespace).unwrap_or(s.len());
    (&s[..end], s[end..].trim_start())
}

fn owner(s: &str) -> Result<(Box<str>, Name), String> {
    let key = normalize(s).ok_or_else(|| format!("bad name {s:?}"))?;
    let mut name = Name::from_ascii(&key).map_err(|e| format!("bad name {s:?}: {e}"))?;
    name.set_fqdn(true);
    Ok((key.into(), name))
}

impl Records {
    fn add(&mut self, key: Box<str>, name: Name, data: RData) {
        self.0.entry(key).or_default().push(Record::from_rdata(name, TTL, data));
    }

    fn add_addr(&mut self, s: &str, ip: IpAddr, addrs: &mut Vec<(IpAddr, Name)>) -> Result<(), String> {
        let (key, name) = owner(s)?;
        addrs.push((ip, name.clone()));
        let data = match ip {
            IpAddr::V4(v4) => RData::A(A(v4)),
            IpAddr::V6(v6) => RData::AAAA(AAAA(v6)),
        };
        self.add(key, name, data);
        Ok(())
    }

    fn parse_line(&mut self, line: &str, addrs: &mut Vec<(IpAddr, Name)>) -> Result<(), String> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return Ok(());
        }
        let (first, rest) = word(line);
        let uncommented = |s: &str| s.split('#').next().unwrap_or("").trim().to_string();

        if let Ok(ip) = first.parse::<IpAddr>() {
            let names = uncommented(rest);
            if names.is_empty() {
                return Err("address with no names".into());
            }
            return names.split_whitespace().try_for_each(|n| self.add_addr(n, ip, addrs));
        }

        let (rtype, value) = word(rest);
        let bad = |e: &dyn std::fmt::Display| format!("bad {rtype} value: {e}");
        match rtype.to_ascii_uppercase().as_str() {
            "A" => {
                let ip: Ipv4Addr = uncommented(value).parse().map_err(|e| bad(&e))?;
                self.add_addr(first, ip.into(), addrs)
            }
            "AAAA" => {
                let ip: Ipv6Addr = uncommented(value).parse().map_err(|e| bad(&e))?;
                self.add_addr(first, ip.into(), addrs)
            }
            "CNAME" => {
                let (key, name) = owner(first)?;
                let (_, target) = owner(&uncommented(value)).map_err(|e| bad(&e))?;
                self.add(key, name, RData::CNAME(CNAME(target)));
                Ok(())
            }
            "TXT" => {
                // Everything after TXT is the text (no comment stripping); one pair of quotes is optional.
                let v = value.trim();
                let text = v.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(v);
                if text.is_empty() || text.len() > 255 {
                    return Err("TXT text must be 1-255 bytes".into());
                }
                let (key, name) = owner(first)?;
                self.add(key, name, RData::TXT(TXT::new(vec![text.to_string()])));
                Ok(())
            }
            "" => Err("missing record type".into()),
            t => Err(format!("unsupported record type {t} (use A, AAAA, CNAME or TXT)")),
        }
    }
}

fn renamed(rr: &Record, name: &Name) -> Record {
    let mut rr = rr.clone();
    rr.name = name.clone();
    rr
}

/// Look `qname` (normalised) up in the sources, first source that has the name wins.
/// `None` if the name isn't local. The first answer records are renamed to `query`, the
/// name exactly as the client asked for it.
pub fn lookup(sources: &[Arc<Records>], query: &Name, qname: &str, qtype: RecordType) -> Option<Local> {
    let find = |key: &str| sources.iter().find_map(|s| s.0.get(key));
    let mut rrs = find(qname)?;
    let mut out: Vec<Record> = Vec::new();
    let mut owner = query.clone();
    for _ in 0..MAX_CHAIN {
        let matches = |rr: &&Record| qtype == RecordType::ANY || rr.record_type() == qtype;
        let cname = rrs.iter().find_map(|rr| match &rr.data {
            RData::CNAME(CNAME(t)) if qtype != RecordType::CNAME => Some((rr, t)),
            _ => None,
        });
        let Some((rr, target)) = cname else {
            out.extend(rrs.iter().filter(matches).map(|rr| renamed(rr, &owner)));
            return Some(Local::Done(out));
        };
        out.push(renamed(rr, &owner));
        owner = target.clone();
        match normalize(&target.to_ascii()).and_then(|k| find(&k)) {
            Some(next) => rrs = next,
            None => return Some(Local::Upstream(out, target.clone())),
        }
    }
    Some(Local::Loop)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = r#"
# comment
nas.home      A      192.168.1.10
NAS.home.     AAAA   fd00::10        # trailing comment
www.home      CNAME  nas.home
cdn.home      CNAME  example.com
loop1.home    CNAME  loop2.home
loop2.home    CNAME  loop1.home
note.home     TXT    "hello # not a comment"
192.168.1.11  printer.home printer.lan
192.168.1.10  other.home
bücher.home   A      10.0.0.1
bad.home      MX     10 mail.home
"#;

    fn q(name: &str, t: RecordType) -> Option<Local> {
        let recs = vec![Arc::new(Records::parse(FILE))];
        let query = Name::from_ascii(name).unwrap(); // keeps case, like a wire query
        lookup(&recs, &query, &normalize(&query.to_ascii()).unwrap(), t)
    }

    fn done(l: Option<Local>) -> Vec<String> {
        match l {
            Some(Local::Done(rrs)) => rrs.iter().map(|r| format!("{} {}", r.name.to_ascii(), r.data)).collect(),
            _ => panic!("expected local answer"),
        }
    }

    #[test]
    fn answers() {
        assert_eq!(done(q("NAS.Home", RecordType::A)), ["NAS.Home 192.168.1.10"]);
        assert_eq!(done(q("nas.home", RecordType::AAAA)), ["nas.home fd00::10"]);
        assert!(done(q("nas.home", RecordType::MX)).is_empty(), "local name, no MX: NODATA");
        assert_eq!(done(q("printer.lan", RecordType::A)), ["printer.lan 192.168.1.11"]);
        assert_eq!(done(q("www.home", RecordType::A)), ["www.home nas.home.", "nas.home. 192.168.1.10"]);
        assert_eq!(done(q("www.home", RecordType::CNAME)), ["www.home nas.home."]);
        assert_eq!(done(q("note.home", RecordType::TXT)), ["note.home hello # not a comment"]);
        assert_eq!(done(q("xn--bcher-kva.home", RecordType::A)), ["xn--bcher-kva.home 10.0.0.1"]);
        assert!(q("unknown.home", RecordType::A).is_none());
        assert!(q("bad.home", RecordType::MX).is_none(), "unsupported line skipped");
    }

    #[test]
    fn ptr_first_name_wins() {
        assert_eq!(done(q("10.1.168.192.in-addr.arpa", RecordType::PTR)), ["10.1.168.192.in-addr.arpa nas.home."]);
        let v6 = Name::from(IpAddr::from("fd00::10".parse::<Ipv6Addr>().unwrap())).to_ascii();
        assert_eq!(done(q(&v6, RecordType::PTR)).len(), 1);
    }

    #[test]
    fn chains() {
        match q("cdn.home", RecordType::A) {
            Some(Local::Upstream(chain, target)) => {
                assert_eq!(chain.len(), 1);
                assert_eq!(target.to_ascii(), "example.com.");
            }
            _ => panic!("expected upstream continuation"),
        }
        assert!(matches!(q("loop1.home", RecordType::A), Some(Local::Loop)));
    }
}
