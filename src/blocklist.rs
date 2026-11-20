use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, RwLock, Weak};
use std::time::{Duration, Instant, SystemTime};

use tracing::{info, warn};

pub type Set = HashSet<Box<str>>;
pub type Shared = Arc<RwLock<Arc<Set>>>;

/// Parse plain (`example.com`) and hosts-format (`0.0.0.0 example.com`) lines.
pub fn parse(text: &str, out: &mut Set) {
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("");
        let mut words = line.split_whitespace();
        let Some(first) = words.next() else { continue };
        if first.parse::<IpAddr>().is_ok() {
            // hosts format: skip `localhost`, `broadcasthost`, `0.0.0.0` and other dotless/IP names
            for w in words.filter(|w| w.contains('.') && w.parse::<IpAddr>().is_err()) {
                insert(out, w);
            }
        } else {
            insert(out, first);
        }
    }
}

fn insert(out: &mut Set, name: &str) {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if !name.is_empty() {
        out.insert(name.into());
    }
}

/// True if `name` (lowercase, no trailing dot) or any parent domain is listed.
pub fn is_blocked(set: &Set, mut name: &str) -> bool {
    loop {
        if set.contains(name) {
            return true;
        }
        match name.find('.') {
            Some(i) => name = &name[i + 1..],
            None => return false,
        }
    }
}

struct Source {
    loc: String,
    text: Option<String>,
    stamp: Option<SystemTime>, // file mtime
    fetched: Option<Instant>,  // url fetch time
}

impl Source {
    fn is_url(&self) -> bool {
        self.loc.starts_with("http://") || self.loc.starts_with("https://")
    }

    /// Returns true if the content changed. On failure the last good copy is kept.
    async fn refresh(&mut self, http: &reqwest::Client, refresh: Duration) -> bool {
        if self.is_url() {
            if self.fetched.is_some_and(|t| t.elapsed() < refresh) {
                return false;
            }
            self.fetched = Some(Instant::now());
            let res = async {
                http.get(&self.loc).send().await?.error_for_status()?.text().await
            };
            match res.await {
                Ok(t) if self.text.as_ref() != Some(&t) => self.text = Some(t),
                Ok(_) => return false,
                Err(e) => {
                    warn!(source = %self.loc, error = %e, "blocklist fetch failed");
                    return false;
                }
            }
        } else {
            let mtime = std::fs::metadata(&self.loc).and_then(|m| m.modified());
            match mtime {
                Ok(m) if self.stamp == Some(m) => return false,
                Ok(m) => match std::fs::read_to_string(&self.loc) {
                    Ok(t) => {
                        self.stamp = Some(m);
                        self.text = Some(t);
                    }
                    Err(e) => {
                        warn!(source = %self.loc, error = %e, "blocklist read failed");
                        return false;
                    }
                },
                Err(e) => {
                    if self.stamp.is_none() {
                        warn!(source = %self.loc, error = %e, "blocklist missing");
                    }
                    return false;
                }
            }
        }
        true
    }
}

pub struct Lists {
    sources: Vec<Source>,
    http: reqwest::Client,
}

impl Lists {
    pub fn new(locs: &[String]) -> Self {
        let sources = locs
            .iter()
            .map(|l| Source { loc: l.clone(), text: None, stamp: None, fetched: None })
            .collect();
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .expect("reqwest client");
        Self { sources, http }
    }

    /// Refresh every source; returns the merged set if anything changed.
    pub async fn refresh(&mut self, refresh: Duration) -> Option<Set> {
        let mut changed = false;
        for s in &mut self.sources {
            changed |= s.refresh(&self.http, refresh).await;
        }
        changed.then(|| {
            let mut set = Set::new();
            for t in self.sources.iter().filter_map(|s| s.text.as_deref()) {
                parse(t, &mut set);
            }
            set
        })
    }

    /// Poll for changes until the view that owns `target` is dropped (e.g. on reload).
    pub fn spawn(mut self, view: String, target: Weak<RwLock<Arc<Set>>>, poll: Duration, refresh: Duration) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(poll).await;
                let Some(target) = target.upgrade() else { return };
                if let Some(set) = self.refresh(refresh).await {
                    info!(view, entries = set.len(), "blocklist reloaded");
                    *target.write().unwrap() = Arc::new(set);
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(text: &str) -> Set {
        let mut s = Set::new();
        parse(text, &mut s);
        s
    }

    #[test]
    fn matching() {
        let s = set("Example.com.\n# comment\n\nads.tracker.net # trailing\n");
        assert!(is_blocked(&s, "example.com"));
        assert!(is_blocked(&s, "a.b.example.com"));
        assert!(is_blocked(&s, "x.ads.tracker.net"));
        assert!(!is_blocked(&s, "tracker.net"));
        assert!(!is_blocked(&s, "com"));
        assert!(!is_blocked(&s, "notexample.com"));
        assert!(!is_blocked(&s, ""));
    }

    #[test]
    fn hosts_format() {
        let s = set("127.0.0.1 localhost\n0.0.0.0 0.0.0.0\n::1 ip6-localhost\n0.0.0.0 bad.example a.bad.org\n");
        assert_eq!(s.len(), 2, "{s:?}");
        assert!(is_blocked(&s, "bad.example"));
        assert!(is_blocked(&s, "a.bad.org"));
    }
}
