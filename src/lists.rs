//! Loading of list-like files and URLs (blocklists, allowlists, local records): polling,
//! size caps, and one shared parsed copy per source. Plus the domain-set format itself.

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::collections::HashSet;
use std::io::Read;
use std::net::IpAddr;
use std::sync::{Arc, LazyLock, Mutex, RwLock, Weak};
use std::time::{Duration, Instant, SystemTime};

use hickory_server::proto::rr::Name;
use tracing::{info, warn};

/// Something a list source parses into.
pub trait Parsed: Any + Send + Sync + Sized {
    const KIND: &'static str; // for logs
    fn parse(text: &str) -> Self;
    fn len(&self) -> usize;
}

/// One parsed value per source, in config order. Sources are shared between views, never merged.
pub type Loaded<T> = Arc<Vec<Arc<T>>>;
pub type Shared<T> = Arc<RwLock<Loaded<T>>>;

/// Domain names; a name also covers its subdomains. Used for blocklists and allowlists.
pub type Set = HashSet<Box<str>>;

impl Parsed for Set {
    const KIND: &'static str = "domain list";
    fn parse(text: &str) -> Self {
        let mut set = Set::new();
        parse(text, &mut set);
        set
    }
    fn len(&self) -> usize {
        HashSet::len(self)
    }
}

/// Larger downloads or files are rejected (the last good copy is kept).
const MAX_LIST_BYTES: u64 = 100 << 20;

/// Lowercase, no trailing dot, internationalised labels in punycode (`xn--…`), the form
/// `Name::to_ascii` gives query names. `None` for empty or unparseable names.
pub fn normalize(name: &str) -> Option<String> {
    let name = name.trim_end_matches('.');
    let ascii = if name.is_ascii() {
        name.to_ascii_lowercase()
    } else {
        Name::from_utf8(name).ok()?.to_ascii().trim_end_matches('.').to_ascii_lowercase()
    };
    (!ascii.is_empty()).then_some(ascii)
}

/// Parse plain (`example.com`) and hosts-format (`0.0.0.0 example.com`) lines.
pub fn parse(text: &str, out: &mut Set) {
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("");
        let mut words = line.split_whitespace();
        let Some(first) = words.next() else { continue };
        let names: Vec<&str> = if first.parse::<IpAddr>().is_ok() {
            // hosts format: skip `localhost`, `broadcasthost`, `0.0.0.0` and other dotless/IP names
            words.filter(|w| w.contains('.') && w.parse::<IpAddr>().is_err()).collect()
        } else {
            vec![first]
        };
        out.extend(names.into_iter().filter_map(normalize).map(Into::into));
    }
}

/// True if `name` (as from `normalize`) or any parent domain is in any of the sets.
pub fn contains(sets: &[Arc<Set>], mut name: &str) -> bool {
    loop {
        if sets.iter().any(|s| s.contains(name)) {
            return true;
        }
        match name.find('.') {
            Some(i) => name = &name[i + 1..],
            None => return false,
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Stamp {
    Modified(SystemTime), // local file mtime
    Fetched(Instant),     // url download time
}

/// Most recent load of each source, so views (and reloads) sharing a source share one copy
/// and one download. Weak, so a source dropped from the config is freed.
type AnyWeak = Weak<dyn Any + Send + Sync>;
static LOADED: LazyLock<Mutex<HashMap<(TypeId, String), (Stamp, AnyWeak)>>> = LazyLock::new(Default::default);

static HTTP: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::custom(|a| {
            if a.url().scheme() != "https" && a.previous().iter().any(|u| u.scheme() == "https") {
                a.error("refusing redirect from https to http")
            } else if a.previous().len() > 5 {
                a.error("too many redirects")
            } else {
                a.follow()
            }
        }))
        .build()
        .expect("reqwest client")
});

type Error = Box<dyn std::error::Error + Send + Sync>;

async fn download(url: &str) -> Result<String, Error> {
    let mut resp = HTTP.get(url).send().await?.error_for_status()?;
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if (body.len() + chunk.len()) as u64 > MAX_LIST_BYTES {
            return Err(format!("larger than {MAX_LIST_BYTES} bytes").into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

fn read_file(path: &str) -> Result<String, Error> {
    let mut text = String::new();
    std::fs::File::open(path)?.take(MAX_LIST_BYTES + 1).read_to_string(&mut text)?;
    if text.len() as u64 > MAX_LIST_BYTES {
        return Err(format!("larger than {MAX_LIST_BYTES} bytes").into());
    }
    Ok(text)
}

struct Source<T> {
    loc: String,
    set: Option<Arc<T>>,
    stamp: Option<Stamp>,
    retry_at: Option<Instant>, // after a failed download
}

impl<T: Parsed> Source<T> {
    fn is_url(&self) -> bool {
        self.loc.starts_with("http://") || self.loc.starts_with("https://")
    }

    /// Returns true if the set changed. On failure the last good copy is kept.
    async fn refresh(&mut self, refresh: Duration) -> bool {
        let current = if self.is_url() {
            if matches!(self.stamp, Some(Stamp::Fetched(t)) if t.elapsed() < refresh)
                || self.retry_at.is_some_and(|t| Instant::now() < t)
            {
                return false;
            }
            None // any download still within `refresh` is current
        } else {
            match std::fs::metadata(&self.loc).and_then(|m| m.modified()) {
                Ok(m) if self.stamp == Some(Stamp::Modified(m)) => return false,
                Ok(m) => Some(Stamp::Modified(m)),
                Err(e) => {
                    if self.stamp.is_none() {
                        warn!(kind = T::KIND, source = %self.loc, error = %e, "list missing");
                    }
                    return false;
                }
            }
        };

        // Reuse another view's (or the previous config's) copy if it is current.
        let key = (TypeId::of::<T>(), self.loc.clone());
        let shared = LOADED.lock().unwrap().get(&key).and_then(|(stamp, set)| {
            let fresh = match (current, *stamp) {
                (None, Stamp::Fetched(t)) => t.elapsed() < refresh,
                (Some(c), s) => c == s,
                _ => false,
            };
            let set = set.upgrade().filter(|_| fresh)?.downcast::<T>().ok()?;
            Some((*stamp, set))
        });
        let (stamp, set) = match shared {
            Some(s) => s,
            None => {
                let (stamp, text) = match current {
                    Some(m) => (m, read_file(&self.loc)),
                    None => (Stamp::Fetched(Instant::now()), download(&self.loc).await),
                };
                let text = match text {
                    Ok(t) => t,
                    Err(e) => {
                        // The last good copy stays in use. Files are retried when they change,
                        // downloads after a back-off (so an oversized list isn't re-fetched every poll).
                        warn!(kind = T::KIND, source = %self.loc, error = %e, "list load failed");
                        match current {
                            Some(m) => self.stamp = Some(m),
                            None => self.retry_at = Some(Instant::now() + refresh.min(Duration::from_secs(300))),
                        }
                        return false;
                    }
                };
                let set = Arc::new(T::parse(&text));
                let weak: AnyWeak = Arc::downgrade(&set) as Weak<T>;
                LOADED.lock().unwrap().insert(key, (stamp, weak));
                (stamp, set)
            }
        };
        self.stamp = Some(stamp);
        self.retry_at = None;
        let changed = !self.set.as_ref().is_some_and(|old| Arc::ptr_eq(old, &set));
        self.set = Some(set);
        changed
    }
}

pub struct Lists<T> {
    sources: Vec<Source<T>>,
}

impl<T: Parsed> Lists<T> {
    pub fn new(locs: &[String]) -> Self {
        for l in locs.iter().filter(|l| l.starts_with("http://")) {
            warn!(kind = T::KIND, source = %l, "list over plain http can be altered in transit; prefer https");
        }
        let sources = locs.iter().map(|l| Source { loc: l.clone(), set: None, stamp: None, retry_at: None }).collect();
        Self { sources }
    }

    /// Refresh every source; returns the current sets if anything changed.
    pub async fn refresh(&mut self, refresh: Duration) -> Option<Loaded<T>> {
        let mut changed = false;
        for s in &mut self.sources {
            changed |= s.refresh(refresh).await;
        }
        changed.then(|| Arc::new(self.sources.iter().filter_map(|s| s.set.clone()).collect()))
    }

    /// Poll for changes until the view that owns `target` is dropped (e.g. on reload).
    pub fn spawn(mut self, view: String, target: Weak<RwLock<Loaded<T>>>, poll: Duration, refresh: Duration) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(poll).await;
                let Some(target) = target.upgrade() else { return };
                if let Some(sets) = self.refresh(refresh).await {
                    info!(view, kind = T::KIND, entries = count(&sets), "list reloaded");
                    *target.write().unwrap() = sets;
                }
            }
        });
    }
}

pub fn count<T: Parsed>(sets: &[Arc<T>]) -> usize {
    sets.iter().map(|s| s.len()).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sets(text: &str) -> Vec<Arc<Set>> {
        let mut s = Set::new();
        parse(text, &mut s);
        vec![Arc::new(s)]
    }

    #[test]
    fn matching() {
        let s = sets("Example.com.\n# comment\n\nads.tracker.net # trailing\n");
        assert!(contains(&s, "example.com"));
        assert!(contains(&s, "a.b.example.com"));
        assert!(contains(&s, "x.ads.tracker.net"));
        assert!(!contains(&s, "tracker.net"));
        assert!(!contains(&s, "com"));
        assert!(!contains(&s, "notexample.com"));
        assert!(!contains(&s, ""));
    }

    #[test]
    fn hosts_format() {
        let s = sets("127.0.0.1 localhost\n0.0.0.0 0.0.0.0\n::1 ip6-localhost\n0.0.0.0 bad.example a.bad.org\n");
        assert_eq!(count(&s), 2, "{s:?}");
        assert!(contains(&s, "bad.example"));
        assert!(contains(&s, "a.bad.org"));
    }

    #[test]
    fn idn_entries_match_punycode_queries() {
        // Lists store IDNs either way; queries arrive as punycode.
        let s = sets("xn--bcher-kva.example\nBücher2.example\n");
        assert!(contains(&s, "xn--bcher-kva.example"));
        assert!(contains(&s, "www.xn--bcher2-3ya.example"));
        assert_eq!(normalize("Bücher.Example.").as_deref(), Some("xn--bcher-kva.example"));
        // What the server matches is Name::to_ascii of the query.
        let q = Name::from_utf8("www.bücher.example.").unwrap().to_ascii();
        assert!(contains(&sets("bücher.example"), q.trim_end_matches('.')));
    }
}
