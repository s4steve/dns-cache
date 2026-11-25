mod blocklist;
mod config;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use hickory_server::Server;
use hickory_server::net::runtime::Time;
use hickory_server::net::{DnsError, NetError};
use hickory_server::proto::op::{Edns, Header, Metadata, MessageType, OpCode, ResponseCode};
use hickory_server::proto::rr::{Name, Record};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;
use tokio::net::{TcpListener, UdpSocket};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use config::{Config, View};

type Views = Arc<RwLock<Arc<Vec<View>>>>;

/// Largest UDP response we send (DNS Flag Day 2020), and the smallest a client may ask for.
const MAX_UDP: u16 = 1232;
const MIN_UDP: u16 = 512;

#[derive(Default)]
struct Answer {
    code: ResponseCode,
    answers: Vec<Record>,
    authorities: Vec<Record>,
    additionals: Vec<Record>,
}

impl From<ResponseCode> for Answer {
    fn from(code: ResponseCode) -> Self {
        Self { code, ..Default::default() }
    }
}

/// Per-client queries per second, in fixed one-second windows.
// ponytail: one global mutex; shard by IP if it ever shows up in a profile.
struct RateLimiter {
    limit: u32,
    window: Mutex<(Instant, HashMap<IpAddr, u32>)>,
}

impl RateLimiter {
    /// Clients tracked per window. Past this (e.g. a spoofed-source flood), new clients are
    /// refused for the rest of the second rather than letting the map grow.
    const MAX_CLIENTS: usize = 100_000;

    fn new(limit: u32) -> Self {
        Self { limit, window: Mutex::new((Instant::now(), HashMap::new())) }
    }

    fn allow(&self, ip: IpAddr) -> bool {
        if self.limit == 0 {
            return true;
        }
        let mut w = self.window.lock().unwrap();
        if w.0.elapsed() >= Duration::from_secs(1) {
            *w = (Instant::now(), HashMap::new());
        }
        if w.1.len() >= Self::MAX_CLIENTS && !w.1.contains_key(&ip) {
            return false;
        }
        let n = w.1.entry(ip).or_default();
        *n = n.saturating_add(1);
        *n <= self.limit
    }
}

struct Handler {
    views: Views,
    limiter: RateLimiter,
    inflight: Semaphore,
}

impl Handler {
    async fn answer(&self, req: &Request, src: IpAddr) -> Answer {
        if req.metadata.message_type != MessageType::Query || req.metadata.op_code != OpCode::Query {
            return ResponseCode::NotImp.into();
        }
        let [q] = req.queries.queries() else {
            return ResponseCode::FormErr.into();
        };

        let views = self.views.read().unwrap().clone();
        let Some(view) = views.iter().find(|v| v.nets.iter().any(|n| n.contains(&src))) else {
            debug!(%src, "no view matches client");
            return ResponseCode::Refused.into();
        };

        // Punycode, lowercase: the form blocklist entries are normalised to.
        let name = Name::from(q.name().clone());
        let ascii = name.to_ascii();
        let qname = ascii.trim_end_matches('.');
        if blocklist::is_blocked(&view.blocklist.read().unwrap(), qname) {
            debug!(view = view.name, %src, name = qname, "blocked");
            return ResponseCode::NXDomain.into();
        }

        let Ok(_permit) = self.inflight.try_acquire() else {
            debug!(view = view.name, name = qname, "too many lookups in progress");
            return ResponseCode::ServFail.into();
        };
        let mut res = view.resolver.lookup(name.clone(), q.query_type()).await;
        // ponytail: hickory 0.26.3 keeps pooled upstream TCP/TLS connections the server has
        // already closed, and each failed lookup evicts only a few. After a burst of misses this
        // meant ~10 SERVFAILs in a row; retrying drains them. Drop when hickory fixes it.
        for _ in 0..16 {
            if !matches!(res, Err(NetError::NoConnections)) {
                break;
            }
            res = view.resolver.lookup(name.clone(), q.query_type()).await;
        }

        match res {
            Ok(l) => Answer {
                code: ResponseCode::NoError,
                answers: l.answers().to_vec(),
                authorities: l.authorities().to_vec(),
                additionals: l.additionals().to_vec(),
            },
            Err(NetError::Dns(DnsError::NoRecordsFound(nr))) => Answer {
                code: nr.response_code,
                authorities: nr.authorities.as_deref().unwrap_or_default().to_vec(),
                ..Default::default()
            },
            Err(NetError::Dns(DnsError::Nsec { response, .. })) => Answer {
                code: response.response_code,
                authorities: response.authorities.clone(),
                ..Default::default()
            },
            Err(e) => {
                warn!(view = view.name, name = qname, qtype = %q.query_type(), error = %e, "SERVFAIL");
                ResponseCode::ServFail.into()
            }
        }
    }
}

fn header_only(req: &Request, code: ResponseCode) -> ResponseInfo {
    let mut metadata = Metadata::response_from_request(&req.metadata);
    metadata.response_code = code;
    Header { metadata, counts: Default::default() }.into()
}

#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler, T: Time>(&self, req: &Request, mut rh: R) -> ResponseInfo {
        let src = req.src().ip().to_canonical();
        if !self.limiter.allow(src) {
            // Dropped, not answered: a reply would still feed a reflection attack.
            debug!(%src, "rate limited");
            return header_only(req, ResponseCode::Refused);
        }

        let mut a = self.answer(req, src).await;

        // RFC 4035 §3.2.1: only include DNSSEC records if the client set the DO bit.
        let dnssec_ok = req.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok);
        if !dnssec_ok {
            for rrs in [&mut a.answers, &mut a.authorities, &mut a.additionals] {
                rrs.retain(|r| !r.record_type().is_dnssec());
            }
        }

        let mut meta = Metadata::response_from_request(&req.metadata);
        meta.recursion_available = true; // never authoritative: `authoritative` stays false
        meta.response_code = a.code;
        // hickory truncates UDP responses to the size we advertise here, so never exceed
        // what the client said it can take.
        let edns = req.edns.as_ref().map(|client| {
            let mut e = Edns::new();
            e.set_max_payload(client.max_payload().clamp(MIN_UDP, MAX_UDP)).set_dnssec_ok(dnssec_ok);
            e
        });
        let resp = MessageResponseBuilder::new(&req.queries, edns.as_ref()).build(
            meta,
            &a.answers,
            &a.authorities,
            &[],
            &a.additionals,
        );
        match rh.send_response(resp).await {
            Ok(info) => info,
            Err(e) => {
                error!(error = %e, "failed to send response");
                header_only(req, ResponseCode::ServFail)
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                // per-query logs: RUST_LOG=info,hickory_server=info; blocked names: dns_cache=debug
                .unwrap_or_else(|_| "info,hickory_server=warn".into()),
        )
        .init();

    let path = std::env::args().nth(1).unwrap_or_else(|| "/etc/dns-cache/config.toml".into());
    let cfg = Config::load(&path)?;
    let views: Views = Arc::new(RwLock::new(Arc::new(cfg.build_views(&[]).await?)));

    let mut server = Server::new(Handler {
        views: views.clone(),
        limiter: RateLimiter::new(cfg.rate_limit),
        inflight: Semaphore::new(cfg.max_inflight),
    });
    for addr in &cfg.listen {
        server.register_socket(UdpSocket::bind(addr).await?);
        server.register_listener(TcpListener::bind(addr).await?, Duration::from_secs(10), 64);
        info!(%addr, "listening on udp+tcp");
    }

    // SIGHUP: rebuild views from config, keeping caches of views whose resolver settings are unchanged.
    // If the new config is bad, keep serving the old one.
    let mut hup = signal(SignalKind::hangup())?;
    tokio::spawn(async move {
        while hup.recv().await.is_some() {
            info!("SIGHUP: reloading {path}");
            let built = async {
                let new = Config::load(&path)?;
                if new.listen != cfg.listen || new.rate_limit != cfg.rate_limit || new.max_inflight != cfg.max_inflight {
                    warn!("listen, rate_limit and max_inflight changes need a restart");
                }
                let old = views.read().unwrap().clone();
                new.build_views(&old).await
            };
            match built.await {
                Ok(v) => {
                    *views.write().unwrap() = Arc::new(v);
                    info!("reload complete");
                }
                Err(e) => error!(error = %e, "reload failed; keeping previous config"),
            }
        }
    });

    let mut term = signal(SignalKind::terminate())?;
    tokio::select! {
        r = server.block_until_done() => r?,
        _ = term.recv() => info!("SIGTERM: shutting down"),
        _ = tokio::signal::ctrl_c() => info!("SIGINT: shutting down"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter() {
        let (a, b): (IpAddr, IpAddr) = ("10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap());
        let rl = RateLimiter::new(3);
        assert!((0..3).all(|_| rl.allow(a)));
        assert!(!rl.allow(a), "4th query in the same second is dropped");
        assert!(rl.allow(b), "other clients are unaffected");
        rl.window.lock().unwrap().0 -= Duration::from_secs(1);
        assert!(rl.allow(a), "new window resets the count");
        assert!((0..10).all(|_| RateLimiter::new(0).allow(a)), "0 disables");
    }
}
