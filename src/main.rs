mod blocklist;
mod config;

use std::sync::{Arc, RwLock};
use std::time::Duration;

use hickory_server::Server;
use hickory_server::net::runtime::Time;
use hickory_server::net::{DnsError, NetError};
use hickory_server::proto::op::{Edns, Metadata, MessageType, OpCode, ResponseCode};
use hickory_server::proto::rr::{Name, Record};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;
use tokio::net::{TcpListener, UdpSocket};
use tokio::signal::unix::{SignalKind, signal};
use tracing::{debug, error, info, warn};

use config::{Config, View};

type Views = Arc<RwLock<Arc<Vec<View>>>>;

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

struct Handler {
    views: Views,
}

impl Handler {
    async fn answer(&self, req: &Request) -> Answer {
        if req.metadata.message_type != MessageType::Query || req.metadata.op_code != OpCode::Query {
            return ResponseCode::NotImp.into();
        }
        let [q] = req.queries.queries() else {
            return ResponseCode::FormErr.into();
        };

        let src = req.src().ip().to_canonical();
        let views = self.views.read().unwrap().clone();
        let Some(view) = views.iter().find(|v| v.nets.iter().any(|n| n.contains(&src))) else {
            debug!(%src, "no view matches client");
            return ResponseCode::Refused.into();
        };

        let qname = q.name().to_string();
        let qname = qname.trim_end_matches('.');
        if blocklist::is_blocked(&view.blocklist.read().unwrap(), qname) {
            info!(view = view.name, %src, name = qname, "blocked");
            return ResponseCode::NXDomain.into();
        }

        match view.resolver.lookup(Name::from(q.name().clone()), q.query_type()).await {
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

#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler, T: Time>(&self, req: &Request, mut rh: R) -> ResponseInfo {
        let mut a = self.answer(req).await;

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
        let edns = req.edns.as_ref().map(|_| {
            let mut e = Edns::new();
            e.set_max_payload(1232).set_dnssec_ok(dnssec_ok);
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
                let mut h = Metadata::response_from_request(&req.metadata);
                h.response_code = ResponseCode::ServFail;
                hickory_server::proto::op::Header { metadata: h, counts: Default::default() }.into()
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                // per-query logs: RUST_LOG=info,hickory_server=info
                .unwrap_or_else(|_| "info,hickory_server=warn".into()),
        )
        .init();

    let path = std::env::args().nth(1).unwrap_or_else(|| "/etc/dns-cache/config.toml".into());
    let cfg = Config::load(&path)?;
    let views: Views = Arc::new(RwLock::new(Arc::new(cfg.build_views().await?)));

    let mut server = Server::new(Handler { views: views.clone() });
    for addr in &cfg.listen {
        server.register_socket(UdpSocket::bind(addr).await?);
        server.register_listener(TcpListener::bind(addr).await?, Duration::from_secs(10), 64);
        info!(%addr, "listening on udp+tcp");
    }

    // SIGHUP: rebuild all views from config; keep the old ones if the new config is bad.
    let mut hup = signal(SignalKind::hangup())?;
    tokio::spawn(async move {
        while hup.recv().await.is_some() {
            info!("SIGHUP: reloading {path}");
            let built = async {
                let new = Config::load(&path)?;
                if new.listen != cfg.listen {
                    warn!("listen addresses changed; restart to apply");
                }
                new.build_views().await
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
