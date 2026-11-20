use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use hickory_server::net::runtime::TokioRuntimeProvider;
use hickory_server::resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig};
use hickory_server::resolver::{Resolver, TokioResolver};
use ipnet::IpNet;
use serde::Deserialize;
use tracing::info;

use crate::blocklist::{self, Lists};

type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: Vec<SocketAddr>,
    /// How often local blocklist files are checked for changes.
    #[serde(default = "default_poll")]
    pub poll_secs: u64,
    /// How often remote (http/https) blocklists are re-downloaded.
    #[serde(default = "default_refresh")]
    pub refresh_secs: u64,
    #[serde(rename = "view")]
    pub views: Vec<ViewConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewConfig {
    pub name: String,
    pub match_clients: Vec<IpNet>,
    pub upstreams: Vec<Upstream>,
    #[serde(default = "yes")]
    pub dnssec: bool,
    pub cache_size: Option<u64>,
    #[serde(default)]
    pub blocklists: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub ip: IpAddr,
    /// Defaults to 53 (udp), 853 (tls) or 443 (https).
    pub port: Option<u16>,
    #[serde(default)]
    pub protocol: Protocol,
    /// TLS server name; required for tls/https.
    pub tls_name: Option<String>,
    /// DoH path; defaults to /dns-query.
    pub path: Option<String>,
}

#[derive(Deserialize, Default, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Udp, // with TCP fallback
    Tls,
    Https,
}

fn default_poll() -> u64 {
    30
}
fn default_refresh() -> u64 {
    86400
}
fn yes() -> bool {
    true
}

pub struct View {
    pub name: String,
    pub nets: Vec<IpNet>,
    pub resolver: TokioResolver,
    pub blocklist: blocklist::Shared,
}

impl Config {
    pub fn load(path: &str) -> Result<Self, Error> {
        let cfg: Config = toml::from_str(&std::fs::read_to_string(path)?)?;
        if cfg.views.is_empty() {
            return Err("config has no [[view]]".into());
        }
        for v in &cfg.views {
            if v.upstreams.is_empty() {
                return Err(format!("view {}: no upstreams", v.name).into());
            }
            for u in &v.upstreams {
                if !matches!(u.protocol, Protocol::Udp) && u.tls_name.is_none() {
                    return Err(format!("view {}: upstream {} needs tls_name", v.name, u.ip).into());
                }
            }
        }
        Ok(cfg)
    }

    /// Build every view, loading its blocklists before returning so nothing is served unfiltered.
    pub async fn build_views(&self) -> Result<Vec<View>, Error> {
        let (poll, refresh) = (Duration::from_secs(self.poll_secs), Duration::from_secs(self.refresh_secs));
        let mut views = Vec::new();
        for v in &self.views {
            let mut lists = Lists::new(&v.blocklists);
            let set = lists.refresh(refresh).await.unwrap_or_default();
            info!(view = v.name, entries = set.len(), "view ready");
            let blocklist = Arc::new(RwLock::new(Arc::new(set)));
            lists.spawn(v.name.clone(), Arc::downgrade(&blocklist), poll, refresh);
            views.push(View {
                name: v.name.clone(),
                nets: v.match_clients.clone(),
                resolver: resolver(v)?,
                blocklist,
            });
        }
        Ok(views)
    }
}

fn resolver(v: &ViewConfig) -> Result<TokioResolver, Error> {
    let servers = v
        .upstreams
        .iter()
        .map(|u| {
            let name = || Arc::<str>::from(u.tls_name.as_deref().unwrap_or_default());
            let mut ns = match u.protocol {
                Protocol::Udp => NameServerConfig::udp_and_tcp(u.ip),
                Protocol::Tls => NameServerConfig::tls(u.ip, name()),
                Protocol::Https => NameServerConfig::https(u.ip, name(), u.path.as_deref().map(Into::into)),
            };
            if let Some(port) = u.port {
                ns.connections.iter_mut().for_each(|c| c.port = port);
            }
            ns
        })
        .collect();

    let mut b = Resolver::builder_with_config(
        ResolverConfig::from_name_servers(servers),
        TokioRuntimeProvider::default(),
    );
    let o = b.options_mut();
    o.validate = v.dnssec;
    o.use_hosts_file = ResolveHosts::Never;
    o.preserve_intermediates = true; // keep CNAME chains in answers
    if let Some(n) = v.cache_size {
        o.cache_size = n;
    }
    Ok(b.build()?)
}
