use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(serde::Deserialize, Debug)]
struct DohAnswer {
    #[serde(rename = "type")]
    type_id: u16,
    data: String,
}

#[derive(serde::Deserialize, Debug)]
struct DohResponse {
    #[serde(rename = "Status")]
    status: i32,
    #[serde(rename = "Answer")]
    answer: Option<Vec<DohAnswer>>,
}

pub struct DohResolver {
    client: reqwest::Client,
    doh_url: String,
    cache: Arc<RwLock<HashMap<String, IpAddr>>>,
}

impl DohResolver {
    pub fn new(doh_url: &str) -> Self {
        Self {
            client: reqwest::Client::builder()
                .danger_accept_invalid_certs(false)
                .build()
                .unwrap_or_default(),
            doh_url: doh_url.to_string(),
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Resolves a domain hostname to an IP address using DoH (JSON API format).
    pub async fn resolve(&self, domain: &str) -> Option<IpAddr> {
        // Check cache first
        {
            let cache_read = self.cache.read().await;
            if let Some(ip) = cache_read.get(domain) {
                return Some(*ip);
            }
        }

        // Fast path: if domain is already an IP address string
        if let Ok(ip) = domain.parse::<IpAddr>() {
            return Some(ip);
        }

        // Query DoH provider (e.g. Google DoH)
        let url = format!("{}?name={}&type=A", self.doh_url, domain);
        tracing::debug!("DoH resolving: {} via {}", domain, self.doh_url);

        match self.client.get(&url).header("accept", "application/dns-json").send().await {
            Ok(resp) => {
                if let Ok(doh_json) = resp.json::<DohResponse>().await {
                    if doh_json.status == 0 {
                        if let Some(answers) = doh_json.answer {
                            for ans in answers {
                                if ans.type_id == 1 { // Type A record
                                    if let Ok(ip) = ans.data.parse::<IpAddr>() {
                                        tracing::debug!("DoH resolved {} -> {}", domain, ip);
                                        let mut cache_write = self.cache.write().await;
                                        if cache_write.len() > 500 {
                                            cache_write.clear();
                                        }
                                        cache_write.insert(domain.to_string(), ip);
                                        return Some(ip);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("DoH query failed for {}: {}", domain, e);
            }
        }

        None
    }
}
