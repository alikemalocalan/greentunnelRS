use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::dns::DohResolver;
use crate::tls::{
    find_sni_info, fragment_at_offset, is_client_hello, pad, DEFAULT_TARGET_SIZE,
    TLS_RECORD_HEADER_SIZE,
};
use crate::utils::{
    is_http_connect, parse_connect_target, random_delay, split_and_write, strip_proxy_headers,
};

pub struct ProxyServerConfig {
    pub bind_addr: SocketAddr,
    pub aggressive_mode: bool,
    pub doh_url: String,
}

pub async fn run_server(config: ProxyServerConfig) -> anyhow::Result<()> {
    let listener = TcpListener::bind(config.bind_addr).await?;
    tracing::info!(
        "GreenTunnel Rust Proxy running on http://{} (AggressiveMode: {})",
        config.bind_addr,
        config.aggressive_mode
    );

    let resolver = Arc::new(DohResolver::new(&config.doh_url));
    let config = Arc::new(config);

    loop {
        let (client_stream, client_addr) = match listener.accept().await {
            Ok(val) => val,
            Err(e) => {
                tracing::error!("Accept error: {}", e);
                continue;
            }
        };

        let resolver = Arc::clone(&resolver);
        let config = Arc::clone(&config);

        tokio::spawn(async move {
            if let Err(e) = handle_client(client_stream, client_addr, resolver, config).await {
                tracing::debug!("Client connection ended ({}) : {}", client_addr, e);
            }
        });
    }
}

async fn handle_client(
    mut client: TcpStream,
    _client_addr: SocketAddr,
    resolver: Arc<DohResolver>,
    config: Arc<ProxyServerConfig>,
) -> anyhow::Result<()> {
    let mut buf = vec![0u8; 4096];
    let n = client.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let request_str = String::from_utf8_lossy(&buf[..n]);
    let cleaned_request = strip_proxy_headers(&request_str);

    if is_http_connect(&cleaned_request) {
        let (host, port) = match parse_connect_target(&cleaned_request) {
            Some(target) => target,
            None => {
                client
                    .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                    .await?;
                return Ok(());
            }
        };

        tracing::info!("CONNECT request: {}:{}", host, port);

        // Resolve domain via DoH or standard IP parse
        let remote_ip = match resolver.resolve(&host).await {
            Some(ip) => ip,
            None => {
                // Fallback to std net resolution if DoH fails
                match tokio::net::lookup_host(format!("{}:{}", host, port)).await {
                    Ok(mut addrs) => match addrs.next() {
                        Some(addr) => addr.ip(),
                        None => {
                            client
                                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                                .await?;
                            return Ok(());
                        }
                    },
                    Err(_) => {
                        client
                            .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                            .await?;
                        return Ok(());
                    }
                }
            }
        };

        let remote_addr = SocketAddr::new(remote_ip, port);
        let mut remote = match TcpStream::connect(remote_addr).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to connect to remote {}:{}", host, e);
                client
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    .await?;
                return Ok(());
            }
        };

        // Respond 200 Connection Established to client
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        client.flush().await?;

        // Read ClientHello record from client
        let mut client_hello_buf = vec![0u8; 8192];
        let hello_len = client.read(&mut client_hello_buf).await?;
        if hello_len > 0 {
            let raw_bytes = &client_hello_buf[..hello_len];

            // Step 1: Aggressive Mode Connection Padding (RFC 7685)
            let bytes = if config.aggressive_mode && is_client_hello(raw_bytes) {
                pad(raw_bytes, DEFAULT_TARGET_SIZE)
            } else {
                raw_bytes.to_vec()
            };

            // Step 2: SNI Location & Layer 5 TLS Record Fragmentation
            if let Some(sni_info) = find_sni_info(&bytes) {
                if sni_info.hostname_length > 4 {
                    let cut_in_sni = rand::Rng::gen_range(
                        &mut rand::thread_rng(),
                        3..=8.min(sni_info.hostname_length - 1),
                    );
                    let split_point = sni_info.hostname_offset + cut_in_sni;

                    if split_point > TLS_RECORD_HEADER_SIZE && split_point < bytes.len() {
                        let tls_records = fragment_at_offset(&bytes, split_point);

                        // Send record 1 with random TCP segmentation
                        split_and_write(&tls_records[0], &mut remote).await?;

                        // Step 3: Inter-fragment delay (1-30ms) to trigger DPI reassembly timeout
                        random_delay(1, 30).await;

                        // Send remaining records
                        for rec in &tls_records[1..] {
                            split_and_write(rec, &mut remote).await?;
                        }

                        tracing::info!(
                            "DPI Bypass applied for {}: split at byte {}, delay 1-30ms, {} TLS records",
                            host,
                            split_point,
                            tls_records.len()
                        );

                        // Tunnel remaining bidirectional TCP stream
                        tunnel_bidirectional(client, remote).await?;
                        return Ok(());
                    }
                }
            }

            // Fallback: TCP fragmentation without TLS record split
            split_and_write(&bytes, &mut remote).await?;
        }

        // Tunnel remaining bidirectional TCP stream
        tunnel_bidirectional(client, remote).await?;
    } else {
        // Plaintext HTTP request redirect to HTTPS
        let response = format!(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: https://{}\r\nContent-Length: 0\r\n\r\n",
            request_str.lines().next().unwrap_or("")
        );
        let _ = client.write_all(response.as_bytes()).await;
    }

    Ok(())
}

async fn tunnel_bidirectional(mut client: TcpStream, mut remote: TcpStream) -> anyhow::Result<()> {
    let (mut client_read, mut client_write) = client.split();
    let (mut remote_read, mut remote_write) = remote.split();

    let client_to_remote = tokio::io::copy(&mut client_read, &mut remote_write);
    let remote_to_client = tokio::io::copy(&mut remote_read, &mut client_write);

    tokio::select! {
        _ = client_to_remote => {},
        _ = remote_to_client => {},
    }

    Ok(())
}
