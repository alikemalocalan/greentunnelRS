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
    is_http_connect, is_padding_incompatible_domain, parse_connect_target, random_delay,
    split_and_write, strip_proxy_headers,
};

pub struct ProxyServerConfig {
    pub bind_addr: SocketAddr,
    pub aggressive_mode: bool,
    pub doh_url: String,
    pub disorder_mode: bool,
    pub fake_ttl: u32,
    pub fake_sni: String,
    pub window_shrink: usize,
}

pub async fn run_server(config: ProxyServerConfig) -> anyhow::Result<()> {
    let listener = TcpListener::bind(config.bind_addr).await?;
    tracing::info!(
        "GreenTunnel Rust Proxy running on http://{} (AggressiveMode: {}, Disorder: {}, FakeTTL: {}, WindowShrink: {})",
        config.bind_addr,
        config.aggressive_mode,
        config.disorder_mode,
        config.fake_ttl,
        config.window_shrink
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
    let mut buf = [0u8; 4096];
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

        // Enable TCP_NODELAY to ensure split packets are sent immediately
        remote.set_nodelay(true).ok();

        // Apply TCP Window Shrinking if configured
        if config.window_shrink > 0 {
            let socket_ref = socket2::SockRef::from(&remote);
            socket_ref.set_recv_buffer_size(config.window_shrink).ok();
            socket_ref.set_send_buffer_size(config.window_shrink).ok();
        }

        // Respond 200 Connection Established to client
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        client.flush().await?;

        // Read ClientHello record from client
        let mut client_hello_buf = [0u8; 8192];
        let hello_len = client.read(&mut client_hello_buf).await?;
        if hello_len > 0 {
            let raw_bytes = &client_hello_buf[..hello_len];

            // Fake Packet TTL Injection on a separate dummy probe socket to avoid main TLS stream corruption
            if config.fake_ttl > 0 && is_client_hello(raw_bytes) {
                if let Ok(mut fake_stream) = TcpStream::connect(remote_addr).await {
                    fake_stream.set_ttl(config.fake_ttl).ok();
                    let fake_hello = crate::tls::build_synthetic_client_hello(Some(&config.fake_sni), false);
                    let _ = fake_stream.write_all(&fake_hello).await;
                    let _ = fake_stream.flush().await;
                    tracing::info!(
                        "Fake TTL Packet injected on probe socket for {}: fake SNI {}, TTL {}",
                        host,
                        config.fake_sni,
                        config.fake_ttl
                    );
                }
            }

            // Step 1: Aggressive Mode Connection Padding (RFC 7685)
            // Skip padding for Meta/Facebook/Instagram domains because Meta's C++ Fizz TLS stack drops padded ClientHello records.
            let bytes = if config.aggressive_mode
                && !is_padding_incompatible_domain(&host)
                && is_client_hello(raw_bytes)
            {
                pad(raw_bytes, DEFAULT_TARGET_SIZE)
            } else {
                raw_bytes.to_vec()
            };

            if let Some(sni_info) = find_sni_info(&bytes) {
                if sni_info.hostname_length > 4 {
                    let cut_in_sni = rand::random_range(3..=8.min(sni_info.hostname_length - 1));
                    let split_point = sni_info.hostname_offset + cut_in_sni;

                    if split_point > TLS_RECORD_HEADER_SIZE && split_point < bytes.len() {
                        let tls_records = fragment_at_offset(&bytes, split_point);

                        // Send Record 1 (containing split SNI header) first with random TCP segmentation
                        split_and_write(&tls_records[0], &mut remote).await?;

                        // Fast inter-fragment delay (1-5ms) to trigger DPI reassembly timeout
                        random_delay(1, 5).await;

                        // Send remaining records (Record 2)
                        for rec in &tls_records[1..] {
                            remote.write_all(rec).await?;
                        }
                        remote.flush().await?;

                        tracing::info!(
                            "DPI Bypass applied for {}: split at byte {}, delay 1-5ms, {} TLS records",
                            host,
                            split_point,
                            tls_records.len()
                        );

                        // Tunnel remaining bidirectional TCP stream
                        tunnel_bidirectional(&mut client, &mut remote).await?;
                        return Ok(());
                    }
                }
            }

            // Fallback: TCP fragmentation without TLS record split
            split_and_write(&bytes, &mut remote).await?;
        }

        // Tunnel remaining bidirectional TCP stream
        tunnel_bidirectional(&mut client, &mut remote).await?;
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

async fn tunnel_bidirectional(client: &mut TcpStream, remote: &mut TcpStream) -> anyhow::Result<()> {
    tokio::io::copy_bidirectional(client, remote).await?;
    Ok(())
}
