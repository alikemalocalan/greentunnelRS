use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::dns::DnsResolver;
use crate::tls::{
    find_sni_info, fragment_at_offset, has_post_quantum_extension, is_client_hello,
    pad_client_hello, DEFAULT_TARGET_SIZE, TLS_RECORD_HEADER_SIZE,
};
use crate::utils::{
    is_http_connect, is_padding_incompatible_domain, parse_connect_target, preprocess_http_request,
    random_delay, split_and_write,
};

pub struct ProxyServerConfig {
    pub bind_addr: SocketAddr,
    pub tls_padding: bool,
    pub dns_addr: String,
    pub disorder_mode: bool,
    pub fake_ttl: u32,
    pub fake_sni: String,
    pub window_shrink: usize,
    pub http_space: bool,
    pub mix_header_case: bool,
    pub strip_alt_svc: bool,
    pub port_rotate: bool,
    pub ja4_permute: bool,
    pub trailing_dot: bool,
    pub filter_type65: bool,
    pub post_quantum: bool,
    pub fallback_target: String,
}

pub async fn run_server(config: ProxyServerConfig) -> anyhow::Result<()> {
    let num_workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2);
    let resolver = Arc::new(DnsResolver::new(&config.dns_addr));
    let config = Arc::new(config);

    tracing::info!(
        "GreenTunnel Rust Proxy running on http://{} with {} CPU worker threads (TLSPadding: {}, Disorder: {}, FakeTTL: {}, WindowShrink: {}, HttpSpace: {}, MixHeaderCase: {}, StripAltSvc: {}, PortRotate: {}, JA4Permute: {}, TrailingDot: {}, FilterType65: {}, PostQuantum: {}, FallbackTarget: {})",
        config.bind_addr,
        num_workers,
        config.tls_padding,
        config.disorder_mode,
        config.fake_ttl,
        config.window_shrink,
        config.http_space,
        config.mix_header_case,
        config.strip_alt_svc,
        config.port_rotate,
        config.ja4_permute,
        config.trailing_dot,
        config.filter_type65,
        config.post_quantum,
        config.fallback_target
    );

    let mut handles = Vec::with_capacity(num_workers);

    for worker_id in 0..num_workers {
        let resolver = Arc::clone(&resolver);
        let config = Arc::clone(&config);

        let handle = tokio::spawn(async move {
            if let Err(e) = run_worker_listener(worker_id, resolver, config).await {
                tracing::error!("Worker {} listener error: {}", worker_id, e);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}

async fn run_worker_listener(
    worker_id: usize,
    resolver: Arc<DnsResolver>,
    config: Arc<ProxyServerConfig>,
) -> anyhow::Result<()> {
    let domain = if config.bind_addr.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    socket.set_reuse_address(true).ok();
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    socket.set_reuse_port(true).ok();
    socket.set_nonblocking(true)?;
    socket.bind(&config.bind_addr.into())?;
    socket.listen(1024)?;

    let std_listener: std::net::TcpListener = socket.into();
    let listener = TcpListener::from_std(std_listener)?;

    tracing::debug!(
        "Worker thread {} listening on http://{}",
        worker_id,
        config.bind_addr
    );

    loop {
        let (client_stream, client_addr) = match listener.accept().await {
            Ok(val) => val,
            Err(e) => {
                tracing::error!("Worker {} accept error: {}", worker_id, e);
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
    resolver: Arc<DnsResolver>,
    config: Arc<ProxyServerConfig>,
) -> anyhow::Result<()> {
    // Enable TCP_NODELAY on client socket to eliminate Linux 40ms Nagle delay during HTTP CONNECT handshake
    client.set_nodelay(true).ok();

    let mut buf = [0u8; 4096];
    let n = client.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let request_str = String::from_utf8_lossy(&buf[..n]);
    let cleaned_request =
        preprocess_http_request(&request_str, config.http_space, config.mix_header_case);

    if is_http_connect(&cleaned_request) {
        let (raw_host, port) = match parse_connect_target(&cleaned_request) {
            Some(target) => target,
            None => {
                client
                    .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                    .await?;
                return Ok(());
            }
        };

        let host = if config.trailing_dot {
            crate::utils::ensure_trailing_dot(&raw_host)
        } else {
            raw_host
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

        // TCP Source Port Rotation: bind socket to explicit ephemeral port to evade 4-tuple blackhole bans
        let outbound_socket = if remote_addr.is_ipv6() {
            tokio::net::TcpSocket::new_v6()?
        } else {
            tokio::net::TcpSocket::new_v4()?
        };
        outbound_socket.set_reuseaddr(true).ok();

        if config.port_rotate {
            let bind_zero: SocketAddr = if remote_addr.is_ipv6() {
                "[::]:0".parse().unwrap()
            } else {
                "0.0.0.0:0".parse().unwrap()
            };
            outbound_socket.bind(bind_zero).ok();
        }

        let mut remote = match outbound_socket.connect(remote_addr).await {
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

        // Apply TCP KeepAlive to prevent dead socket leaks on OpenWrt Linux kernel
        let keepalive = socket2::TcpKeepalive::new().with_time(std::time::Duration::from_secs(60));
        socket2::SockRef::from(&client)
            .set_tcp_keepalive(&keepalive)
            .ok();
        socket2::SockRef::from(&remote)
            .set_tcp_keepalive(&keepalive)
            .ok();

        // Apply TCP Window Shrinking if configured (clamp to minimum 4096 bytes on Linux/OpenWrt to prevent TCP Zero Window stalls)
        if config.window_shrink > 0 {
            let safe_win = config.window_shrink.max(4096);
            let socket_ref = socket2::SockRef::from(&remote);
            socket_ref.set_recv_buffer_size(safe_win).ok();
            socket_ref.set_send_buffer_size(safe_win).ok();
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
            if config.fake_ttl > 0
                && !config.fake_sni.is_empty()
                && !is_padding_incompatible_domain(&host)
                && is_client_hello(raw_bytes)
            {
                if let Ok(peer_addr) = remote.peer_addr() {
                    if let Ok(mut fake_stream) = TcpStream::connect(peer_addr).await {
                        fake_stream.set_ttl(config.fake_ttl).ok();
                        let fake_hello =
                            crate::tls::build_synthetic_client_hello(Some(&config.fake_sni), false);
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
            }

            // Separate the first TLS record (ClientHello) from any trailing buffer data
            // Firefox and modern browsers often pipeline initial ClientHello with session tickets or application data.
            let (raw_ch, trailing_data) = if is_client_hello(raw_bytes) {
                let payload_len = crate::tls::read_u16(raw_bytes, 3).unwrap_or(0) as usize;
                let rec_len = TLS_RECORD_HEADER_SIZE + payload_len;
                if rec_len > TLS_RECORD_HEADER_SIZE && raw_bytes.len() > rec_len {
                    (&raw_bytes[..rec_len], &raw_bytes[rec_len..])
                } else {
                    (raw_bytes, &[][..])
                }
            } else {
                (raw_bytes, &[][..])
            };

            // Step 1: TLS ClientHello Padding (RFC 7685)
            // Skip padding for Meta/Facebook/Instagram domains because Meta's C++ Fizz TLS stack drops padded ClientHello records.
            let mut bytes = if config.tls_padding
                && !is_padding_incompatible_domain(&host)
                && is_client_hello(raw_ch)
            {
                pad_client_hello(raw_ch, DEFAULT_TARGET_SIZE)
            } else {
                raw_ch.to_vec()
            };

            // Dynamic JA4 Extension Permutation: randomize TLS extension ordering to defeat JA3/JA4 fingerprinting
            if config.ja4_permute && is_client_hello(&bytes) {
                bytes = crate::tls::permute_tls_extensions(&bytes);
            }

            if config.post_quantum && has_post_quantum_extension(raw_ch) {
                tracing::info!(
                    "Post-Quantum ML-KEM-768 TLS 1.3 Key Share detected for {}",
                    host
                );
            }

            if let Some(sni_info) = find_sni_info(&bytes) {
                if sni_info.hostname_length > 4 {
                    let cut_in_sni = if sni_info.hostname_length > 6 {
                        let start_offset = if host.to_lowercase().starts_with("www.") {
                            4
                        } else {
                            0
                        };
                        let domain_len = sni_info.hostname_length.saturating_sub(start_offset);
                        let mid = start_offset + (domain_len / 2);
                        let min_cut = (mid.saturating_sub(1)).max(start_offset + 2);
                        let max_cut = (mid + 1).min(sni_info.hostname_length - 2);
                        if min_cut <= max_cut {
                            rand::random_range(min_cut..=max_cut)
                        } else {
                            sni_info.hostname_length / 2
                        }
                    } else {
                        sni_info.hostname_length / 2
                    };
                    let split_point = sni_info.hostname_offset + cut_in_sni;

                    if split_point > TLS_RECORD_HEADER_SIZE && split_point < bytes.len() {
                        let tls_records = fragment_at_offset(&bytes, split_point);

                        let is_meta = is_padding_incompatible_domain(&host);

                        // Send Record 1 (split SNI)
                        remote.write_all(&tls_records[0]).await?;
                        remote.flush().await?;

                        // Fast inter-fragment delay (1-5ms) to trigger DPI reassembly timeout unless Meta domain
                        if !is_meta {
                            random_delay(1, 5).await;
                        }

                        // Send remaining ClientHello records (Record 2)
                        for rec in &tls_records[1..] {
                            remote.write_all(rec).await?;
                        }
                        remote.flush().await?;

                        // Send any trailing unfragmented bytes read from client buffer
                        if !trailing_data.is_empty() {
                            remote.write_all(trailing_data).await?;
                            remote.flush().await?;
                        }

                        tracing::info!(
                            "DPI Bypass applied for {}: split at byte {}, delay {}, {} TLS records",
                            host,
                            split_point,
                            if is_meta { "0ms (Meta)" } else { "1-5ms" },
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
    } else if request_str.starts_with("GET ") || request_str.starts_with("POST ") {
        // Plaintext HTTP request redirect to HTTPS
        let first_line = request_str.lines().next().unwrap_or("");
        let target_path = first_line.split_whitespace().nth(1).unwrap_or("");
        let host_val = target_path.strip_prefix("http://").unwrap_or(target_path);
        let clean_host = host_val.split('/').next().unwrap_or(host_val);

        let response = format!(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: https://{}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            clean_host
        );
        let _ = client.write_all(response.as_bytes()).await;
    } else {
        // Active Probing Scanner Defense: Serve realistic Nginx 404 HTML server banner to ISP scanner bots
        tracing::warn!(
            "Active probe detected from client, serving benign 404 response to mislead ISP scanner"
        );
        let html_body = "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n";
        let response = format!(
            "HTTP/1.1 404 Not Found\r\nServer: nginx\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            html_body.len(),
            html_body
        );
        let _ = client.write_all(response.as_bytes()).await;
    }

    Ok(())
}

async fn tunnel_bidirectional(
    client: &mut TcpStream,
    remote: &mut TcpStream,
) -> anyhow::Result<()> {
    tokio::io::copy_bidirectional(client, remote).await?;
    Ok(())
}
