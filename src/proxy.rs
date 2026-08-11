use std::io::IoSlice;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::dns::DnsResolver;
use crate::tls::{
    find_sni_info, fragment_at_offset, is_client_hello, TlsRecordSlice, TLS_RECORD_HEADER_SIZE,
};
use crate::utils::{
    is_http_connect, is_padding_incompatible_domain, parse_connect_target, preprocess_http_request,
    random_delay, split_and_write,
};

pub struct ProxyServerConfig {
    pub bind_addr: SocketAddr,
    pub dns_addr: String,
    pub fake_ttl: u32,
    pub fake_sni: String,
    pub window_shrink: usize,
    pub http_space: bool,
    pub mix_header_case: bool,
    pub strip_alt_svc: bool,
    pub port_rotate: bool,
    pub trailing_dot: bool,
    pub filter_type65: bool,
    pub fallback_target: String,
}

pub fn run_server(config: ProxyServerConfig) -> anyhow::Result<()> {
    let num_workers = if cfg!(windows) {
        1
    } else {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2)
    };
    let config = Arc::new(config);

    tracing::info!(
        "GreenTunnel Rust Proxy running on http://{} with {} Thread-per-Core workers (SO_REUSEPORT, current_thread) (FakeTTL: {}, WindowShrink: {}, HttpSpace: {}, MixHeaderCase: {}, StripAltSvc: {}, PortRotate: {}, TrailingDot: {}, FilterType65: {}, FallbackTarget: {})",
        config.bind_addr,
        num_workers,
        config.fake_ttl,
        config.window_shrink,
        config.http_space,
        config.mix_header_case,
        config.strip_alt_svc,
        config.port_rotate,
        config.trailing_dot,
        config.filter_type65,
        config.fallback_target
    );

    let mut handles = Vec::with_capacity(num_workers);

    for worker_id in 0..num_workers {
        let config = Arc::clone(&config);

        let handle = std::thread::Builder::new()
            .name(format!("worker-{}", worker_id))
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("Failed to build single-threaded Tokio runtime");

                let resolver = Arc::new(DnsResolver::new(&config.dns_addr));

                rt.block_on(async move {
                    if let Err(e) = run_worker_listener(worker_id, resolver, config).await {
                        tracing::error!("Worker {} listener error: {}", worker_id, e);
                    }
                });
            })?;

        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.join();
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

        let clean_raw = raw_host.trim_end_matches('.');
        if clean_raw.eq_ignore_ascii_case("localhost")
            || clean_raw
                .parse::<std::net::IpAddr>()
                .map(|ip| ip.is_loopback() || ip.is_unspecified())
                .unwrap_or(false)
        {
            tracing::debug!(
                "Rejecting CONNECT connection for {}:{} -> loopback/unspecified host detected",
                raw_host,
                port
            );
            client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
            return Ok(());
        }

        let host = if config.trailing_dot {
            crate::utils::ensure_trailing_dot(&raw_host)
        } else {
            raw_host
        };

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

        if remote_ip.is_loopback() || remote_ip.is_unspecified() {
            tracing::debug!(
                "Rejecting CONNECT connection for {}:{} -> resolved to loopback/unspecified IP: {}",
                host,
                port,
                remote_ip
            );
            client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
            return Ok(());
        }

        tracing::info!("CONNECT request: {}:{}", host, port);

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

            // Fake Packet TTL Injection on a separate dummy probe socket
            if config.fake_ttl > 0
                && !config.fake_sni.is_empty()
                && !is_padding_incompatible_domain(&host)
                && is_client_hello(raw_bytes)
            {
                if let Ok(peer_addr) = remote.peer_addr() {
                    inject_fake_ttl_probe(peer_addr, &config.fake_sni, config.fake_ttl).await;
                    tracing::info!(
                        "Fake TTL Packet injected on probe socket for {}: fake SNI {}, TTL {}",
                        host,
                        config.fake_sni,
                        config.fake_ttl
                    );
                }
            }

            // Separate the first TLS record (ClientHello) from any trailing buffer data
            let (raw_ch, trailing_data) = extract_first_tls_record(raw_bytes);
            let bytes = raw_ch.to_vec();

            if let Some(sni_info) = find_sni_info(&bytes) {
                if sni_info.hostname_length > 4 {
                    let cut_in_sni = calculate_sni_cut_offset(sni_info.hostname_length, &host);
                    let split_point = sni_info.hostname_offset + cut_in_sni;

                    if split_point > TLS_RECORD_HEADER_SIZE && split_point < bytes.len() {
                        let (rec1, rec2) = fragment_at_offset(&bytes, split_point);
                        let is_meta = is_padding_incompatible_domain(&host);

                        transmit_tls_records(
                            &mut remote,
                            &rec1,
                            rec2.as_ref(),
                            trailing_data,
                            is_meta,
                        )
                        .await?;

                        tracing::info!(
                            "DPI Bypass applied for {}: split at byte {}, delay {}, {} TLS records",
                            host,
                            split_point,
                            if is_meta { "0ms (Meta)" } else { "1-5ms" },
                            if rec2.is_some() { 2 } else { 1 }
                        );

                        tunnel_bidirectional(&mut client, &mut remote).await?;
                        return Ok(());
                    }
                }
            }

            // Fallback: TCP fragmentation without TLS record split
            split_and_write(&bytes, &mut remote).await?;
        }

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

fn extract_first_tls_record(raw_bytes: &[u8]) -> (&[u8], &[u8]) {
    if is_client_hello(raw_bytes) {
        let payload_len = crate::tls::read_u16(raw_bytes, 3).unwrap_or(0) as usize;
        let rec_len = TLS_RECORD_HEADER_SIZE + payload_len;
        if rec_len > TLS_RECORD_HEADER_SIZE && raw_bytes.len() > rec_len {
            (&raw_bytes[..rec_len], &raw_bytes[rec_len..])
        } else {
            (raw_bytes, &[][..])
        }
    } else {
        (raw_bytes, &[][..])
    }
}

fn calculate_sni_cut_offset(hostname_length: usize, host: &str) -> usize {
    if hostname_length > 6 {
        let start_offset = if host.to_lowercase().starts_with("www.") {
            4
        } else {
            0
        };
        let domain_len = hostname_length.saturating_sub(start_offset);
        let mid = start_offset + (domain_len / 2);
        let min_cut = (mid.saturating_sub(1)).max(start_offset + 2);
        let max_cut = (mid + 1).min(hostname_length - 2);
        if min_cut <= max_cut {
            fastrand::usize(min_cut..=max_cut)
        } else {
            hostname_length / 2
        }
    } else {
        hostname_length / 2
    }
}

async fn inject_fake_ttl_probe(peer_addr: SocketAddr, fake_sni: &str, fake_ttl: u32) {
    if let Ok(mut fake_stream) = TcpStream::connect(peer_addr).await {
        fake_stream.set_ttl(fake_ttl).ok();
        let fake_hello = crate::tls::build_synthetic_client_hello(Some(fake_sni), false);
        let _ = fake_stream.write_all(&fake_hello).await;
        let _ = fake_stream.flush().await;
    }
}

/// Helper to send multiple slice buffers using zero-allocation vectored I/O (`writev` syscall).
pub async fn write_all_vectored<S>(stream: &mut S, slices: &[&[u8]]) -> std::io::Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    let mut current_slices = slices;
    let mut first_slice_offset = 0;

    while !current_slices.is_empty() {
        while !current_slices.is_empty() && first_slice_offset >= current_slices[0].len() {
            current_slices = &current_slices[1..];
            first_slice_offset = 0;
        }

        if current_slices.is_empty() {
            break;
        }

        let first = &current_slices[0][first_slice_offset..];
        let mut io_slices_buf = [
            IoSlice::new(&[]),
            IoSlice::new(&[]),
            IoSlice::new(&[]),
            IoSlice::new(&[]),
        ];
        let count = current_slices.len().min(4);
        io_slices_buf[0] = IoSlice::new(first);
        for i in 1..count {
            io_slices_buf[i] = IoSlice::new(current_slices[i]);
        }

        let n = stream.write_vectored(&io_slices_buf[..count]).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "failed to write buffer with write_vectored",
            ));
        }

        let mut remaining = n;
        while remaining > 0 && !current_slices.is_empty() {
            let active_len = current_slices[0].len() - first_slice_offset;
            if remaining >= active_len {
                remaining -= active_len;
                current_slices = &current_slices[1..];
                first_slice_offset = 0;
            } else {
                first_slice_offset += remaining;
                remaining = 0;
            }
        }
    }

    Ok(())
}

async fn transmit_tls_records(
    remote: &mut TcpStream,
    rec1: &TlsRecordSlice<'_>,
    rec2: Option<&TlsRecordSlice<'_>>,
    trailing_data: &[u8],
    is_meta: bool,
) -> anyhow::Result<()> {
    // Record 1 (containing first half of SNI) must be transmitted first using vectored I/O
    write_all_vectored(remote, &[&rec1.header[..], rec1.payload]).await?;
    remote.flush().await?;

    // Fast inter-fragment delay (1-5ms) to trigger DPI reassembly timeout unless Meta domain
    if !is_meta {
        random_delay(1, 5).await;
    }

    // Record 2 (containing second half of SNI) and trailing data transmitted in ONE vectored writev syscall
    if let Some(rec2) = rec2 {
        if !trailing_data.is_empty() {
            write_all_vectored(remote, &[&rec2.header[..], rec2.payload, trailing_data]).await?;
        } else {
            write_all_vectored(remote, &[&rec2.header[..], rec2.payload]).await?;
        }
    } else if !trailing_data.is_empty() {
        remote.write_all(trailing_data).await?;
    }

    remote.flush().await?;

    Ok(())
}

async fn tunnel_bidirectional(
    client: &mut TcpStream,
    remote: &mut TcpStream,
) -> anyhow::Result<()> {
    tokio::io::copy_bidirectional(client, remote).await?;
    Ok(())
}
