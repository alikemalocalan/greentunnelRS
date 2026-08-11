mod args;
mod dns;
mod proxy;
mod tls;
mod utils;

use args::{Cli, Parser};
use proxy::{run_server, ProxyServerConfig};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let subscriber = SimpleLogSubscriber {
        verbose: cli.verbose,
    };
    tracing::subscriber::set_global_default(subscriber).ok();

    let bind_addr: SocketAddr = format!("{}:{}", cli.bind, cli.port).parse()?;

    println!(
        r#"
  ________                       ___________                          .__ 
 /  _____/______  ____   ____   _\__    ___/__ __  ____   ____   ____ |  |
/   \  __\_  __ \/ __ \_/ __ \ / \ |    | |  |  \/    \ /    \_/ __ \|  |
\    \_\  \  | \/\  ___/\  ___/ /  |    | |  |  /   |  \   |  \  ___/|  |__
 \______  /__|    \___  >\___  >   |____| |____/|___|  /___|  /\___  >____/
        \/            \/     \/                      \/     \/     \/     
"#
    );

    let config = ProxyServerConfig {
        bind_addr,
        tls_padding: cli.tls_padding,
        dns_addr: cli.dns_addr,
        disorder_mode: cli.disorder,
        fake_ttl: cli.fake_ttl,
        fake_sni: cli.fake_sni,
        window_shrink: cli.window_shrink,
        http_space: cli.http_space,
        mix_header_case: cli.mix_header_case,
        strip_alt_svc: cli.strip_alt_svc,
        port_rotate: cli.port_rotate,
        ja4_permute: cli.ja4_permute,
        trailing_dot: cli.trailing_dot,
        filter_type65: cli.filter_type65,
        post_quantum: cli.post_quantum,
        fallback_target: cli.fallback_target,
    };

    run_server(config).await?;

    Ok(())
}

struct SimpleLogSubscriber {
    verbose: bool,
}

impl tracing::Subscriber for SimpleLogSubscriber {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        if self.verbose {
            metadata.level() <= &tracing::Level::DEBUG
        } else {
            metadata.level() <= &tracing::Level::INFO
        }
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::Id {
        tracing::Id::from_u64(1)
    }

    fn record(&self, _id: &tracing::Id, _record: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _id: &tracing::Id, _follows: &tracing::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        if !self.enabled(event.metadata()) {
            return;
        }

        struct MessageVisitor(String);
        impl tracing::field::Visit for MessageVisitor {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = format!("{:?}", value);
                }
            }
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "message" {
                    self.0 = value.to_string();
                }
            }
        }

        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);

        let level = event.metadata().level();
        let target = event.metadata().target();
        eprintln!("[{}] {}: {}", level, target, visitor.0);
    }

    fn enter(&self, _id: &tracing::Id) {}
    fn exit(&self, _id: &tracing::Id) {}
}
