//! Local UDP DNS resolution module with Type 65/64 ISP poisoning defense.

pub mod resolver;

pub use resolver::DnsResolver;
