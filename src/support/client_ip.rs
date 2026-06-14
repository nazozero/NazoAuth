//! 可信反向代理下的客户端 IP 解析。
//! 默认只使用连接 peer 地址；转发头仅在 peer 命中可信代理 CIDR 后生效。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClientIpHeaderMode {
    None,
    Forwarded,
    XForwardedFor,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IpCidr {
    addr: IpAddr,
    prefix: u8,
}

impl ClientIpHeaderMode {
    pub(crate) fn parse(value: &str) -> anyhow::Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "none" => Ok(Self::None),
            "forwarded" => Ok(Self::Forwarded),
            "x-forwarded-for" => Ok(Self::XForwardedFor),
            value => anyhow::bail!(
                "CLIENT_IP_HEADER_MODE must be none, forwarded, or x-forwarded-for, got {value}"
            ),
        }
    }
}

impl IpCidr {
    pub(crate) fn parse(value: &str) -> anyhow::Result<Self> {
        let (addr, prefix) = value
            .trim()
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("trusted proxy CIDR must include prefix length"))?;
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| anyhow::anyhow!("trusted proxy CIDR address is invalid"))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| anyhow::anyhow!("trusted proxy CIDR prefix is invalid"))?;
        let max_prefix = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max_prefix {
            anyhow::bail!("trusted proxy CIDR prefix is out of range");
        }
        Ok(Self { addr, prefix })
    }

    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                ipv4_prefix_value(network, self.prefix) == ipv4_prefix_value(ip, self.prefix)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                ipv6_prefix_value(network, self.prefix) == ipv6_prefix_value(ip, self.prefix)
            }
            _ => false,
        }
    }
}

pub(crate) fn parse_trusted_proxy_cidrs(raw: Option<String>) -> anyhow::Result<Vec<IpCidr>> {
    raw.unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(IpCidr::parse)
        .collect()
}

pub(crate) fn client_ip(req: &HttpRequest, settings: &Settings) -> String {
    let Some(peer_ip) = req.peer_addr().map(|addr| addr.ip()) else {
        return "unknown".to_owned();
    };
    if settings.client_ip_header_mode == ClientIpHeaderMode::None
        || !trusted_proxy_peer_ip(peer_ip, settings)
    {
        return peer_ip.to_string();
    }
    let parsed = match settings.client_ip_header_mode {
        ClientIpHeaderMode::None => None,
        ClientIpHeaderMode::Forwarded => forwarded_client_ip(req),
        ClientIpHeaderMode::XForwardedFor => x_forwarded_for_client_ip(req, settings),
    };
    parsed.unwrap_or(peer_ip).to_string()
}

pub(crate) fn request_from_trusted_proxy(req: &HttpRequest, settings: &Settings) -> bool {
    req.peer_addr()
        .map(|addr| trusted_proxy_peer_ip(addr.ip(), settings))
        .unwrap_or(false)
}

fn trusted_proxy_peer_ip(peer_ip: IpAddr, settings: &Settings) -> bool {
    settings
        .trusted_proxy_cidrs
        .iter()
        .any(|cidr| cidr.contains(peer_ip))
}

fn forwarded_client_ip(req: &HttpRequest) -> Option<IpAddr> {
    let raw = req.headers().get("forwarded")?.to_str().ok()?;
    for item in raw.split(',').flat_map(|part| part.split(';')) {
        let (name, value) = item.trim().split_once('=')?;
        if name.trim().eq_ignore_ascii_case("for") {
            return parse_forwarded_for_value(value.trim());
        }
    }
    None
}

fn parse_forwarded_for_value(value: &str) -> Option<IpAddr> {
    let value = value.trim_matches('"');
    if let Some(ip) = value
        .strip_prefix('[')
        .and_then(|rest| rest.split_once(']').map(|(ip, _)| ip))
    {
        return ip.parse().ok();
    }
    let host = value.rsplit_once(':').and_then(|(host, port)| {
        port.parse::<u16>().ok()?;
        Some(host)
    });
    host.unwrap_or(value).parse().ok()
}

fn x_forwarded_for_client_ip(req: &HttpRequest, settings: &Settings) -> Option<IpAddr> {
    let raw = req.headers().get("x-forwarded-for")?.to_str().ok()?;
    raw.split(',')
        .map(str::trim)
        .filter_map(|value| value.parse::<IpAddr>().ok())
        .find(|ip| {
            !settings
                .trusted_proxy_cidrs
                .iter()
                .any(|cidr| cidr.contains(*ip))
        })
}

fn ipv4_prefix_value(ip: Ipv4Addr, prefix: u8) -> u32 {
    if prefix == 0 {
        return 0;
    }
    u32::from(ip) >> (32 - prefix)
}

fn ipv6_prefix_value(ip: Ipv6Addr, prefix: u8) -> u128 {
    if prefix == 0 {
        return 0;
    }
    u128::from(ip) >> (128 - prefix)
}

#[cfg(test)]
mod tests;
