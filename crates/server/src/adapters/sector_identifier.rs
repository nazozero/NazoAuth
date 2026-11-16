use std::net::IpAddr;

pub(crate) const MAX_RESPONSE_BYTES: u64 = 128 * 1024;

#[derive(Debug)]
pub(crate) enum SectorIdentifierError {
    InvalidJson,
    #[allow(dead_code)]
    InvalidEntry(String),
}

pub(crate) fn is_blocked_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_blocked_ip(ip);
    }
    false
}

pub(crate) fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !is_globally_reachable_ipv4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_blocked_ip(IpAddr::V4(mapped));
            }
            !is_globally_reachable_ipv6(v6)
        }
    }
}

fn ipv4_in_prefix(address: std::net::Ipv4Addr, network: [u8; 4], prefix_length: u32) -> bool {
    let mask = u32::MAX << (32 - prefix_length);
    u32::from(address) & mask == u32::from_be_bytes(network) & mask
}

fn is_globally_reachable_ipv4(address: std::net::Ipv4Addr) -> bool {
    // Mirror the IANA IPv4 Special-Purpose Address Registry's globally-reachable
    // column. The two anycast assignments are more specific exceptions to /24.
    if matches!(address.octets(), [192, 0, 0, 9] | [192, 0, 0, 10]) {
        return true;
    }
    ![
        ([0, 0, 0, 0], 8),
        ([10, 0, 0, 0], 8),
        ([100, 64, 0, 0], 10),
        ([127, 0, 0, 0], 8),
        ([169, 254, 0, 0], 16),
        ([172, 16, 0, 0], 12),
        ([192, 0, 0, 0], 24),
        ([192, 0, 2, 0], 24),
        ([192, 88, 99, 0], 24),
        ([192, 168, 0, 0], 16),
        ([198, 18, 0, 0], 15),
        ([198, 51, 100, 0], 24),
        ([203, 0, 113, 0], 24),
        ([224, 0, 0, 0], 4),
        ([240, 0, 0, 0], 4),
    ]
    .into_iter()
    .any(|(network, prefix_length)| ipv4_in_prefix(address, network, prefix_length))
}

fn ipv6_in_prefix(address: std::net::Ipv6Addr, network: u128, prefix_length: u32) -> bool {
    let mask = u128::MAX << (128 - prefix_length);
    u128::from(address) & mask == network & mask
}

fn is_globally_reachable_ipv6(address: std::net::Ipv6Addr) -> bool {
    // Mirror the IANA IPv6 Special-Purpose Address Registry. Only the listed
    // exceptions inside 2001::/23 and the well-known translation prefix remain
    // reachable in addition to ordinary global unicast space.
    let ietf_exception =
        matches!(
            address.segments(),
            [0x2001, 0x0001, 0, 0, 0, 0, 0, 1]
                | [0x2001, 0x0001, 0, 0, 0, 0, 0, 2]
                | [0x2001, 0x0001, 0, 0, 0, 0, 0, 3]
        ) || ipv6_in_prefix(address, 0x2001_0003_0000_0000_0000_0000_0000_0000, 32)
            || ipv6_in_prefix(address, 0x2001_0004_0112_0000_0000_0000_0000_0000, 48)
            || ipv6_in_prefix(address, 0x2001_0020_0000_0000_0000_0000_0000_0000, 28)
            || ipv6_in_prefix(address, 0x2001_0030_0000_0000_0000_0000_0000_0000, 28);
    if ietf_exception {
        return true;
    }
    if ipv6_in_prefix(address, 0x0064_ff9b_0000_0000_0000_0000_0000_0000, 96) {
        return true;
    }
    let is_global_unicast = ipv6_in_prefix(address, 0x2000_0000_0000_0000_0000_0000_0000_0000, 3);
    is_global_unicast
        && ![
            (0x2001_0000_0000_0000_0000_0000_0000_0000, 23),
            (0x2001_0db8_0000_0000_0000_0000_0000_0000, 32),
            (0x2002_0000_0000_0000_0000_0000_0000_0000, 16),
            (0x3fff_0000_0000_0000_0000_0000_0000_0000, 20),
        ]
        .into_iter()
        .any(|(network, prefix_length)| ipv6_in_prefix(address, network, prefix_length))
}

pub(crate) fn parse_sector_identifier_document(
    body: &[u8],
) -> Result<Vec<String>, SectorIdentifierError> {
    let uris: Vec<String> =
        serde_json::from_slice(body).map_err(|_| SectorIdentifierError::InvalidJson)?;
    for entry in &uris {
        if url::Url::parse(entry).is_err() {
            return Err(SectorIdentifierError::InvalidEntry(entry.clone()));
        }
    }
    Ok(uris)
}

#[cfg(test)]
#[path = "../../tests/unit/domain/sector_identifier.rs"]
mod tests;
