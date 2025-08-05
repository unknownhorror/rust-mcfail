use ::futures::future::join_all;
use ipnet;
use ipnet::Ipv4Net;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tokio::task::futures;

async fn check_ip_legality(checked_ip: &ipnet::Ipv4Net) -> bool {
    use ipnet::Ipv4Net;

    let excluded_ips: Vec<ipnet::Ipv4Net> = vec![
        "127.0.0.0/8".parse().unwrap(),
        // 🏠 Private network ranges (RFC 1918
        "10.0.0.0/8".parse().unwrap(),     // Class A private network
        "172.16.0.0/12".parse().unwrap(),  // Class B private networks
        "192.168.0.0/16".parse().unwrap(), // Class C private networks
        // 🔌 Link-local (self-assigned when DHCP fails
        "169.254.0.0/16".parse().unwrap(),
        // 🧪 Reserved for software/experimental use
        "0.0.0.0/8".parse().unwrap(),   // "This" network
        "240.0.0.0/4".parse().unwrap(), // Reserved for future use
        // 📡 Multicast addresses (used for streaming, routing protocols, etc.
        "224.0.0.0/4".parse().unwrap(),
        // 🧱 Internet infrastructure / non-game hosts (o^ptional
        "4.2.2.1/32".parse().unwrap(), // Level3 DNS
        "4.2.2.2/32".parse().unwrap(),
        "4.2.2.3/32".parse().unwrap(),
        "4.2.2.4/32".parse().unwrap(),
        "4.2.2.5/32".parse().unwrap(),
        "4.2.2.6/32".parse().unwrap(),
    ];

    !excluded_ips.iter().any(|ips| ips.contains(checked_ip))
}

async fn filter_ip(ip: Ipv4Net) -> Option<Ipv4Net> {
    if check_ip_legality(&ip).await {
        return Some(ip);
    }
    None
}
pub async fn generate_ips() -> Vec<ipnet::Ipv4Net> {
    let mut handles = vec![];
    for i in 0..256 {
        for j in 0..256 {
            println!("{}", i);
            let ip = format!("{}.{}.0.0/16", i, j)
                .parse::<ipnet::Ipv4Net>()
                .unwrap();
            handles.push(tokio::spawn(filter_ip(ip)));
        }
    }
    let mut sol: Vec<Ipv4Net> = vec![];
    for res in join_all(handles).await {
        if let Ok(unwrapped_res) = res {
            if let Some(ip) = unwrapped_res {
                sol.push(ip);
            }
        }
    }
    sol
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn generate_full_ip_set() {
        assert_eq!(generate_ips().await.len(), 56558)
    }

    #[tokio::test]
    async fn deny_localhost() {
        for i in 0..256 {
            assert!(!check_ip_legality(&format!("127.{i}.0.0/16").parse().unwrap()).await);
        }
    }
}
