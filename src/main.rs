use ipnet;
use ipnet::Ipv4Net;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

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

async fn generate_ips() -> Vec<ipnet::Ipv4Net> {
    let mut ip_ranges: Arc<Mutex<Vec<Ipv4Net>>> = Default::default();
    let mut handles = vec![];
    for i in 0..256 {
        for j in 0..256 {
            let ip = format!("{}.{}.0.0/16", i, j)
                .parse::<ipnet::Ipv4Net>()
                .unwrap();
            let ip_ranges = ip_ranges.clone();
            handles.push(tokio::spawn(async move {
                if (check_ip_legality(&ip).await) {
                    ip_ranges.lock().unwrap().push(ip);
                }
            }));
        }
    }
    let mut sol: Vec<Ipv4Net> = vec![];
    for handle in handles {
        tokio::join!(handle);
    }
    for i in ip_ranges.lock().unwrap().iter() {
        sol.push(*i);
    }
    sol
}

#[tokio::main]
async fn main() {
    let ips = generate_ips();
    println!("ips:\n{:#?}", ips.await);
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
