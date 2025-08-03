use ipnet;

fn check_ip_legality(checked_ip: &ipnet::Ipv4Net) -> bool {
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
        // ☁️ Cloud metadata services (AWS, Azure, GCP
        "169.254.169.254/32".parse().unwrap(), // Metadata service for cloud VMs
        // 🧱 Internet infrastructure / non-game hosts (o^ptional
        "4.2.2.1/32".parse().unwrap(), // Level3 DNS
        "4.2.2.2/32".parse().unwrap(),
        "4.2.2.3/32".parse().unwrap(),
        "4.2.2.4/32".parse().unwrap(),
        "4.2.2.5/32".parse().unwrap(),
        "4.2.2.6/32".parse().unwrap(),
        // dns servers
        "8.8.8.8/32".parse().unwrap(), // Google
        "8.8.4.4/32".parse().unwrap(),
        "1.1.1.1/32".parse().unwrap(), // Cloudflare
        "1.0.0.1/32".parse().unwrap(),
        "9.9.9.9/32".parse().unwrap(), // Quad9
        "149.112.112.112/32".parse().unwrap(),
        "208.67.222.222/32".parse().unwrap(), // OpenDNS
        "208.67.220.220/32".parse().unwrap(),
        "185.228.168.168/32".parse().unwrap(), // CleanBrowsing (Family)
        "185.228.169.168/32".parse().unwrap(),
        "94.140.14.14/32".parse().unwrap(), // AdGuard
        "94.140.15.15/32".parse().unwrap(),
        "77.88.8.88/32".parse().unwrap(), // Yandex DNS (Safe)
        "77.88.8.2/32".parse().unwrap(),
        "8.26.56.26/32".parse().unwrap(), // Comodo Secure DNS
        "8.20.247.20/32".parse().unwrap(),
        "156.154.70.1/32".parse().unwrap(), // Neustar DNS
        "156.154.71.1/32".parse().unwrap(),
        "209.244.0.3/32".parse().unwrap(), // Level3/CenturyLink
        "209.244.0.4/32".parse().unwrap(),
        "216.146.35.35/32".parse().unwrap(), // Dyn
        "216.146.36.36/32".parse().unwrap(),
        "64.6.64.6/32".parse().unwrap(), // Verisign
        "64.6.65.6/32".parse().unwrap(),
        "76.76.19.19/32".parse().unwrap(), // Alternate DNS (ad blocking)
        "76.223.122.150/32".parse().unwrap(),
    ];

    excluded_ips.iter().any(|ips| ips.contains(checked_ip))
}
fn generate_ips() -> Vec<ipnet::Ipv4Net> {
    let mut ip_ranges: Vec<ipnet::Ipv4Net> = vec![];
    for i in 0..256 {
        for j in 0..256 {
            let ip: ipnet::Ipv4Net = format!("{i}.{j}.0.0/16").parse().unwrap();
            if check_ip_legality(&ip) {
                ip_ranges.push(ip);
            }
        }
    }
    ip_ranges
}

fn main() {
    let ips = generate_ips();
    println!("ips:\n{:#?}", ips.len());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore]
    #[test]
    fn generate_full_ip_set() {
        assert_eq!(generate_ips().len(), 56558)
    }

    #[test]
    fn deny_localhost() {
        for i in 0..256 {
            assert!(!check_ip_legality(
                &format!("127.{i}.0.0/16").parse().unwrap()
            ));
        }
    }
    #[test]
    fn deny_dns() {
        let dns = vec![
            "8.8.8.8", // Google
            "8.8.4.4",
            "1.1.1.1", // Cloudflare
            "1.0.0.1",
            "9.9.9.9", // Quad9
            "149.112.112.112",
            "208.67.222.222", // OpenDNS
            "208.67.220.220",
            "185.228.168.168", // CleanBrowsing (Family)
            "185.228.169.168",
            "94.140.14.14", // AdGuard
            "94.140.15.15",
            "77.88.8.88", // Yandex DNS (Safe)
            "77.88.8.2",
            "8.26.56.26", // Comodo Secure DNS
            "8.20.247.20",
            "156.154.70.1", // Neustar DNS
            "156.154.71.1",
            "209.244.0.3", // Level3/CenturyLink
            "209.244.0.4",
            "216.146.35.35", // Dyn
            "216.146.36.36",
            "64.6.64.6", // Verisign
            "64.6.65.6",
            "76.76.19.19", // Alternate DNS (ad blocking)
            "76.223.122.150",
        ];
        for ip in dns.iter() {
            assert!(!check_ip_legality(&ip.parse().unwrap()));
        }
    }
}
