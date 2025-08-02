use ipnet;
use std::net::TcpStream;

fn check_ip_legality(checked_ip: &ipnet::Ipv4Net) -> bool {
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
        // 🌐 Public DNS servers (don't waste scanning these
        "8.8.8.8/32".parse().unwrap(), // Google DNS
        "8.8.4.4/32".parse().unwrap(), // Google secondary
        "1.1.1.1/32".parse().unwrap(), // Cloudflare DNS
        "1.0.0.1/32".parse().unwrap(), // Cloudflare secondary
        "9.9.9.9/32".parse().unwrap(), // Quad9 DNS
        // ☁️ Cloud metadata services (AWS, Azure, GCP
        "169.254.169.254/32".parse().unwrap(), // Metadata service for cloud VMs
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
    println!("ips:\n{:#?}", ips);
}
