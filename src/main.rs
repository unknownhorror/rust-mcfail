mod IpGenerator;
use IpGenerator::generate_ips;
#[tokio::main]
async fn main() {
    let ips = generate_ips();
    // println!("ips:\n{:#?}", ips.await);
}
