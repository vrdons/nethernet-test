mod discovery;
fn main() {
    if std::env::var("RUST_LOG").is_err() {
        unsafe {
            std::env::set_var("RUST_LOG", "debug");
        }
    }
    env_logger::init();
    let addr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(192,168,1,255),7551));
    let mut discovery = discovery::LanDiscovery::new(addr);
    discovery.listen().unwrap();
                    loop {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
}
