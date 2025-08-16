pub mod packet;
pub mod id;
pub mod crypto;
pub struct DiscoverySettings {
    pub network_id: u64,
    pub broadcast_addr: std::net::SocketAddr,
}

pub struct LanDiscovery {
    pub config: std::sync::Arc<std::sync::Mutex<DiscoverySettings>>,
    connection: Option<std::sync::Arc<std::sync::Mutex<std::net::UdpSocket>>>,
}
impl LanDiscovery {
    pub fn new(addr: std::net::SocketAddr) -> Self {
        let network_id = rand::random::<u64>();
        log::debug!("Creating new Lan Discovery, Network ID: {}", network_id);
        let config = std::sync::Arc::new(std::sync::Mutex::new(DiscoverySettings {
            broadcast_addr: addr,
            network_id,
        }));

        LanDiscovery {
            config,
            connection: None,
        }
    }
    pub fn listen(
        &mut self,
    ) -> Result<std::sync::Arc<std::sync::Mutex<std::net::UdpSocket>>, std::io::Error> {
        let  config = self.config.lock().unwrap();
        let connection = std::net::UdpSocket::bind(config.broadcast_addr)?;
        
        //connection.set_broadcast(true)?;
        let arc = std::sync::Arc::new(std::sync::Mutex::new(connection));

        let mut arc_clone = arc.clone();

        let mut config_clone = self.config.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1024];
            loop {
                let mut socket = arc_clone.lock().unwrap();
                let mut config = config_clone.lock().unwrap();
                match socket.recv_from(&mut buf) {
                    Ok((size, src)) => {
                        println!("Received {} bytes from {}", size, src);

                        // Self::handle_packet(&mut *socket, &mut *config, &buf[..size], src).unwrap()
                    }
                    Err(e) => eprintln!("Recv error: {}", e),
                }
            }
        });
        self.connection = Some(arc.clone());
        Ok(arc)
    }
}
