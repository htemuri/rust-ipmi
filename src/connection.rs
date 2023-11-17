use std::net::{Ipv4Addr, UdpSocket};

use crate::packet::packet::Packet;

pub struct Connection {
    pub state: State,
    pub client_socket: UdpSocket,
    pub ipmi_server_ip_addr: Ipv4Addr,
    auth: bool,
    pub username: Option<String>,
    pub password: Option<String>,
}

pub enum State {
    Discovery,
    // Activation,
    // Active
}

impl Connection {
    // create a new connection
    pub fn new(ipmi_server_ip_addr: Ipv4Addr) -> Connection {
        Connection {
            state: State::Discovery,
            client_socket: { UdpSocket::bind("0.0.0.0:5000").expect("Can't bind to the port") },
            ipmi_server_ip_addr,
            username: None,
            password: None,
            auth: false,
        }
    }

    pub fn new_with_auth(
        ipmi_server_ip_addr: Ipv4Addr,
        username: String,
        password: String,
    ) -> Connection {
        Connection {
            state: State::Discovery,
            client_socket: { UdpSocket::bind("0.0.0.0:5000").expect("Can't bind to the port") },
            ipmi_server_ip_addr,
            username: Some(username),
            password: Some(password),
            auth: true,
        }
    }

    pub fn send(&self, slice: &[u8]) {
        let packet = Packet::from_slice(slice, slice.len());

        self.client_socket
            .connect(format!("{}:{}", &self.ipmi_server_ip_addr, 623))
            .expect(format!("Can't connect to {}:{}", &self.ipmi_server_ip_addr, &623).as_str());

        self.client_socket
            .send(&packet.to_bytes())
            .expect("couldn't send message");

        let mut recv_buff = [0; 8092];
        println!("Awaiting responses...");
        while let Ok((n, addr)) = self.client_socket.recv_from(&mut recv_buff) {
            println!("{} bytes response from {:?}", n, addr);
            println!("{:x?}", &recv_buff[..n]);
            // println!("{:x?}", Packet::from_slice(&recv_buff, n));
        }
    }
}
