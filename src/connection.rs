use std::net::{Ipv4Addr, UdpSocket};

use crate::{
    ipmi::{
        data::{
            app::channel::{self, GetChannelAuthCapabilitiesRequest},
            commands::Command,
        },
        ipmi_header::AuthType,
        payload::{
            ipmi_payload::IpmiPayload,
            ipmi_payload_response::{CompletionCode, IpmiPayloadResponse},
        },
    },
    packet::packet::Packet,
};

pub struct Connection {
    pub state: State,
    pub client_socket: UdpSocket,
    pub ipmi_server_ip_addr: Ipv4Addr,
    pub auth_type: AuthType,
    pub username: Option<String>,
    pub password_encrypted: Option<String>,
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
            client_socket: {
                let socket = UdpSocket::bind("0.0.0.0:5000").expect("Can't bind to the port");
                socket
                    .connect(format!("{}:{}", ipmi_server_ip_addr, 623))
                    .expect(format!("Can't connect to {}:{}", ipmi_server_ip_addr, &623).as_str());
                socket
            },
            ipmi_server_ip_addr,
            username: None,
            password_encrypted: None,
            auth_type: AuthType::None,
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
            password_encrypted: Some(password),
            auth_type: AuthType::RmcpPlus,
        }
    }

    pub fn establish_connection(&self) -> &Connection {
        match self.auth_type {
            AuthType::None => {
                let discovery_req =
                    GetChannelAuthCapabilitiesRequest::new(true, channel::Privilege::Administrator)
                        .create_packet(self, 0x00, 0x00, None);
                println!("{:?}", discovery_req);
                self.client_socket
                    .send(&discovery_req.to_bytes())
                    .expect("couldn't send message");
                let mut recv_buff = [0; 8092];
                if let Ok((n, _addr)) = self.client_socket.recv_from(&mut recv_buff) {
                    let response = Packet::from_slice(&recv_buff, n);
                    if let Some(IpmiPayload::Response(payload)) = response.ipmi_payload {
                        println!("{:?}", payload);
                    }
                    self
                } else {
                    todo!()
                }
            }
            _ => {
                todo!()
            }
        }
    }

    fn _handle_completion_code(
        &self,
        response_payload: IpmiPayloadResponse,
        completion_code: CompletionCode,
    ) {
        match completion_code {
            CompletionCode::CompletedNormally => match response_payload.command {
                Command::GetChannelAuthCapabilities => {}
                _ => todo!(),
            },
            _ => todo!(),
        }
        todo!()
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
