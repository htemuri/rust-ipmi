use std::net::{Ipv4Addr, UdpSocket};

use crate::{
    ipmi::{
        data::{
            app::{
                channel::{
                    self, GetChannelAuthCapabilitiesRequest, GetChannelAuthCapabilitiesResponse,
                    Privilege,
                },
                cipher::{GetChannelCipherSuitesRequest, GetChannelCipherSuitesResponse},
            },
            commands::Command,
        },
        ipmi_header::AuthType,
        payload::{
            self,
            ipmi_payload::IpmiPayload,
            ipmi_payload_response::{CompletionCode, IpmiPayloadResponse},
        },
        rmcp_payloads::{
            rakp::RAKPMessage,
            rmcp_open_session::{
                AuthAlgorithm, ConfidentialityAlgorithm, IntegrityAlgorithm, RMCPPlusOpenSession,
                RMCPPlusOpenSessionRequest, StatusCode,
            },
        },
    },
    packet::packet::{Packet, Payload},
};

pub struct Connection {
    pub state: State,
    cipher_list_index: u8,
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
            cipher_list_index: 0,
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
            cipher_list_index: 0,
            client_socket: { UdpSocket::bind("0.0.0.0:5000").expect("Can't bind to the port") },
            ipmi_server_ip_addr,
            username: Some(username),
            password_encrypted: Some(password),
            auth_type: AuthType::RmcpPlus,
        }
    }

    pub fn establish_connection(&mut self) {
        let discovery_req =
            GetChannelAuthCapabilitiesRequest::new(true, channel::Privilege::Administrator)
                .create_packet(self, 0x00, 0x00, None);

        self.client_socket
            .send(&discovery_req.to_bytes())
            .expect("couldn't send message");

        let mut recv_buff = [0; 8092];

        while let Ok((n, _addr)) = self.client_socket.recv_from(&mut recv_buff) {
            // println!("response slice: {:x?}", &recv_buff[..n]);
            let response = Packet::from_slice(&recv_buff[..n]);
            if let Some(Payload::Ipmi(IpmiPayload::Response(payload))) = response.payload {
                // println!("RESPONSE: {:?}", payload);
                self.handle_completion_code(payload)
            } else {
                println!("Not an IPMI Response!");
                self.handle_status_code(response.payload);
            }
        }
    }

    fn handle_completion_code(&mut self, response_payload: IpmiPayloadResponse) {
        match response_payload.completion_code {
            CompletionCode::CompletedNormally => match response_payload.command {
                Command::GetChannelAuthCapabilities => {
                    let response =
                        GetChannelAuthCapabilitiesResponse::from_slice(&response_payload.data);
                    println!("{:x?}", response);
                    self.auth_type = AuthType::RmcpPlus;
                    let cipher_packet =
                        GetChannelCipherSuitesRequest::default().create_packet(self);
                    // println!("created packet");
                    // println!("FIRST CIPHER PACKET: {:x?}", cipher_packet);
                    self.client_socket
                        .send(&cipher_packet.to_bytes())
                        .expect("couldn't send message");
                    // println!("sent packet");
                }
                Command::GetChannelCipherSuites => {
                    let response =
                        GetChannelCipherSuitesResponse::from_slice(&response_payload.data);
                    println!("{:x?}", response);
                    match response.is_last() {
                        false => {
                            self.cipher_list_index += 1;
                            let cipher_packet = GetChannelCipherSuitesRequest::new(
                                0xe,
                                crate::ipmi::ipmi_v2_header::PayloadType::IPMI,
                                true,
                                self.cipher_list_index,
                            )
                            .create_packet(self);
                            // println!("reponse to cipher response: {:x?}", cipher_packet);
                            self.client_socket
                                .send(&cipher_packet.to_bytes())
                                .expect("couldn't send message");
                        }
                        true => {
                            // parse through cipher suite records

                            // begin rmcp open session
                            let rmcp_open_packet = RMCPPlusOpenSessionRequest::new(
                                0,
                                Privilege::Reserved,
                                0xa0a2a3a4,
                                AuthAlgorithm::RakpHmacSha256,
                                IntegrityAlgorithm::HmacSha256128,
                                ConfidentialityAlgorithm::AesCbc128,
                            )
                            .create_packet(&self);
                            self.client_socket
                                .send(&rmcp_open_packet.to_bytes())
                                .expect("couldn't send message");
                        }
                    }
                }
                _ => {
                    println!("command of response: {:x?}", response_payload.command)
                }
            },
            _ => {
                println!("Completion code: {:x?}", response_payload.completion_code)
            }
        }
    }

    fn handle_status_code(&mut self, response_payload: Option<Payload>) {
        if let Some(Payload::RMCP(RMCPPlusOpenSession::Response(payload))) = response_payload {
            match payload.rmcp_plus_status_code {
                StatusCode::NoErrors => {
                    // send rakp message 1
                    println!("{:x?}", payload)
                }
                _ => todo!(),
            }
        }
        // if let Payload::RAKP(RAKPMessage::Message2(payload)) = response_payload {
        //     match payload.rmcp_plus_status_code {
        //         StatusCode::NoErrors => {
        //             // send rakp message 1
        //             println!("{:x?}", payload)
        //         }
        //         _ => todo!(),
        //     }
        // }
    }
    // pub fn send(&self, slice: &[u8]) {
    //     let packet = Packet::from_slice(slice, slice.len());

    //     self.client_socket
    //         .connect(format!("{}:{}", &self.ipmi_server_ip_addr, 623))
    //         .expect(format!("Can't connect to {}:{}", &self.ipmi_server_ip_addr, &623).as_str());

    //     self.client_socket
    //         .send(&packet.to_bytes())
    //         .expect("couldn't send message");

    //     let mut recv_buff = [0; 8092];
    //     println!("Awaiting responses...");
    //     while let Ok((n, addr)) = self.client_socket.recv_from(&mut recv_buff) {
    //         println!("{} bytes response from {:?}", n, addr);
    //         println!("{:x?}", &recv_buff[..n]);
    //         // println!("{:x?}", Packet::from_slice(&recv_buff, n));
    //     }
    // }
}
