use std::net::{Ipv4Addr, UdpSocket};

use crate::{
    helpers::utils::{aes_128_cbc_encrypt, hash_hmac_sha_256},
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
            ipmi_payload::IpmiPayload,
            ipmi_payload_response::{CompletionCode, IpmiPayloadResponse},
            ipmi_raw_request::IpmiPayloadRawRequest,
        },
        rmcp_payloads::{
            rakp::{RAKPMessage1, RAKPMessage2, RAKPMessage3, RAKP},
            rmcp_open_session::{
                AuthAlgorithm, ConfidentialityAlgorithm, IntegrityAlgorithm, RMCPPlusOpenSession,
                RMCPPlusOpenSessionRequest, StatusCode,
            },
        },
    },
    packet::packet::{Packet, Payload},
};

pub struct Connection {
    state: State,
    cipher_list_index: u8,
    pub client_socket: UdpSocket,
    pub ipmi_server_ip_addr: Ipv4Addr,
    pub auth_type: AuthType,
    pub username: Option<String>,
    password: Option<String>,
    managed_system_session_id: u32,
    max_privilege: Privilege,
    managed_system_guid: u128,
    remote_console_random_number: u128,
    sik: [u8; 32],
    k1: [u8; 32],
    k2: [u8; 32],
}
#[derive(PartialEq)]
pub enum State {
    Discovery,
    Authentication,
    Established,
}

impl Connection {
    // create a new connection
    pub fn new(ipmi_server_ip_addr: Ipv4Addr) -> Connection {
        Connection {
            state: State::Discovery,
            client_socket: {
                let socket = UdpSocket::bind("0.0.0.0:0").expect("Can't bind to the port");
                socket
                    .connect(format!("{}:{}", ipmi_server_ip_addr, 623))
                    .expect(format!("Can't connect to {}:{}", ipmi_server_ip_addr, &623).as_str());
                socket
            },
            cipher_list_index: 0,
            ipmi_server_ip_addr,
            username: None,
            password: None,
            auth_type: AuthType::None,
            managed_system_session_id: 0,
            max_privilege: Privilege::Administrator,
            managed_system_guid: 0,
            remote_console_random_number: u128::from_le_bytes([
                0xd9, 0xd5, 0x10, 0xa0, 0x0b, 0xf4, 0x7e, 0xd1, 0xdb, 0x1f, 0xfe, 0x09, 0x2f, 0x84,
                0x47, 0x91,
            ]),
            sik: [0; 32],
            k1: [0; 32],
            k2: [0; 32],
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
            client_socket: { UdpSocket::bind("0.0.0.0:0").expect("Can't bind to the port") },
            ipmi_server_ip_addr,
            username: Some(username),
            password: Some(password),
            auth_type: AuthType::RmcpPlus,
            managed_system_guid: 0,
            managed_system_session_id: 0,
            max_privilege: Privilege::Administrator,
            remote_console_random_number: u128::from_le_bytes([
                0xd9, 0xd5, 0x10, 0xa0, 0x0b, 0xf4, 0x7e, 0xd1, 0xdb, 0x1f, 0xfe, 0x09, 0x2f, 0x84,
                0x47, 0x91,
            ]),
            sik: [0; 32],
            k1: [0; 32],
            k2: [0; 32],
        }
    }

    pub fn establish_connection(&mut self, username: String, password: String) {
        self.username = Some(username);
        self.password = Some(password);
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
                if self.state == State::Established {
                    return;
                }
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
                    // println!("{:x?}", response);
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
        if let Some(Payload::RMCP(RMCPPlusOpenSession::Response(payload))) =
            response_payload.clone()
        {
            match payload.rmcp_plus_status_code {
                StatusCode::NoErrors => {
                    println!("{:x?}", payload);
                    self.state = State::Authentication;
                    self.max_privilege = payload.max_privilege;
                    self.managed_system_session_id = payload.managed_system_session_id.clone();
                    // self.username = Some(String::from("root"));
                    // send rakp message 1
                    let rakp1_packet = RAKPMessage1::new(
                        0x0,
                        self.managed_system_session_id,
                        self.remote_console_random_number,
                        true,
                        Privilege::Administrator,
                        self.username.clone().unwrap(),
                    )
                    .create_packet(&self);

                    self.client_socket
                        .send(&rakp1_packet.to_bytes())
                        .expect("couldn't send rakp message 1");
                }
                _ => todo!(),
            }
        }
        // println!("rakp message 2")
        // todo!();
        if let Some(Payload::RAKP(RAKP::Message2(payload))) = response_payload.clone() {
            match payload.rmcp_plus_status_code {
                StatusCode::NoErrors => {
                    println!("{:x?}", payload);
                    let rakp3_packet = self.generate_rakp3_message(payload);

                    self.client_socket
                        .send(&rakp3_packet.to_bytes())
                        .expect("couldn't send rakp message 1");
                }
                _ => {
                    println!("{:?}", payload.rmcp_plus_status_code);
                }
            }
        }

        if let Some(Payload::RAKP(RAKP::Message4(payload))) = response_payload.clone() {
            match payload.rmcp_plus_status_code {
                StatusCode::NoErrors => {
                    // println!("rak4: {:x?}", payload.integrity_check_value.unwrap());
                    let mut input: Vec<u8> = Vec::new();
                    self.remote_console_random_number
                        .to_le_bytes()
                        .map(|x| input.push(x));
                    self.managed_system_session_id
                        .to_le_bytes()
                        .map(|x| input.push(x));
                    self.managed_system_guid
                        .to_le_bytes()
                        .map(|x| input.push(x));
                    let auth_code = hash_hmac_sha_256(self.sik.into(), input);
                    // println!("auth code: {:x?}", &auth_code);

                    if payload.integrity_check_value.clone().unwrap() == auth_code[..16] {
                        println!("RAKP COMPLETED!!!");
                        self.state = State::Established;
                    }
                }
                _ => {
                    println!("{:?}", payload.rmcp_plus_status_code);
                }
            }
        }
    }

    fn generate_rakp3_message(&mut self, rakp2_payload: RAKPMessage2) -> Packet {
        let mut rakp2_input_buffer = Vec::new();
        self.managed_system_guid = rakp2_payload.managed_system_guid;
        rakp2_payload
            .remote_console_session_id
            .to_le_bytes()
            .map(|x| rakp2_input_buffer.push(x));
        self.managed_system_session_id
            .to_le_bytes()
            .map(|x| rakp2_input_buffer.push(x));
        self.remote_console_random_number
            .clone()
            .to_le_bytes()
            .map(|x| rakp2_input_buffer.push(x));
        rakp2_payload
            .managed_system_random_number
            .to_le_bytes()
            .map(|x| rakp2_input_buffer.push(x));
        rakp2_payload
            .managed_system_guid
            .to_le_bytes()
            .map(|x| rakp2_input_buffer.push(x));
        // rakp2_input_buffer.push(self.max_privilege.to_u8());
        rakp2_input_buffer.push(0x14);
        rakp2_input_buffer.push(self.username.clone().unwrap().len().try_into().unwrap());
        self.username
            .clone()
            .unwrap()
            .as_bytes()
            .iter()
            .for_each(|char| rakp2_input_buffer.push(char.clone()));

        let mut rakp2_mac_key: [u8; 20] = [0; 20];

        let password = self.password.clone().unwrap();
        password
            .chars()
            .enumerate()
            .for_each(|(index, character)| rakp2_mac_key[index] = character.try_into().unwrap());

        let mut rakp3_input_buffer = Vec::new();
        rakp2_payload
            .managed_system_random_number
            .to_le_bytes()
            .map(|x| rakp3_input_buffer.push(x));
        rakp2_payload
            .remote_console_session_id
            .to_le_bytes()
            .map(|x| rakp3_input_buffer.push(x));
        // rakp3_input_buffer.push(self.max_privilege.to_u8());
        rakp3_input_buffer.push(0x14);
        rakp3_input_buffer.push(self.username.clone().unwrap().len().try_into().unwrap());
        self.username
            .clone()
            .unwrap()
            .as_bytes()
            .iter()
            .for_each(|char| rakp3_input_buffer.push(char.clone()));

        let mut session_integrity_key_input = Vec::new();
        self.remote_console_random_number
            .clone()
            .to_le_bytes()
            .map(|x| session_integrity_key_input.push(x));
        rakp2_payload
            .managed_system_random_number
            .to_le_bytes()
            .map(|x| session_integrity_key_input.push(x));

        // session_integrity_key_input.push(self.max_privilege.to_u8());
        session_integrity_key_input.push(0x14); // no idea why this should be 10100b. docs say to do whole byte for max privelege which is 100b

        session_integrity_key_input.push(self.username.clone().unwrap().len().try_into().unwrap());
        self.username
            .clone()
            .unwrap()
            .as_bytes()
            .iter()
            .for_each(|char| session_integrity_key_input.push(char.clone()));

        let auth_vec = hash_hmac_sha_256(rakp2_mac_key.into(), rakp3_input_buffer);
        self.sik = hash_hmac_sha_256(rakp2_mac_key.into(), session_integrity_key_input);
        self.k1 = hash_hmac_sha_256(self.sik.into(), [1; 20].into());
        self.k2 = hash_hmac_sha_256(self.sik.into(), [2; 20].into());
        // send rakp message 3
        let rakp3_packet = RAKPMessage3::new(
            0x0,
            rakp2_payload.rmcp_plus_status_code,
            self.managed_system_session_id,
            Some(auth_vec.into()),
        )
        .create_packet(&self);
        rakp3_packet
    }

    pub fn send_raw_request(&self) {
        let raw_request = IpmiPayloadRawRequest::new(
            crate::ipmi::payload::ipmi_payload::NetFn::App,
            Command::SetSessionPrivilegeLevel,
            Some(vec![0x4]),
        )
        .create_packet(self, self.managed_system_session_id, 0x0000000a);

        // println!("raw request packet: {:x?}", raw_request.clone().to_bytes());
        let raw_request_encrypted = raw_request.to_encrypted_bytes(&self.k1, &self.k2).unwrap();
        // println!("raw request encrypted: {:x?}", raw_request_encrypted);
        self.client_socket
            .send(&raw_request_encrypted.as_slice())
            .expect("couldn't send raw request");

        let mut recv_buff = [0; 8092];

        while let Ok((n, _addr)) = self.client_socket.recv_from(&mut recv_buff) {
            println!("raw request response slice: {:x?}", &recv_buff[..n]);
            // let response = Packet::from_slice(&recv_buff[..n]);
            // if let Some(Payload::Ipmi(IpmiPayload::Response(payload))) = response.payload {
            //     // println!("RESPONSE: {:?}", payload);
            //     self.handle_completion_code(payload)
            // } else {
            //     println!("Not an IPMI Response!");
            //     self.handle_status_code(response.payload);
            //     if self.state == State::Established {
            //         return;
            //     }
            // }
        }
    }

    // pub fn get_device_id(&self) {
    //     let packet = Packet::new(
    //         IpmiHeader::V2_0(IpmiV2Header::new(
    //             self.auth_type,
    //             true,
    //             true,
    //             PayloadType::IPMI,
    //             ,
    //             session_seq_number,
    //             payload_length,
    //         )),
    //         payload,
    //     );
    // }
}
