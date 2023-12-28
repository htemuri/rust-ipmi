// use aes::Aes128;
use aes::{
    cipher::{
        block_padding::Pkcs7, block_padding::ZeroPadding, BlockDecryptMut, BlockEncryptMut,
        KeyIvInit,
    },
    Block,
};
// use block_modes::block_padding::Pkcs7;
// use block_modes::{BlockMode, Cbc};
// use hex_literal::hex;
// use std::env;s

// type Aes128Cbc = Cbc<Aes128, Pkcs7>;

use hmac::{Hmac, Mac};
use sha2::Sha256;
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
        ipmi_header::{AuthType, IpmiHeader},
        ipmi_v2_header::{IpmiV2Header, PayloadType},
        payload::{
            ipmi_payload::{IpmiPayload, NetFn},
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
    packet::{
        self,
        packet::{Packet, Payload},
    },
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
    remote_console_random_number: u128,
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
            remote_console_random_number: 0,
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
            managed_system_session_id: 0,
            max_privilege: Privilege::Administrator,
            remote_console_random_number: 0,
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
        if let Some(Payload::RMCP(RMCPPlusOpenSession::Response(payload))) =
            response_payload.clone()
        {
            match payload.rmcp_plus_status_code {
                StatusCode::NoErrors => {
                    println!("{:x?}", payload);
                    self.state = State::Authentication;
                    self.max_privilege = payload.max_privilege;
                    self.managed_system_session_id = payload.managed_system_session_id;
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
                    println!("{:x?}", payload);
                    println!("RAKP COMPLETED!!!");
                    self.state = State::Established;
                }
                _ => {
                    println!("{:?}", payload.rmcp_plus_status_code);
                }
            }
        }
    }

    fn generate_rakp3_message(&mut self, rakp2_payload: RAKPMessage2) -> Packet {
        let mut rakp2_input_buffer = Vec::new();
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
        // println!("{:x?}", rakp2_input_buffer);

        let mut rakp2_mac_key: [u8; 20] = [0; 20];

        let password = self.password.clone().unwrap();
        password
            .chars()
            .enumerate()
            .for_each(|(index, character)| rakp2_mac_key[index] = character.try_into().unwrap());

        // let rakp2_mac = rakp2_payload
        //     .key_exchange_auth_code
        //     .clone()
        //     .unwrap()
        //     .as_slice();

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

        session_integrity_key_input.push(self.max_privilege.to_u8());
        session_integrity_key_input.push(self.username.clone().unwrap().len().try_into().unwrap());
        self.username
            .clone()
            .unwrap()
            .as_bytes()
            .iter()
            .for_each(|char| session_integrity_key_input.push(char.clone()));

        // let mut vec = Vec::new();
        // let test_input_rakp2 = [
        //     0xa4, 0xa3, 0xa2, 0xa0, 0x00, 0x6c, 0x00, 0x02, 0x42, 0x2d, 0x45, 0xe6, 0x1f, 0xbe,
        //     0x13, 0xf1, 0x65, 0x21, 0x9d, 0x77, 0x45, 0xce, 0x32, 0x56, 0x12, 0x4d, 0x7a, 0x51,
        //     0xa5, 0x18, 0xdf, 0x63, 0xe9, 0x0a, 0xf5, 0xda, 0xea, 0xd1, 0x2b, 0x21, 0x44, 0x45,
        //     0x4c, 0x4c, 0x48, 0x00, 0x10, 0x53, 0x80, 0x34, 0xb6, 0xc0, 0x4f, 0x43, 0x48, 0x32,
        //     0x14, 0x04, 0x72, 0x6f, 0x6f, 0x74,
        // ]
        // let test_input_sik = [
        //     0x3e, 0x41, 0x16, 0x0f, 0xc1, 0x78, 0x89, 0x27, 0xdf, 0x00, 0xd4, 0x56, 0xa3, 0xfb,
        //     0xca, 0x7e, 0x48, 0xbb, 0x15, 0x62, 0xf6, 0xee, 0x8f, 0xce, 0xe4, 0xdc, 0x6d, 0xec,
        //     0xf6, 0xf6, 0x0d, 0x5d, 0x14, 0x04, 0x72, 0x6f, 0x6f, 0x74,
        // ];
        // .as_slice();
        //     a4 a3 a2 a0 00 6c 00 02 42 2d 45 e6 1f be 13 f1
        //  65 21 9d 77 45 ce 32 56 12 4d 7a 51 a5 18 df 63
        //  e9 0a f5 da ea d1 2b 21 44 45 4c 4c 48 00 10 53
        //  80 34 b6 c0 4f 43 48 32 14 04 72 6f 6f 74
        // vec.extend_from_slice(&test_input_rakp2);

        // let test_key: &[u8] = [
        //     0xc0, 0xa0, 0xa2, 0x6a, 0x9c, 0xc0, 0x90, 0x13, 0xfe, 0x31, 0x8e, 0x1e, 0x55, 0xfd,
        //     0xcb, 0xa2, 0x05, 0x15, 0xc6, 0x48, 0x75, 0xa0, 0x0f, 0xed, 0xbf, 0xb5, 0x64, 0x2e,
        //     0xf0, 0x0e, 0xf9, 0xaf,
        // ]
        // .as_slice();

        type HmacSha256 = Hmac<Sha256>;
        // println!("mac key: {:x?}", rakp2_mac_key.as_slice());
        let mut mac = HmacSha256::new_from_slice(rakp2_mac_key.as_slice())
            .expect("HMAC can take key of any size");
        let mut sikmac = HmacSha256::new_from_slice(rakp2_mac_key.as_slice())
            .expect("HMAC can take key of any size");
        // mac.update(rakp3_input_buffer.as_slice());
        mac.update(rakp3_input_buffer.as_slice());
        // mac.rakp3_input_buffer
        // `result` has type `CtOutput` which is a thin wrapper around array of
        // bytes for providing constant time equality check

        let result = mac.finalize();
        // for i in result.
        let auth_bytes = result.into_bytes();
        // let mut mac_sik = HmacSha256::new_from_slice()
        sikmac.update(session_integrity_key_input.as_slice());
        let sik = sikmac.finalize().into_bytes();

        println!("sik {:x?}", sik);
        // for i in 1..64 {
        //     let mut kmac = HmacSha256::new_from_slice(&sik).expect("HMAC can take key of any size");
        //     let vec = vec![2; i];
        //     kmac.update(vec.as_slice());
        //     // println!("k2 input: {:x?}", [0x02; 32]);
        //     let k2 = kmac.finalize().into_bytes();
        //     if k2
        //         == [
        //             0xdb, 0xfd, 0x56, 0x00, 0xcf, 0x9e, 0x85, 0x3b, 0x2a, 0x3d, 0x95, 0xb1, 0xb2,
        //             0x5e, 0xa3, 0xf3, 0x72, 0x9d, 0xec, 0x75, 0x43, 0x10, 0xd4, 0x57, 0x97, 0x5e,
        //             0x1b, 0xb1, 0xce, 0x40, 0xf2, 0x71,
        //         ]
        //         .into()
        //     {
        //         println!("i = {}", i)
        //     }
        //     println!("k2 {:x?}", k2);
        // }
        let mut kmac = HmacSha256::new_from_slice(&sik).expect("HMAC can take key of any size");
        kmac.update(&[2; 20]);
        let k2 = kmac.finalize().into_bytes();
        println!("k2 {:x?}", k2);
        self.k2 = k2.into();
        // println!(
        //     "rakp2 auth code {:x?}",
        //     rakp2_payload.key_exchange_auth_code.as_slice()
        // );
        let mut auth_vec = Vec::new();
        for i in auth_bytes {
            // TryInto::<u8>::try_into(i).unwrap();
            // println!("{}", i);
            auth_vec.push(i)
        }
        self.encrypt_packet(vec![]);
        todo!();
        // println!()

        // auth_vec.extend_from_slice(auth_bytes.try_into().unwrap());

        // send rakp message 3
        let rakp3_packet = RAKPMessage3::new(
            0x0,
            rakp2_payload.rmcp_plus_status_code,
            self.managed_system_session_id,
            Some(auth_vec),
        )
        .create_packet(&self);
        // let test = rakp3_packet.payload.clone().unwrap().to_bytes();
        // println!("{:x?}", rakp3_packet);
        rakp3_packet

        // todo!()
    }

    fn encrypt_packet(&self, payload_bytes: Vec<u8>) {
        type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
        type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
        // type Aes128Cbc = Cbc<Aes128, Pkcs7>;

        let test_packet = IpmiPayloadRawRequest::new(
            NetFn::App,
            Command::SetSessionPrivilegeLevel,
            Some(vec![0x04]),
        )
        .create_packet(&self, 0x0200a800, 0x0000000a);

        // let key = [0x42; 16];
        let key = [
            0x79, 0x8f, 0xe6, 0x1d, 0x60, 0xf5, 0x26, 0xda, 0xea, 0xab, 0x52, 0x6d, 0x1e, 0x34,
            0xf5, 0x77,
        ];
        // let iv = [0x24; 16];
        let iv = [
            0xba, 0x2e, 0x05, 0xfe, 0x94, 0xf3, 0x70, 0x56, 0x8a, 0xee, 0x6e, 0x3c, 0xfe, 0xe1,
            0x4b, 0x51,
        ];
        println!("test packet whole: {:x?}", &test_packet.payload.clone());
        let mut binding = test_packet.payload.clone().unwrap().to_bytes();
        let binding = Self::pad_payload_bytes(&mut binding);
        let plaintext = binding.as_slice();
        // let plaintext = binding.as_slice();
        // let plaintext = [
        //     0x20, 0x18, 0xc8, 0x81, 0x20, 0x3b, 0x4, 0x20, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        //     0x07, 0x07,
        // ]
        // .as_slice();
        println!("test packet: {:x?}", &plaintext);
        // if let x = test_packet.payload.unwrap() {
        //     plaintext = x.to_bytes();
        // };
        // let plaintext = [
        //     0x06, 0xc0, 0x00, 0x8b, 0x00, 0x02, 0x0a, 0x00, 0x00, 0x00, 0x20, 0x00, 0xad, 0xf9,
        //     0x95, 0x36, 0x64, 0x35, 0x8f, 0xcc, 0xec, 0x45, 0x9a, 0x4c, 0xbd, 0x7e, 0xee, 0x39,
        //     0x7e, 0x6a, 0x27, 0x7a, 0x5a, 0xb8, 0xc2, 0x8d, 0x75, 0x67, 0x4a, 0x6c, 0x93, 0x67,
        //     0xa0, 0xae, 0xff, 0xff, 0x02, 0x07,
        // ];
        // let ciphertext = hex!(
        //     "c7fe247ef97b21f07cbdd26cb5d346bf"
        //     "d27867cb00d9486723e159978fb9a5f9"
        //     "14cfb228a710de4171e396e7b6cf859e"
        // );
        // let cipher = Aes128Cbc::new_from_slices(&self.k2, &iv.as_slice()).unwrap();

        // let pos = plaintext.len();

        // let mut buffer = [0u8; 128];

        // buffer[..pos].copy_from_slice(plaintext);

        // let ciphertext = cipher.encrypt(&mut buffer, pos).unwrap();

        // println!("\nCiphertext: {:?}", ciphertext);

        // let cipher = Aes128Cbc::new_from_slices(&self.k2, &iv).unwrap();
        // let mut buf = ciphertext.to_vec();
        // let decrypted_ciphertext = cipher.decrypt(&mut buf).unwrap();

        // println!("\nCiphertext: {:?}", decrypted_ciphertext);

        // encrypt/decrypt in-place
        // buffer must be big enough for padded plaintext
        let mut buf = [0u8; 48];
        // let test = GenericArray::from_slice(plaintext.as_slice());
        // let array: &GenericArray<u8> = GenericArray::from_slice(plaintext.as_slice());
        let pt_len = plaintext.len();
        // let mut block = *Block::from_slice(plaintext);
        // let mut block2 = *Block::from_slice([0; 16].as_slice());
        buf[..pt_len].copy_from_slice(&plaintext);
        // let key = self.k2[..16];
        let ct = Aes128CbcEnc::new(&key.into(), &iv.into())
            // .encrypt_block_b2b_mut(&mut block, &mut block2);
            .encrypt_padded_mut::<aes::cipher::block_padding::NoPadding>(&mut buf, pt_len)
            .unwrap();
        // .encrypt_block_mut(&mut buf.into());
        // println!("out buf: {:x?}", block2);

        println!("ct {:x?}", ct);
        // assert_eq!(ct, &ciphertext[..]);

        // let pt = Aes256CbcDec::new(&self.k2.into(), &iv.into())
        //     .decrypt_padded_mut::<Pkcs7>(&mut buf)
        //     .unwrap();
        // println!("plain text {:x?}", pt)
        // assert_eq!(pt, &plaintext);
    }

    fn pad_payload_bytes(data: &mut Vec<u8>) -> Vec<u8> {
        let length = &data.len();
        if length % 16 == 0 {
            data.to_vec()
        } else {
            let padding_needed = length % 16;
            for i in 1..padding_needed {
                data.push(i.try_into().unwrap());
            }
            data.push((padding_needed - 1).try_into().unwrap());
            data.to_vec()
        }
    }

    // fn decrypt_packet(&self)

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
