use std::{
    fmt,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    vec,
};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct RmcpPacket {
    rmcp_header: RmcpHeader,
    ipmi_message: IpmiMessage,
}

impl RmcpPacket {
    fn serialize(self) -> Vec<u8> {
        let mut serialized: Vec<u8> = Vec::new();
        let mut serialized_header = bincode::serialize(&self.rmcp_header).unwrap();
        serialized.append(&mut serialized_header);
        serialized.append(&mut self.ipmi_message.serialize());
        serialized
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct RmcpHeader {
    version: u8,      // 06h for RCMP v1.0
    reserved: u8,     // 0h
    rcmp_seq_num: u8, // should be 255 for no ACK (ipmi doesn't use RMCP ACK)
    class_of_msg: u8, /*
                      This field identifies the format of the messages that follow this header.
                      All messages of class ASF (6) conform to the formats defined in this
                      specification and can be extended via an OEM IANA.
                      Bit 7 RMCP ACK
                          0 - Normal RMCP message
                          1 - RMCP ACK message Bit
                      6:5 Reserved Bit
                      4:0 Message Class
                          0-5 = Reserved
                          6 = ASF
                          7 = IPMI
                          8 = OEM defined
                          all other = Reserved
                       */
}

// impl fmt::Display for RmcpPacket {
//     fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
//         let mut str = "";
//     }
// }

#[derive(Serialize, Deserialize, Debug)]
struct IpmiMessage {
    header: IpmiHeaderV1_5,
    payload: Vec<u8>,
}

impl IpmiMessage {
    // fn new(self) -> IpmiMessage {

    // }

    fn serialize(self) -> Vec<u8> {
        let mut serialized: Vec<u8> = Vec::new();
        let mut serialized_header = bincode::serialize(&self.header).unwrap();
        serialized.append(&mut serialized_header);
        serialized.append(&mut vec![
            0x20, 0x18, 0xc8, 0x81, 0x00, 0x38, 0x8e, 0x04, 0xb5,
        ]); //20 18 c8 81 00 38 8e 04 b5
        serialized
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct IpmiHeaderV1_5 {
    auth_type: u8,
    session_seq_num: u32,
    session_id: u32,
    message_len: u8,
}
#[derive(Serialize, Deserialize, Debug)]
struct IpmiPayloadV1_5 {
    payload_data: Vec<u8>,
}

// struct AsfMessage {
//     iana_ent_num: u32,
//     message_type: u8,
//     message_tag: u8,
//     reserved: u8,
//     data_length: u8,
//     iana_ent_num_2: u32,
//     oem_defined: u32,
//     supported_ent: u8,
//     supported_int: u8,
//     reserved_2: u64 // 6 bytes
// }

fn main() {
    // let packet;
    let ipmi_header = IpmiHeaderV1_5 {
        auth_type: 0x0,
        session_seq_num: 0x0,
        session_id: 0x0,
        message_len: 0x9,
    };

    let ipmi_payload: IpmiPayloadV1_5 = IpmiPayloadV1_5 {
        payload_data: (&[20, 8, 200, 81, 00, 38, 142, 04, 181]).to_vec(),
    };
    let vector = vec![20, 8, 200, 81, 00, 38, 142, 04, 181];
    let dec: usize = 913;
    let payload_encoded = bincode::serialize(&ipmi_payload).unwrap();
    let test_encode = bincode::serialize(&dec);
    let encoded_size = bincode::serialized_size(&payload_encoded).unwrap();

    // let message: IpmiMessage = IpmiMessage {
    //     header: ipmi_header,
    //     payload: (&[20, 8, 200, 81, 00, 38, 142, 04, 181]).to_vec(),
    // };

    // println!("{:?}", message.serialize());

    // println!("{:?}", test_encode);
    // println!("{encoded_size}");
    // println!("{:?}", vector.len());

    let packet = RmcpPacket {
        rmcp_header: RmcpHeader {
            version: 0x6,
            reserved: 0x0,
            rcmp_seq_num: 0xff,
            class_of_msg: 0x7,
        },
        ipmi_message: IpmiMessage {
            header: ipmi_header,
            payload: (&[20, 8, 200, 81, 00, 38, 142, 04, 181]).to_vec(),
        },
    };

    let encoded: Vec<u8> = packet.serialize(); // bincode::serialize(&packet).unwrap();
    println!("{:x?}", encoded);

    // let test: Vec<u8> = bincode::serialized_size(value)

    let socket = UdpSocket::bind("0.0.0.0:12342").expect("coudn't bind to address");
    socket
        .connect("192.168.88.10:623")
        .expect("couldn't connect to 192.168.88.10");

    let result = socket.send(&encoded).expect("couldn't send message");
    println!("{result}");

    let mut recv_buff = [0; 8092];
    print!("{:?}, ", &recv_buff[1..3]);
    println!("Awaiting responses..."); // self.recv_buff is a [u8; 8092]
    while let Ok((n, addr)) = socket.recv_from(&mut recv_buff) {
        print!("{:x?}, ", &recv_buff[0..n]);
        println!("");
        println!("{} bytes response from {:?}", n, addr);
        // Remaining code not directly relevant to the question
    }
}

// 0000   18 66 da bf 88 9a a8 a1 59 3d a9 35 08 00 45 00
// 0010   00 33 8d 52 40 00 40 11 7b 0e c0 a8 58 fe c0 a8
// 0020   58 0a 89 dd 02 6f 00 1f 32 8a 06 00 ff 07 00 00
// 0030   00 00 00 00 00 00 00 09 20 18 c8 81 00 38 8e 04 b5
