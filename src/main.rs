use bitvec::{prelude::*, vec};
use serde::{Deserialize, Serialize};
use std::{fmt::format, net::UdpSocket, str::FromStr};
fn main() {
    let dest_ip = String::from("192.168.88.10");
    let rmcp_port = String::from("623");

    let rmcp_header = RmcpHeader {
        version: 0x6,
        reserved: 0x00,
        sequence_number: 0xff,
        message_class: 0x7,
    };

    let ipmi_payload: IpmiPayload1_5 = IpmiPayload1_5 {
        rs_addr: 0x20,
        net_fn: 0x06,
        rs_lun: 0x00,
        rq_addr: 0x81,
        rq_seq: 0x00,
        rq_lun: 0x00,
        cmd: 0x38,
        data: vec![0x8e, 0x04],
        completion_code: 0,
    };

    let ipmi_header: IpmiSessionHeader1_5 = IpmiSessionHeader1_5 {
        auth_type: 0x00,
        session_seq_number: 0x00,
        session_id: 0x00,
        payload_length: 0x00,
        auth_code: 0x00,
    };
    let packet = Packet {
        rmcp_header,
        ipmi_header,
        ipmi_payload,
    };
    // println!("{:x?}", packet.get_bytes());

    // start a udp server and listen to requests

    let socket = UdpSocket::bind("0.0.0.0:5000").expect("Can't bind to the port");

    socket
        .connect(format!("{}:{}", &dest_ip, &rmcp_port))
        .expect(format!("Can't connect to {}:{}", &dest_ip, &rmcp_port).as_str());

    socket
        .send(&packet.get_bytes())
        .expect("couldn't send message");

    let mut recv_buff = [0; 8092];
    println!("Awaiting responses...");
    while let Ok((n, addr)) = socket.recv_from(&mut recv_buff) {
        println!("{} bytes response from {:?}", n, addr);
        println!("{:x?}", Packet::from_slice(&recv_buff, &n));
    }
}
#[derive(Debug)]
struct Packet {
    rmcp_header: RmcpHeader,
    ipmi_header: IpmiSessionHeader1_5,
    ipmi_payload: IpmiPayload1_5,
}

impl Packet {
    fn get_bytes(&self) -> Vec<u8> {
        let rmcp_header_bytes = self.rmcp_header.get_bytes();
        let mut ipmi_header_bytes = self.ipmi_header.get_bytes(&self.ipmi_payload);
        let mut ipmi_payload_bytes = self.ipmi_payload.get_bytes();

        let mut result = Vec::from(rmcp_header_bytes);
        result.append(&mut ipmi_header_bytes);
        result.append(&mut ipmi_payload_bytes);
        result
    }

    fn from_slice(bytes: &[u8; 8092], size: &usize) -> Packet {
        // println!("{:x?}", &bytes[14..*size]);
        Packet {
            rmcp_header: RmcpHeader::from_slice(&bytes[..4]),
            ipmi_header: IpmiSessionHeader1_5::from_slice(&bytes[4..15]),
            ipmi_payload: IpmiPayload1_5::from_slice(&bytes[14..*size]),
        }
    }
}
#[derive(Debug)]
struct RmcpHeader {
    version: u8,
    reserved: u8,
    sequence_number: u8,
    message_class: u8,
}

impl RmcpHeader {
    fn get_bytes(&self) -> [u8; 4] {
        let final_bytes: [u8; 4] = [
            self.version,
            self.reserved,
            self.sequence_number,
            self.message_class,
        ];
        final_bytes
    }
    fn from_slice(bytes: &[u8]) -> RmcpHeader {
        RmcpHeader {
            version: bytes[0],
            reserved: bytes[1],
            sequence_number: bytes[2],
            message_class: bytes[3],
        }
    }
}

struct RmcpData {
    data: [u8],
}

#[derive(Debug)]
struct IpmiSessionHeader1_5 {
    auth_type: u8,
    session_seq_number: u32,
    session_id: u32,
    auth_code: u64,
    payload_length: u8,
}

impl IpmiSessionHeader1_5 {
    fn get_bytes(&self, payload: &IpmiPayload1_5) -> Vec<u8> {
        let mut result = vec![];
        result.push(self.auth_type);
        result.append(&mut bincode::serialize(&self.session_seq_number).unwrap());
        result.append(&mut bincode::serialize(&self.session_id).unwrap());
        result.push(payload.get_bytes().len().try_into().unwrap());
        result
    }

    fn from_slice(bytes: &[u8]) -> IpmiSessionHeader1_5 {
        let session_seq_number: u32 = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        let session_id: u32 = u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]);
        IpmiSessionHeader1_5 {
            auth_type: bytes[0],
            session_seq_number: session_seq_number,
            session_id: session_id,
            auth_code: 0,
            payload_length: bytes[9],
        }
    }
}
#[derive(Debug)]
struct IpmiPayload1_5 {
    rs_addr: u8,
    net_fn: u8,
    rs_lun: u8,
    rq_addr: u8,
    rq_seq: u8,
    rq_lun: u8,
    cmd: u8,
    completion_code: u8,
    data: Vec<u8>,
}

impl IpmiPayload1_5 {
    fn get8bit_checksum(byte_array: &[u8]) -> u8 {
        let answer: u8 = byte_array.iter().fold(0, |a, &b| a.wrapping_add(b));
        255 - answer + 1
    }

    fn join_bits_to_byte(long_bits: u8, short_bits: u8) -> u8 {
        let mut bv: BitVec<u8, Msb0> = bitvec![u8, Msb0; 0;8];
        bv[0..6].store::<u8>(long_bits);
        bv[6..].store::<u8>(short_bits);
        let result = bv[..].load::<u8>();
        result
    }

    fn to_be_endian(byte_array: &Vec<u8>) -> Vec<u8> {
        let mut new: Vec<u8> = byte_array.clone();
        new.sort();
        new.reverse();
        new
    }

    fn from_slice(bytes: &[u8]) -> IpmiPayload1_5 {
        let netfn_rqlun: &BitSlice<u8, Msb0> = BitSlice::<u8, Msb0>::from_element(&bytes[1]);
        let (netfn_slice, rqlun_slice) = (&netfn_rqlun[0..6], &netfn_rqlun[7..8]);
        let netfn = netfn_slice[..].load::<u8>();
        let rqlun = rqlun_slice[..].load::<u8>();

        let rqseq_rslun: &BitSlice<u8, Msb0> = BitSlice::<u8, Msb0>::from_element(&bytes[1]);
        let (rqseq_slice, rslun_slice) = (&rqseq_rslun[0..6], &rqseq_rslun[7..8]);
        let rqseq = rqseq_slice[..].load::<u8>();
        let rslun = rslun_slice[..].load::<u8>();
        let data: Vec<u8> = Vec::from(&bytes[7..bytes.len() - 1]);
        IpmiPayload1_5 {
            rs_addr: bytes[3],
            net_fn: netfn,
            rs_lun: rslun,
            rq_addr: bytes[0],
            rq_seq: rqseq,
            rq_lun: rqlun,
            cmd: bytes[5],
            completion_code: bytes[6],
            data: data,
        }
    }

    fn get_bytes(&self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        let netfn_rslun = Self::join_bits_to_byte(self.net_fn, self.rs_lun);
        let rqseq_rqlun = Self::join_bits_to_byte(self.rq_seq, self.rq_lun);
        let be_data = Self::to_be_endian(&self.data);
        result.push(self.rs_addr);
        result.push(netfn_rslun);
        result.push(Self::get8bit_checksum(&vec![self.rs_addr, netfn_rslun]));
        result.push(self.rq_addr);
        result.push(rqseq_rqlun);
        result.push(self.cmd);
        for &byte in be_data.iter() {
            result.push(byte);
        }
        result.push(Self::get8bit_checksum(&result[3..]));
        result
    }
}

enum IpmiPayLoad {
    Request,
    Response,
}
