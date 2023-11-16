pub mod ipmi;
pub mod rmcp;
// pub mod rmcp_packet;

use std::net::UdpSocket;

use rmcp::rcmp_header::RmcpHeader;

use crate::ipmi::{
    ipmi_header::IpmiHeader, ipmi_v1_header::IpmiV1Header, ipmi_v2_header::IpmiV2Header,
};

fn main() {
    let dest_ip = String::from("192.168.88.10");
    let rmcp_port = String::from("623");

    let rmcp_packet = RmcpHeader::from_slice(&[0x6, 0x0, 0xff, 0x7]);

    let test = rmcp_packet.unwrap().0.to_bytes();

    let ipmi_header =
        IpmiV1Header::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x0, 0x0, 0x0, 0x9]);

    println!("{:x?}", ipmi_header);

    /*
    IPMI V1.5 packet
    18 66 da bf 88 9a a8 a1 59 3d a9 35 08 00 45 00 00 33 47 4d 40 00 40 11 c1 13 c0 a8 58 fe c0 a8 58 0a a8 d5 02 6f 00 1f 32 8a 06 00 ff 07 00 00 00 00 00 00 00 00 00 09 20 18 c8 81 00 38 8e 04 b5


    IPMI V2 packet
    18 66 da bf 88 9a a8 a1 59 3d a9 35 08 00 45 00 00 36 47 4e 40 00 40 11 c1 0f c0 a8 58 fe c0 a8 58 0a a8 d5 02 6f 00 22 32 8d 06 00 ff 07
    06 00 00 00 00 00 00 00 00 00 0a 00
    20 18 c8 81 04 54 0e 00 80 99

     */

    let test = ipmi_header.unwrap().0.to_bytes();

    println!("{:x?}", test);

    let ipmiv2header =
        IpmiV2Header::from_slice(&[0x6, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa, 0x0]);

    println!("{:x?}", ipmiv2header);

    println!("{:x?}", u16::from_le_bytes([0xa, 0x00]));

    for x in 0x10..=0x1F {
        print!("{:x?}, ", x)
    }
    println!();

    // println!("{}", 0b10)

    // let rmcp_header = RmcpHeader {
    //     version: 0x6,
    //     reserved: 0x00,
    //     sequence_number: 0xff,
    //     message_class: 0x7,
    // };

    // let ipmi_payload: IpmiPayload1_5 = IpmiPayload1_5 {
    //     rs_addr: 0x20,
    //     net_fn: 0x06,
    //     rs_lun: 0x00,
    //     rq_addr: 0x81,
    //     rq_seq: 0x00,
    //     rq_lun: 0x00,
    //     cmd: 0x38,
    //     data: vec![0x8e, 0x04],
    //     completion_code: 0,
    // };

    // let ipmi_header: IpmiSessionHeader1_5 = IpmiSessionHeader1_5 {
    //     auth_type: 0x00,
    //     session_seq_number: 0x00,
    //     session_id: 0x00,
    //     payload_length: 0x00,
    //     auth_code: 0x00,
    // };
    // let packet = Packet {
    //     rmcp_header,
    //     ipmi_header,
    //     ipmi_payload,
    // };

    // // start a udp server and listen to requests

    // let socket = UdpSocket::bind("0.0.0.0:5000").expect("Can't bind to the port");

    // socket
    //     .connect(format!("{}:{}", &dest_ip, &rmcp_port))
    //     .expect(format!("Can't connect to {}:{}", &dest_ip, &rmcp_port).as_str());

    // socket
    //     .send(&packet.get_bytes())
    //     .expect("couldn't send message");

    // let mut recv_buff = [0; 8092];
    // println!("Awaiting responses...");
    // while let Ok((n, addr)) = socket.recv_from(&mut recv_buff) {
    //     println!("{} bytes response from {:?}", n, addr);
    //     println!("{:x?}", Packet::from_slice(&recv_buff, &n));
    // }
}
