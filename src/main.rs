pub mod rmcp_packet;

use crate::ipmi_payload1_5::*;
use crate::rmcp_packet::*;
use std::net::UdpSocket;

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
