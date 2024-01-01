use std::net::Ipv4Addr;

use rust_ipmi::{Connection, IPMIClient, IPMIClientError};

fn main() {
    // let dest_ip = String::from("192.168.88.10");
    // let rmcp_port = String::from("623");
    // let mut connection = Connection::new(Ipv4Addr::from([192, 168, 88, 10]));
    // connection.establish_connection(String::from("root"), String::from(""));
    // connection.send_raw_request();
    let client = IPMIClient::new("1.1.2.:623").unwrap_err();
    println!("{:?}", client.to_string())
}
