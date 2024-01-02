use std::net::Ipv4Addr;

use rust_ipmi::{Connection, IPMIClient};

fn main() {
    // let dest_ip = String::from("192.168.88.10");
    // let rmcp_port = String::from("623");
    // let mut connection = Connection::new(Ipv4Addr::from([192, 168, 88, 10]));
    // connection.establish_connection(String::from("root"), String::from(""));
    // connection.send_raw_request();
    let mut client = IPMIClient::new("192.168.88.10:623").expect("Failed to create ipmi client");
    let _ = client
        .establish_connection("rot", "")
        .map_err(|e| println!("{}", e.to_string()));

    // println!("{:?}", client.to_string())
}
