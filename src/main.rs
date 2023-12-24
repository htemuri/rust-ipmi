pub mod connection;
pub mod helpers;
pub mod ipmi;
pub mod packet;
pub mod rmcp;

use std::net::Ipv4Addr;

use crate::connection::Connection;

fn main() {
    // let dest_ip = String::from("192.168.88.10");
    // let rmcp_port = String::from("623");
    let mut connection = Connection::new(Ipv4Addr::from([192, 168, 88, 10]));
    connection.establish_connection(String::from("root"), String::from(""));
    
}
