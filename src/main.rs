use rust_ipmi::{Command, IPMIClient};

fn main() {
    let mut client = IPMIClient::new("192.168.88.10:623").expect("Failed to create ipmi client");
    let _ = client
        .establish_connection("root", "")
        .map_err(|e| println!("{}", e.to_string()));
    let res = client
        .send_raw_request(
            6.try_into().unwrap(),
            Command::SetSessionPrivilegeLevel,
            Some([0x4]),
        )
        .map_err(|e| println!("{}", e.to_string()));
    println!("{:x?}", res)
}
