use rust_ipmi::{IPMIClient, IPMIClientError};

fn main() {
    let mut client = IPMIClient::new("192.168.88.10:623").expect("Failed to create ipmi client");
    let _ = client
        .establish_connection("root", "")
        .map_err(|e| println!("{}", e.to_string()));
    let res = client
        .send_raw_request(0x30, 0x30, Some(vec![0x02, 0xff, 0x10]))
        .map_err(|e: IPMIClientError| println!("{}", e));
    let payload = res.unwrap();
    println!("{}", payload)
}
