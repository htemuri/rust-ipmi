use rust_ipmi::{IPMIClient, NetFn};

fn main() {
    let mut client: IPMIClient =
        IPMIClient::new("192.168.88.10:623").expect("Failed to create ipmi client");

    client
        .establish_connection("root", "")
        .expect("Failed to establish the session with the BMC");

    let response = client.send_raw_request(NetFn::App, 0x3b, Some(vec![0x04]));

    match response {
        Err(err) => println!("Failed to send the raw request; err = {:?}", err),
        Ok(n) => println!("{}", n), // print the response
    }
}
