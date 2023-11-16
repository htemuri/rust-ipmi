use arrayvec::ArrayVec;

use crate::ipmi::payload::ipmi_payload::NetFn;

use super::{app::channel::GetChannelAuthCapabilitiesRequest, data::Data};
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum Command {
    // APP Commands
    GetChannelAuthCapabilities,
}

impl Command {
    pub fn to_u8(&self, net_fn: NetFn) -> u8 {
        todo!()
    }

    pub fn from_u8_and_netfn(command_code: u8, net_fn: NetFn) -> Command {
        todo!()
    }
}

// pub fn data_from_slice(command: Command, slice: &[u8]) -> Option<Box<dyn Data>> {
//     match command {
//         Command::GetChannelAuthCapabilities => Some(Box::new(
//             GetChannelAuthCapabilitiesRequest::from_slice(slice),
//         )),
//     }
// }

// //

// pub trait Data {
//     fn to_bytes(&self) -> ArrayVec<u8, 8092>;
//     fn from_slice<T>(slice: &[u8]) -> Result<T, std::io::ErrorKind>;
// }
