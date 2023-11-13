pub mod data;

use std::collections::{hash_map, HashMap};

// use super::IpmiPayload1_5;
// use crate::ipmi_payload1_5::commands::data::*;

pub enum PayloadType {
    Request,
    Response,
}

// fn parse_data(command_code: u8, data: &[u8], payload_type: PayloadType) -> impl Data {
//     let command_dictionary = HashMap::from([(
//         0x38,
//         (
//             GetChannelAuthCapabilitiesRequest::from_slice(data),
//             GetChannelAuthCapabilitiesResponse::from_slice(data),
//         ),
//     )]);
//     match payload_type {
//         PayloadType::Request => command_dictionary.get(&command_code).unwrap().0,
//         PayloadType::Response => command_dictionary.get(&command_code).unwrap().1,
//     }
// }
