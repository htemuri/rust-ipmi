// pub struct Data<T> {
//     pub data: T,
//     pub length: u8,
// }

pub trait Data {
    fn as_bytes(&self) -> &[u8];
    fn from_slice(bytes: &[u8]) -> Self;
}

pub enum GetChannelAuthCapabilities {
    Request {
        channel_num: u8,
        req_max_priv: u8,
    },
    Response {
        completion_code: u8,
        channel_number: u8,
        auth_type_support: u8,
        auth_continued: u8,
        ipmi_capability: u8,
        oem_id: [u8; 3],
        oem_aux_data: u8,
    },
}

impl Data for GetChannelAuthCapabilities {
    fn as_bytes(&self) -> &[u8] {
        todo!()
    }

    fn from_slice(bytes: &[u8]) -> Self {
        todo!()
    }
}

pub struct GetChannelAuthCapabilitiesRequest {
    pub channel_num: u8,
    pub req_max_priv: u8,
}

pub struct GetChannelAuthCapabilitiesResponse {
    pub completion_code: u8,
    pub channel_number: u8,
    pub auth_type_support: u8,
    pub auth_continued: u8,
    pub ipmi_capability: u8,
    pub oem_id: [u8; 3],
    pub oem_aux_data: u8,
}

impl Data for GetChannelAuthCapabilitiesRequest {
    fn from_slice(bytes: &[u8]) -> GetChannelAuthCapabilitiesRequest {
        GetChannelAuthCapabilitiesRequest {
            channel_num: 0x1,
            req_max_priv: 0x1,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        todo!()
    }
}

impl Data for GetChannelAuthCapabilitiesResponse {
    fn from_slice(bytes: &[u8]) -> GetChannelAuthCapabilitiesResponse {
        GetChannelAuthCapabilitiesResponse {
            completion_code: 1,
            channel_number: 1,
            auth_type_support: 1,
            auth_continued: 1,
            ipmi_capability: 1,
            oem_id: [1, 1, 1],
            oem_aux_data: 1,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        todo!()
    }
}
