use crate::{
    connection::Connection,
    ipmi::{
        data::app::channel::Privilege,
        ipmi_header::{AuthType, IpmiHeader},
        ipmi_v2_header::{IpmiV2Header, PayloadType},
    },
    packet::packet::{Packet, Payload},
};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]

pub enum RMCPPlusOpenSession {
    Request(RMCPPlusOpenSessionRequest),
    Response(RMCPPlusOpenSessionResponse),
}

impl RMCPPlusOpenSession {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            RMCPPlusOpenSession::Request(request) => request.to_bytes(),
            _ => todo!(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RMCPPlusOpenSessionRequest {
    /*
        1 Message Tag - Selected by remote console. Used by remote console to help match
            responses up with requests. In this case, the corresponding Open Session Response
            that is returned by the BMC. The BMC can use this value to help differentiate retried
            messages from new messages from the remote console.
        2 Requested Maximum Privilege Level (Role)
            [7:4] - Reserved for future definition by this specification, set to 0h
            [3:0] - Requested Maximum Privilege Level (Role).
            0h = Highest level matching proposed algorithms.
            BMC will pick the Cipher Suite returned in the RMCP+ Open Session
            Response by checking the algorithms proposed in the RMCP+ Open
            Session Request against the Cipher Suites available for each privilege
            level, starting with the “OEM Proprietary level” and progressing to lower
            privilege levels until a match is found. The resultant match results in an
            ‘effective’ maximum privilege level for the session. The resultant level is
            returned in the RMCP+ Open Session Response.
            1h = CALLBACK level
            2h = USER level
            3h = OPERATOR level
            4h = ADMINISTRATOR level
            5h = OEM Proprietary level
        3:4 reserved - write as 00_00h
        5:8 Remote Console Session ID. Selected by the remote console to identify packets that
            are received for the given session by the remote console
        9:16 Authentication Payload. Identifies the authentication type that the managed system
            wants to use for the session.
            byte 1 - Payload Type
                00h = authentication algorithm
            byte 2:3 - reserved = 0000h
            byte 4 - Payload Length in bytes (1-based). The total length in bytes of the payload
                including the header (= 08h for this specification).
                00h = Null field (“wildcard”). BMC picks algorithm based on Requested Maximum
                Privilege Level and that matches with the proposed Integrity and Confidentiality
                payloads. If the Requested Maximum Privilege Level is ‘unspecified’ the BMC
                picks algorithm based on the Integrity and Confidentiality algorithm proposals
                starting from the highest privilege level until a match is found.
            byte 5 - Authentication Algorithm
                [7:6] - reserved
                [5:0] - Authentication Algorithm (See Table 13-17, Authentication Algorithm
                    Numbers)
            byte 6:8 - reserved
        17:24 Integrity Payload. Identifies the integrity type that the managed system wants to use for
            the session.
            byte 1 - Payload Type
                01h = integrity algorithm
            byte 2:3 - reserved = 0000h
            byte 4 - Payload Length in bytes (1-based). The total length in bytes of the payload
                including the header (= 08h for this specification).
                00h = Null field (“wildcard”). BMC picks algorithm based on Requested Maximum
                Privilege Level and that matches with the proposed Authentication and
                Confidentiality payloads. If the Requested Maximum Privilege Level is
                ‘unspecified’ the BMC picks algorithm based on the Authentication and
                Intelligent Platform Management Interface Specification
                175
                Confidentiality algorithm proposals starting from the highest privilege level until
                a match is found.
            byte 5 - Integrity Algorithm
                [7:6] - reserved
                [5:0] - Integrity Algorithm (See Table 13-18, Integrity Algorithm Numbers)
            byte 6:8 - reserved
        25:32 Confidentiality Payload. Defined confidentiality algorithms are:
            byte 1 - Payload Type
                02h = confidentiality algorithm
            byte 2:3 - reserved = 0000h
            byte 4 - Payload Length in bytes (1-based). The total length in bytes of the payload
                including the header (= 08h for this specification).
                00h = Null field (“wildcard”). BMC picks algorithm based on Requested Maximum
                Privilege Level and that matches with the proposed Authentication and Integrity
                payloads. If the Requested Maximum Privilege Level is ‘unspecified’ the BMC
                picks algorithm based on the Authentication and Integrity algorithm proposals
                starting from the highest privilege level until a match is found.
            byte 5 - Confidentiality Algorithm
                [7:6] - reserved
                [5:0] - Confidentiality Algorithm (See Table 13-19, Confidentiality Algorithm
                Numbers)
            byte 6:8 - reserved
    */
    pub message_tag: u8,
    pub max_privilege: Privilege,
    pub remote_console_session_id: u32,
    pub authentication_algorithm: AuthAlgorithm,
    pub integrity_algorithm: IntegrityAlgorithm,
    pub confidentiality_algorithm: ConfidentialityAlgorithm,
}

impl RMCPPlusOpenSessionRequest {
    pub fn new(
        message_tag: u8,
        max_privilege: Privilege,
        remote_console_session_id: u32,
        authentication_algorithm: AuthAlgorithm,
        integrity_algorithm: IntegrityAlgorithm,
        confidentiality_algorithm: ConfidentialityAlgorithm,
    ) -> RMCPPlusOpenSessionRequest {
        RMCPPlusOpenSessionRequest {
            message_tag,
            max_privilege,
            remote_console_session_id,
            authentication_algorithm,
            integrity_algorithm,
            confidentiality_algorithm,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(self.message_tag);
        result.push(self.max_privilege.to_u8());
        [0x0, 0x0].map(|x| result.push(x)); // reserved bytes
        u32::to_le_bytes(self.remote_console_session_id).map(|x| result.push(x)); // remote console session id
        result.push(0x0); // auth payload type
        [0x0, 0x0].map(|x| result.push(x)); // reserved bytes
        result.push(0x08); // auth payload len
        result.push(self.authentication_algorithm.to_u8()); // Authentication Algorithm
        [0x0, 0x0, 0x0].map(|x| result.push(x)); // reserved bytes
        result.push(0x01); // integrity payload type
        [0x0, 0x0].map(|x| result.push(x)); // reserved bytes
        result.push(0x08); // integrity payload len
        result.push(self.integrity_algorithm.to_u8()); // integrity Algorithm
        [0x0, 0x0, 0x0].map(|x| result.push(x)); // reserved bytes
        result.push(0x02); // confidentiality payload type
        [0x0, 0x0].map(|x| result.push(x)); // reserved bytes
        result.push(0x08); // confidentiality payload len
        result.push(self.confidentiality_algorithm.to_u8()); // confidentiality Algorithm
        [0x0, 0x0, 0x0].map(|x| result.push(x)); // reserved bytes
        result
    }

    pub fn create_packet(&self) -> Packet {
        let packet = Packet::new(
            IpmiHeader::V2_0(IpmiV2Header::new(
                AuthType::RmcpPlus,
                false,
                false,
                PayloadType::RcmpOpenSessionRequest,
                0,
                0,
                32,
            )),
            Payload::RMCP(RMCPPlusOpenSession::Request(self.clone())),
        );
        packet
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RMCPPlusOpenSessionResponse {
    /*
    1 Message Tag - The BMC returns the Message Tag value that was passed by the remote
        console in the Open Session Request message.
    2 RMCP+ Status Code - Identifies the status of the previous message. If the previous message
        generated an error, then only the Status Code, Reserved, and Remote Console Session ID
        fields are returned. See Table 13-15, RMCP+ and RAKP Message Status Codes. The
        session establishment in progress is discarded at the BMC, and the remote console will need
        to start over with a new Open Session Request message. (Since the BMC has not yet
        delivered a Managed System Session ID to the remote console, it shouldn’t be carrying any
        state information from the prior Open Session Request, but if it has, that state should be
        discarded.)
    3 Maximum Privilege Level (Role) - Indicates the Maximum Privilege Level allowed for the
        session based on the security algorithms that were proposed in the RMCP+ Open Session
        Request.
        [7:4] - Reserved for future definition by this specification, set to 0h
        [3:0] - Requested Maximum Privilege Level (Role).
        0h = unspecified (returned with error completion code).
        1h = CALLBACK level
        2h = USER level
        3h = OPERATOR level
        4h = ADMINISTRATOR level
        5h = OEM Proprietary level
    4 reserved - write as 00h
        Intelligent Platform Management Interface Specification
        176
    5:8 Remote Console Session ID The Remote Console Session ID specified by RMCP+ Open
        Session Request message associated with this response.
    9:12 Managed System Session ID The Session ID selected by the Managed System for this new
        session. A null Session ID (All 0’s) is not valid in this context.
    13:20 Authentication Payload This payload defines the authentication algorithm proposal selected
        by the Managed System to be used for this session (see Table 13-9, RMCP+ Open Session
        Request for the definition of this payload). A single algorithm will be returned. The ‘Null field’
        is not allowed.
    21:28 Integrity Payload This payload defines the integrity algorithm proposal selected by the
        Managed System to be used for this session (see Table 13-9, RMCP+ Open Session
        Request for the definition of this payload). A single algorithm will be returned. The ‘Null field’
        is not allowed.
    29:36 Confidentiality Payload This payload defines the confidentiality algorithm proposal selected by
        the Managed System to be used for this session (see Table 13-9, RMCP+ Open Session
        Request for the definition of this payload). A single algorithm will be returned. The ‘Null field’
        is not allowed
    */
    pub message_tag: u8,
    pub rmcp_plus_status_code: StatusCode,
    pub max_privilege: Privilege,
    pub remote_console_session_id: u32,
    pub managed_system_session_id: u32,
    pub authentication_algorithm: AuthAlgorithm,
    pub integrity_algorithm: IntegrityAlgorithm,
    pub confidentiality_algorithm: ConfidentialityAlgorithm,
}

impl RMCPPlusOpenSessionResponse {
    pub fn from_slice(slice: &[u8]) -> RMCPPlusOpenSessionResponse {
        RMCPPlusOpenSessionResponse {
            message_tag: slice[0],
            rmcp_plus_status_code: StatusCode::from_u8(slice[1]),
            max_privilege: Privilege::from_u8(slice[2]),
            remote_console_session_id: u32::from_le_bytes([slice[4], slice[5], slice[6], slice[7]]),
            managed_system_session_id: u32::from_le_bytes([
                slice[8], slice[9], slice[10], slice[11],
            ]),
            authentication_algorithm: AuthAlgorithm::from_u8(slice[16]),
            integrity_algorithm: IntegrityAlgorithm::from_u8(slice[24]),
            confidentiality_algorithm: ConfidentialityAlgorithm::from_u8(slice[32]),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]

pub enum StatusCode {
    NoErrors,
    InsufficientResources,
    InvalidSessionId,
    InvalidPayloadType,
    InvalidAuthAlgorithm,
    InvalidIntegrityAlgorithm,
    NoMatchingAuthPayload,
    NoMatchingIntegrityPayload,
    InactiveSessionId,
    InvalidRole,
    UnauthorizedRoleRequested,
    InsufficientResourcesForRole,
    InvalidNameLength,
    UnauthorizedName,
    UnauthorizedGUID,
    InvalidIntegrityCheckValue,
    InvalidConfidentialityAlgorithm,
    NoCipherSuiteMatch,
    IllegalParameter,
    Reserved(u8),
}

impl StatusCode {
    pub fn from_u8(value: u8) -> StatusCode {
        match value {
            0x0 => StatusCode::NoErrors,
            0x01 => StatusCode::InsufficientResources,
            0x02 => StatusCode::InvalidSessionId,
            0x03 => StatusCode::InvalidPayloadType,
            0x04 => StatusCode::InvalidAuthAlgorithm,
            0x05 => StatusCode::InvalidIntegrityAlgorithm,
            0x06 => StatusCode::NoMatchingAuthPayload,
            0x07 => StatusCode::NoMatchingIntegrityPayload,
            0x08 => StatusCode::InactiveSessionId,
            0x09 => StatusCode::InvalidRole,
            0xA => StatusCode::UnauthorizedRoleRequested,
            0xB => StatusCode::InsufficientResourcesForRole,
            0xC => StatusCode::InvalidNameLength,
            0xD => StatusCode::UnauthorizedName,
            0xE => StatusCode::UnauthorizedGUID,
            0xF => StatusCode::InvalidIntegrityCheckValue,
            0x10 => StatusCode::InvalidConfidentialityAlgorithm,
            0x11 => StatusCode::NoCipherSuiteMatch,
            0x12 => StatusCode::IllegalParameter,
            0x13..=0xFF => StatusCode::Reserved(value),
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            StatusCode::NoErrors => 0x0,
            StatusCode::InsufficientResources => 0x01,
            StatusCode::InvalidSessionId => 0x02,
            StatusCode::InvalidPayloadType => 0x03,
            StatusCode::InvalidAuthAlgorithm => 0x04,
            StatusCode::InvalidIntegrityAlgorithm => 0x05,
            StatusCode::NoMatchingAuthPayload => 0x06,
            StatusCode::NoMatchingIntegrityPayload => 0x07,
            StatusCode::InactiveSessionId => 0x08,
            StatusCode::InvalidRole => 0x09,
            StatusCode::UnauthorizedRoleRequested => 0xA,
            StatusCode::InsufficientResourcesForRole => 0xB,
            StatusCode::InvalidNameLength => 0xC,
            StatusCode::UnauthorizedName => 0xD,
            StatusCode::UnauthorizedGUID => 0xE,
            StatusCode::InvalidIntegrityCheckValue => 0xF,
            StatusCode::InvalidConfidentialityAlgorithm => 0x10,
            StatusCode::NoCipherSuiteMatch => 0x11,
            StatusCode::IllegalParameter => 0x12,
            StatusCode::Reserved(value) => *value,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]

pub enum AuthAlgorithm {
    RakpNone,
    RakpHmacSha1,
    RakpHmacMd5,
    RakpHmacSha256,
    OEM(u8),
    Reserved(u8),
}

impl AuthAlgorithm {
    pub fn from_u8(value: u8) -> AuthAlgorithm {
        match value {
            0x0 => AuthAlgorithm::RakpNone,
            0x1 => AuthAlgorithm::RakpHmacSha1,
            0x2 => AuthAlgorithm::RakpHmacMd5,
            0x3 => AuthAlgorithm::RakpHmacSha256,
            0xC0..=0xFF => AuthAlgorithm::OEM(value),
            _ => AuthAlgorithm::Reserved(value),
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            AuthAlgorithm::RakpNone => 0x00,
            AuthAlgorithm::RakpHmacSha1 => 0x01,
            AuthAlgorithm::RakpHmacMd5 => 0x02,
            AuthAlgorithm::RakpHmacSha256 => 0x03,
            AuthAlgorithm::OEM(value) => *value,
            AuthAlgorithm::Reserved(value) => *value,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Hash)]

pub enum IntegrityAlgorithm {
    None,
    HmacSha196,
    HmacMd5128,
    Md5128,
    HmacSha256128,
    OEM(u8),
    Reserved(u8),
}

impl IntegrityAlgorithm {
    pub fn from_u8(value: u8) -> IntegrityAlgorithm {
        match value {
            0x0 => IntegrityAlgorithm::None,
            0x1 => IntegrityAlgorithm::HmacSha196,
            0x2 => IntegrityAlgorithm::HmacMd5128,
            0x3 => IntegrityAlgorithm::Md5128,
            0x4 => IntegrityAlgorithm::HmacSha256128,
            0xC0..=0xFF => IntegrityAlgorithm::OEM(value),
            _ => IntegrityAlgorithm::Reserved(value),
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            IntegrityAlgorithm::None => 0x00,
            IntegrityAlgorithm::HmacSha196 => 0x01,
            IntegrityAlgorithm::HmacMd5128 => 0x02,
            IntegrityAlgorithm::Md5128 => 0x03,
            IntegrityAlgorithm::HmacSha256128 => 0x04,
            IntegrityAlgorithm::OEM(value) => *value,
            IntegrityAlgorithm::Reserved(value) => *value,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Hash)]

pub enum ConfidentialityAlgorithm {
    None,
    AesCbc128,
    XRc4128,
    XRc440,
    OEM(u8),
    Reserved(u8),
}

impl ConfidentialityAlgorithm {
    pub fn from_u8(value: u8) -> ConfidentialityAlgorithm {
        match value {
            0x0 => ConfidentialityAlgorithm::None,
            0x1 => ConfidentialityAlgorithm::AesCbc128,
            0x2 => ConfidentialityAlgorithm::XRc4128,
            0x3 => ConfidentialityAlgorithm::XRc440,
            0x30..=0xFF => ConfidentialityAlgorithm::OEM(value),
            _ => ConfidentialityAlgorithm::Reserved(value),
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            ConfidentialityAlgorithm::None => 0x00,
            ConfidentialityAlgorithm::AesCbc128 => 0x01,
            ConfidentialityAlgorithm::XRc4128 => 0x02,
            ConfidentialityAlgorithm::XRc440 => 0x03,
            ConfidentialityAlgorithm::OEM(value) => *value,
            ConfidentialityAlgorithm::Reserved(value) => *value,
        }
    }
}
