use std::net::{ToSocketAddrs, UdpSocket};

use crate::{
    err::ipmi::IPMIClientError,
    ipmi::{
        ipmi_header::AuthType,
        rmcp_payloads::rmcp_open_session::{
            AuthAlgorithm, ConfidentialityAlgorithm, IntegrityAlgorithm,
        },
    },
};

type IPMIResult<T> = Result<T, IPMIClientError>;

#[derive(Debug)]
pub struct IPMIClient {
    client_socket: UdpSocket,
    auth_state: AuthState,
    command_state: Option<CommandState>,
    auth_algorithm: Option<AuthAlgorithm>,
    integrity_algorithm: Option<IntegrityAlgorithm>,
    confidentiality_algorithm: Option<ConfidentialityAlgorithm>,
    auth_type: Option<AuthType>,
    managed_system_session_id: Option<u32>,
    managed_system_guid: Option<u128>,
    remote_console_random_number: Option<u128>,
    sik: Option<[u8; 32]>,
    k1: Option<[u8; 32]>,
    k2: Option<[u8; 32]>,
}
impl IPMIClient {
    /// Adds one to the number given.
    ///
    /// # Examples
    ///
    /// ```
    /// let arg = 5;
    /// let answer = my_crate::add_one(arg);
    ///
    /// assert_eq!(6, answer);
    /// ```
    pub fn new<A: ToSocketAddrs>(ipmi_server_addr: A) -> IPMIResult<IPMIClient> {
        let client_socket =
            UdpSocket::bind("0.0.0.0:0").map_err(|e| IPMIClientError::FailedBind(e))?;
        client_socket
            .connect(ipmi_server_addr)
            .map_err(|e| IPMIClientError::ConnectToIPMIServer(e))?;
        Ok(IPMIClient {
            client_socket,
            auth_state: AuthState::Discovery,
            command_state: None,
            auth_algorithm: None,
            integrity_algorithm: None,
            confidentiality_algorithm: None,
            auth_type: None,
            managed_system_session_id: None,
            managed_system_guid: None,
            remote_console_random_number: None,
            sik: None,
            k1: None,
            k2: None,
        })
    }
}

#[derive(Debug)]
enum AuthState {
    Discovery,
    Authentication,
    Established,
    FailedToEstablish,
}
#[derive(Debug)]

enum CommandState {
    AwaitingResponse,
    ResponseReceived,
}
