use crate::parser::AuthType;

#[derive(Debug, Eq, PartialEq, Hash)]
pub struct GetSessionChallengeRequest {
    pub auth_type: AuthType,
    pub username: String,
}

// impl GetSessionChallengeRequest {
//     pub fn new(auth_type: AuthType, username: String) -> GetSessionChallengeRequest {
//         GetSessionChallengeRequest {
//             auth_type,
//             username,
//         }
//     }

//     // fn username_to_bytes()

//     // pub fn to_bytes(&self) -> Vec<u8> {
//     //     let mut result = Vec::new();
//     //     let string_bytes = self.username.as_bytes();
//     //     let mut username
//     //     result.push(self.auth_type.to_u8());
//     //     result.push(self.username.as_bytes())

//     // }
// }
