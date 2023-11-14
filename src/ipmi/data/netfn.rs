pub enum NetFn {
    Chassis(CommandType),
    Bridge(CommandType),
    SensorEvent(CommandType),
    App(CommandType),
    Firmware(CommandType),
    Storage(CommandType),
    Transport(CommandType),
    Reserved,
}

impl NetFn {
    pub fn from_u8(fn_code: u8) -> NetFn {
        if &fn_code % 2 == 0 {
            match fn_code {
                0x06 => NetFn::App(CommandType::Request),
                _ => NetFn::App(CommandType::Request),
            }
        } else {
            match fn_code {
                0x07 => NetFn::App(CommandType::Response),
                _ => NetFn::App(CommandType::Response),
            }
        }
    }
}

pub enum CommandType {
    Request,
    Response,
}
