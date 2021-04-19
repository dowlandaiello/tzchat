use super::{
    msg::NotifyTxt,
    room::{Room, RoomError},
};
use actix::{Addr, Message, Recipient};
use std::{error::Error, fmt, str::FromStr, sync::Arc};

pub const CMD_NAMES: [(&str, CmdTypes); 2] =
    [("MSG", CmdTypes::Msg), ("JOIN_ROOM", CmdTypes::JoinRoom)];

/// The types of commands able to be issued by users.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CmdTypes {
    Msg,
    JoinRoom,
}

/// Users issue commands in the following format:
/// CMD␝ARG␝ARG
pub struct Cmd {
    pub kind: CmdTypes,
    pub args: Vec<String>,
}

/// Occurs when a malformed command is parsed.
#[derive(Debug)]
pub enum ParseCmdError {
    NullRequest,
    UnrecognizedCmd,
}

impl fmt::Display for ParseCmdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NullRequest => write!(f, "request was empty"),
            Self::UnrecognizedCmd => write!(f, "unrecognized command"),
        }
    }
}

impl Error for ParseCmdError {}

impl FromStr for Cmd {
    type Err = ParseCmdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts: Vec<String> = s
            .trim()
            .split(super::msg::MSG_ARG_DELIM)
            .map(|s| s.to_owned())
            .collect();

        // A command name must be specified, at least
        if parts.is_empty() {
            return Err(ParseCmdError::NullRequest);
        }

        // Match a command name with a Rust binding
        // See CMD_NAMES const for valid command names
        let raw_cmd = parts.remove(0);
        CMD_NAMES
            .iter()
            .find(|(cmd_name, _)| *cmd_name == raw_cmd)
            .ok_or(ParseCmdError::UnrecognizedCmd)
            .map(|(_, kind)| Self {
                kind: *kind,
                args: parts,
            })
    }
}

/// A message sent to the hub to connect a socket to the room with the given name.
#[derive(Message)]
#[rtype(result = "Result<Addr<Room>, RoomError>")]
pub struct JoinRoom(pub Arc<String>, pub Recipient<NotifyTxt>);
