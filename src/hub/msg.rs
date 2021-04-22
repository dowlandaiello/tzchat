use super::cmd::{Cmd, CmdTypes};
use actix::Message;
use std::{
    collections::HashSet, convert::TryFrom, error::Error, fmt, iter::FromIterator, str::FromStr,
    sync::Arc,
};

/// The character used to separate arguments in a message
pub const MSG_ARG_DELIM: &str = "␝";

/// The character used to separate users in a group
pub const USER_LIST_DELIM: &str = "␟";

#[derive(Clone, Debug)]
pub enum MsgContext {
    /// The message is part of a DM between 2+ users
    Whisper(HashSet<Arc<String>>),

    /// The message was sent in a normal channel
    Channel(String),
}

impl fmt::Display for MsgContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Any number of actors owns users. Downcast to a &str from Rc
            // This design choice was made bc actix doesn't like lifetimes in
            // type signatures.
            Self::Whisper(users) => write!(
                f,
                "{}",
                users
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<&str>>()
                    .join(USER_LIST_DELIM)
            ),
            Self::Channel(c) => c.fmt(f),
        }
    }
}

impl FromStr for MsgContext {
    type Err = ParseMsgError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts: Vec<String> = s.split(USER_LIST_DELIM).map(|s| s.to_owned()).collect();

        // A message can reside in:
        // - a channel (with just a name like #general)
        // - a whisper between >1 users (names separated)
        match parts.len() {
            0 => Err(ParseMsgError::PartsMissing),
            1 => Ok(Self::Channel(parts.remove(0))),
            _ => Ok(Self::Whisper(HashSet::from_iter(
                parts.into_iter().map(|s| Arc::new(s)),
            ))),
        }
    }
}

/// An intermediary representation of a raw text message.
#[derive(Clone)]
pub struct Msg {
    pub ctx: MsgContext,
    pub sender: Arc<String>,
    pub text: Arc<String>,
}

impl fmt::Display for Msg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MSG␝{}␝{}␝{}", self.ctx, self.sender, self.text)
    }
}

impl TryFrom<Cmd> for Msg {
    type Error = ParseMsgError;

    fn try_from(mut c: Cmd) -> Result<Self, Self::Error> {
        if c.kind != CmdTypes::Msg {
            Err(ParseMsgError::ExtraneousCmd)
        } else if c.args.len() < 3 {
            Err(ParseMsgError::PartsMissing)
        } else {
            c.args.remove(0).parse().map(|ctx| Self {
                ctx,
                sender: Arc::new(c.args.remove(0)),
                text: Arc::new(c.args.remove(0)),
            })
        }
    }
}

/// Occurs when a message is malformed (e.g., unrecognized CMD)
#[derive(Debug)]
pub enum ParseMsgError {
    PartsMissing,
    ExtraneousCmd,
}

impl FromStr for Msg {
    type Err = ParseMsgError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(MSG_ARG_DELIM).collect();

        // See display impl
        if parts.len() < 4 {
            return Err(ParseMsgError::PartsMissing);
        }

        // Parsing the context requires string manipulation that could go wrong
        parts[1].parse().map(|ctx| Self {
            ctx,
            sender: Arc::new(parts[2].to_owned()),
            text: Arc::new(parts[3].to_owned()),
        })
    }
}

impl fmt::Display for ParseMsgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PartsMissing => write!(f, "request was missing parts"),
            Self::ExtraneousCmd => write!(f, "command is not a message"),
        }
    }
}

impl Error for ParseMsgError {}

/// A message sent from the hub to a client listening to a topic.
#[derive(MessageResponse, Message, Clone)]
#[rtype(result = "()")]
pub struct NotifyTxt(pub Arc<Msg>);

/// Caches the given message, generating a multiply-owned Msg.
#[derive(Message)]
#[rtype(result = "NotifyTxt")]
pub struct StoreMsg(pub Msg);

/// Publishes the given message.
#[derive(Message)]
#[rtype(result = "()")]
pub struct PubMsg(pub Msg);
