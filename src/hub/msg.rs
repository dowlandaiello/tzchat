use actix::Message;
use std::{fmt, sync::Arc};

/// The character used to separate arguments in a message
pub const MSG_ARG_DELIM: &'static str = "␝";

/// The character used to separate users in a group
pub const USER_LIST_DELIM: &'static str = "␟";

#[derive(Clone)]
pub enum MsgContext {
    /// The message is part of a DM between 2+ users
    Whisper(Vec<String>),

    /// The message was sent in a normal channel
    Channel(String),
}

impl fmt::Display for MsgContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Any number of actors owns users. Downcast to a &str from Rc
            // This design choice was made bc actix doesn't like lifetimes in
            // type signatures.
            Self::Whisper(users) => write!(f, "{}", users.join(USER_LIST_DELIM)),
            Self::Channel(c) => c.fmt(f),
        }
    }
}

/// An intermediary representation of a raw text message.
#[derive(Clone)]
pub struct Msg {
    ctx: MsgContext,
    sender: String,
    text: String,
}

impl fmt::Display for Msg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MSG␝{}␝{}␝{}", self.ctx, self.sender, self.text)
    }
}

/// A message sent from the hub to a client listening to a topic.
#[derive(MessageResponse, Message)]
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
