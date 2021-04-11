use super::msg::{Msg, NotifyTxt, StoreMsg};
use actix::{Actor, Addr, Context, Handler, Recipient, MailboxError};
use std::{collections::HashSet, error::Error, fmt, sync::Arc};

/// The default rooms spawned at program start.
pub const DEFAULT_ROOMS: [&'static str; 5] =
    ["general", "freshmen", "sophomores", "juniors", "seniors"];

/// Represents some extraneous condition causing a room to function incorrectly.
#[derive(Debug)]
pub enum RoomError {
    NotAuthorized,
    RoomDoesNotExist,
    MailboxError(MailboxError),
}

impl fmt::Display for RoomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAuthorized => write!(f, "not authorized to access this resource"),
            Self::RoomDoesNotExist => write!(f, "room does not exist"),
            Self::MailboxError(e) => e.fmt(f),
        }
    }
}

impl Error for RoomError {}

/// Represents a channel or group message.
pub struct Room {
    cache: Addr<MsgCache>,
    clients: HashSet<Recipient<NotifyTxt>>,
}

/// A message passed to a room indicating that a subscription is in order.
#[derive(Message)]
#[rtype(result = "()")]
pub struct SubscribeToRoom(pub Recipient<NotifyTxt>);

impl Default for Room {
    fn default() -> Self {
        Self {
            cache: MsgCache::start_default(),
            clients: HashSet::new(),
        }
    }
}

impl Actor for Room {
    type Context = Context<Self>;
}

impl Handler<SubscribeToRoom> for Room {
    type Result = ();

    fn handle(&mut self, msg: SubscribeToRoom, ctx: &mut Self::Context) {
        self.clients.insert(msg.0);
    }
}

/// Caches messages sent in the last 24 hours.
#[derive(Default)]
pub struct MsgCache {
    messages: Vec<Arc<Msg>>,
}

impl Actor for MsgCache {
    type Context = Context<Self>;
}

impl Handler<StoreMsg> for MsgCache {
    type Result = NotifyTxt;

    // Handle incoming text messages by adding them to the cache
    fn handle(&mut self, msg: StoreMsg, _ctx: &mut Context<Self>) -> Self::Result {
        // Keep a handle for the message to hand out to other clients
        let msg_handle = Arc::new(msg.0);
        self.messages.push(Arc::clone(&msg_handle));

        NotifyTxt(msg_handle)
    }
}
