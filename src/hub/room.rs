use super::msg::{Msg, NotifyTxt, StoreMsg};
use actix::{Actor, Addr, Context, Handler, Recipient};
use std::{collections::HashSet, sync::Arc};

/// The default rooms spawned at program start.
pub const DEFAULT_ROOMS: [&'static str; 5] =
    ["general", "freshmen", "sophomores", "juniors", "seniors"];

/// Represents a channel or group message.
pub struct Room {
    cache: Addr<MsgCache>,
    clients: HashSet<Recipient<NotifyTxt>>,
}

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
