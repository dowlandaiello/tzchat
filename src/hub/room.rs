use super::msg::{Msg, NotifyTxt, PubMsg, StoreMsg};
use actix::{
    prelude::SendError, Actor, ActorFuture, Addr, AsyncContext, Context, ContextFutureSpawner,
    Handler, MailboxError, Recipient, WrapFuture,
};
use std::{collections::HashSet, error::Error, fmt, sync::Arc};
use tokio::time::Duration;

/// The default rooms spawned at program start.
pub const DEFAULT_ROOMS: [&str; 5] = ["general", "freshmen", "sophomores", "juniors", "seniors"];

/// Represents some extraneous condition causing a room to function incorrectly.
#[derive(Debug)]
pub enum RoomError {
    NotAuthorized,
    RoomDoesNotExist,
    MailboxError(MailboxError),
    Misc(String),
}

impl fmt::Display for RoomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAuthorized => write!(f, "not authorized to access this resource"),
            Self::RoomDoesNotExist => write!(f, "room does not exist"),
            Self::MailboxError(e) => e.fmt(f),
            Self::Misc(e) => e.fmt(f),
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

impl Handler<PubMsg> for Room {
    type Result = ();

    fn handle(&mut self, msg: PubMsg, ctx: &mut Self::Context) {
        // Cache the message for the next 24 hours and send it to all clients
        self.cache
            .send(StoreMsg(msg.0))
            .into_actor(self)
            .map(|res, act, _ctx| {
                // After the cache caches the msg, it gives us a copy that we can lend out
                match res {
                    Ok(publishable_msg) => {
                        // While sending to each of the clients, we might encounter some that have
                        // detached. Clean these up
                        let mut removables = vec![];

                        for client in act.clients.iter() {
                            if let Err(e) = client.do_send(publishable_msg.clone()) {
                                match e {
                                    // Since the client is no longer listening, drop it
                                    SendError::Closed(_) => {
                                        info!("dropping closed client #{}", act.clients.len());
                                        removables.push(client.clone());
                                    }
                                    _ => error!("error while broadcasting MSG: {}", e),
                                }
                            }
                        }

                        // Clear dead clients
                        for to_remove in removables {
                            act.clients.remove(&to_remove);
                        }
                    }
                    Err(e) => error!("error while broadcasting MSG: {}", e),
                };
            })
            .spawn(ctx);
    }
}

impl Handler<SubscribeToRoom> for Room {
    type Result = ();

    fn handle(&mut self, msg: SubscribeToRoom, _ctx: &mut Self::Context) {
        // Record the client and inform them of all the messages they missed in the last 24 hours.
        // The cache itself handles this. See cache def
        self.clients.insert(msg.0.clone());
        self.cache.do_send(msg);
    }
}

/// Caches messages sent in the last 24 hours.
#[derive(Default)]
pub struct MsgCache {
    messages: Vec<Arc<Msg>>,
}

impl Actor for MsgCache {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        // After starting, spawn a daemon that automatically clears the cache every 24 hours
        ctx.run_interval(Duration::from_secs(86_400), |act, _ctx| {
            act.messages.clear();
        });
    }
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

impl Handler<SubscribeToRoom> for MsgCache {
    type Result = ();

    fn handle(&mut self, msg: SubscribeToRoom, _ctx: &mut Context<Self>) -> Self::Result {
        info!("beginning bootstrap procedure for a new user");

        // TODO: This is a naive implementation. We'll want to determine the number of messages
        // that can be reliably transferred at once and then lazily load the rest.
        //
        // TODO: Also, we might want to consider caching messages locally and performing some kind
        // of merkel tree negotiation to determine which parts we don't have, although this is a
        // linear history, so a hash might just work (assuming no faulty client logic)
        //
        // Alert the user of all the cached messages
        for new_msg in self.messages.iter() {
            match msg.0.do_send(NotifyTxt(new_msg.clone())) {
                Ok(_) => (),
                Err(e) => warn!("client bootstrap error: {}", e),
            }
        }
    }
}
