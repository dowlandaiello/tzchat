pub mod cmd;
pub mod msg;
pub mod room;

/// The authentication module also provides name resolution for a google user (i.e., users can
/// claim as many usernames as they want, but no two users can have the same username). Only two
/// rules are enforced by the authentication module:
/// - a user may not access a room they are not privy to
/// - a user may not publish a message if the username they are publishing from is not associated
/// with their current google cookie
pub mod auth;

use actix::{fut, Actor, ActorFuture, Addr, AsyncContext, Context, Handler, StreamHandler};
use actix_web_actors::ws::{Message as WsMessage, ProtocolError, WebsocketContext};
use cmd::{Cmd, CmdTypes, JoinRoom};
use msg::{Msg, NotifyTxt, PubMsg};
use room::{Room, RoomError, SubscribeToRoom};
use auth::Authenticator;
use std::{collections::HashMap, convert::TryInto, sync::Arc};

/// Houses any number of chat rooms.
#[derive(Default)]
pub struct Hub {
    topics: HashMap<String, Addr<Room>>,

    /// The default authenticator utilized by the hub
    pub auth: Authenticator,
}

impl Actor for Hub {
    type Context = Context<Self>;

    fn started(&mut self, _ctx: &mut Context<Self>) {
        for room_name in &room::DEFAULT_ROOMS {
            self.topics
                .insert((*room_name).to_owned(), Room::start_default());
        }
    }
}

impl Handler<JoinRoom> for Hub {
    type Result = Result<Addr<Room>, RoomError>;

    fn handle(&mut self, msg: JoinRoom, _ctx: &mut Self::Context) -> Result<Addr<Room>, RoomError> {
        info!("user joined room {}", msg.0);

        let room = self
            .topics
            .get(msg.0.as_str())
            .ok_or(RoomError::RoomDoesNotExist)?;
        room.do_send(SubscribeToRoom(msg.1));

        // TODO: BLOCK NON-PRIVILEGED USERS

        Ok(room.clone())
    }
}

/// A client connected to the hub.
pub struct WsSocket {
    hub: Addr<Hub>,
    joined_rooms: HashMap<Arc<String>, Addr<Room>>,
}

impl WsSocket {
    pub fn new(hub: Addr<Hub>) -> Self {
        Self {
            hub,
            joined_rooms: HashMap::new(),
        }
    }
}

impl Actor for WsSocket {
    type Context = WebsocketContext<Self>;
}

impl StreamHandler<Result<WsMessage, ProtocolError>> for WsSocket {
    fn handle(&mut self, msg: Result<WsMessage, ProtocolError>, ctx: &mut Self::Context) {
        match msg {
            // Handle all possible top-level websocket messages (defined by mozilla)
            Ok(WsMessage::Ping(msg)) => ctx.pong(&msg),
            Ok(WsMessage::Text(text)) => match text.parse::<Cmd>() {
                Ok(mut cmd) => match cmd.kind {
                    // Handle all of the tz-specific message types
                    CmdTypes::JoinRoom => {
                        let room_name = Arc::new(cmd.args.remove(0));

                        // Join the room
                        let res = self
                            .hub
                            .send(JoinRoom(Arc::clone(&room_name), ctx.address().recipient()));

                        // Record the address of the room after joining
                        let record_room_fut =
                            fut::wrap_future::<_, Self>(res).map(|res, act, ctx| {
                                match res {
                                    Ok(res) => match res {
                                        Ok(room_addr) => {
                                            act.joined_rooms.insert(room_name, room_addr);
                                        }
                                        Err(e) => ctx.text(format!("error: {:?}", e)),
                                    },
                                    Err(e) => ctx.text(format!("error: {:?}", e)),
                                };
                            });

                        ctx.spawn(record_room_fut);
                    }
                    // The user wishes to broadcast a message to other users in the provided context
                    CmdTypes::Msg => match <Cmd as TryInto<Msg>>::try_into(cmd) {
                        Ok(msg) => {
                            if let Some(room) = self.joined_rooms.get(&msg.ctx.to_string()) {
                                room.do_send(PubMsg(msg));
                            } else {
                                ctx.text("error: room does not exist")
                            }
                        }
                        Err(e) => ctx.text(format!("error: {:?}", e)),
                    },
                },
                Err(e) => ctx.text(format!("error: {:?}", e)),
            },
            Ok(WsMessage::Binary(_)) => (),
            _ => (),
        }
    }
}

impl Handler<NotifyTxt> for WsSocket {
    type Result = ();

    fn handle(&mut self, msg: NotifyTxt, ctx: &mut Self::Context) {
        ctx.text(msg.0.to_string())
    }
}
