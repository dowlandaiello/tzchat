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

use actix::{
    dev::MessageResponse, fut, Actor, ActorFuture, Addr, AsyncContext, Context, Handler,
    StreamHandler, WrapFuture,
};
use actix_web_actors::ws::{Message as WsMessage, ProtocolError, WebsocketContext};
use auth::{AssertContextAccessPermissible, AuthError, Authenticator, RegisterAlias};
use cmd::{Cmd, CmdTypes, JoinRoom};
use msg::{Msg, NotifyTxt, PubMsg};
use room::{Room, RoomError, SubscribeToRoom};
use std::{collections::HashMap, convert::TryInto, sync::Arc};

/// Lists the rooms managed by the hub.
#[derive(Message)]
#[rtype(result = "OpenRooms")]
pub struct ListRooms;

#[derive(MessageResponse)]
pub struct OpenRooms(pub Vec<String>);

/// Houses any number of chat rooms.
#[derive(Default)]
pub struct Hub {
    topics: HashMap<String, Addr<Room>>,
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

impl Handler<ListRooms> for Hub {
    type Result = OpenRooms;

    fn handle(&mut self, _msg: ListRooms, _ctx: &mut Self::Context) -> Self::Result {
        // Clone the list of rooms, since the user will want to manipulate or otherwise display
        // this data (e.g., through serialization). This can't occur if we have a borrow or Arc
        OpenRooms(self.topics.keys().cloned().collect())
    }
}

impl Handler<JoinRoom> for Hub {
    type Result = Result<Addr<Room>, RoomError>;

    fn handle(&mut self, msg: JoinRoom, _ctx: &mut Self::Context) -> Result<Addr<Room>, RoomError> {
        let room = self
            .topics
            .get(msg.0.as_str())
            .ok_or(RoomError::RoomDoesNotExist)?;

        info!("user joined room {}", msg.0);
        room.do_send(SubscribeToRoom(msg.1));

        // TODO: BLOCK NON-PRIVILEGED USERS

        Ok(room.clone())
    }
}

/// A client connected to the hub.
pub struct WsSocket {
    hub: Addr<Hub>,
    auth: Addr<Authenticator>,
    joined_rooms: HashMap<Arc<String>, Addr<Room>>,
}

impl WsSocket {
    pub fn new(hub: Addr<Hub>, auth: Addr<Authenticator>) -> Self {
        Self {
            hub,
            auth,
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
                        let record_room_fut = res.into_actor(self).map(|res, act, ctx| {
                            match res {
                                Ok(res) => match res {
                                    Ok(room_addr) => {
                                        // TODO: Allow for users to be in multiple rooms, but only
                                        // get notifications for rooms that are in the BACKGROUND
                                        act.joined_rooms.clear();
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
                            if let Some(room) = self
                                .joined_rooms
                                .get(&msg.ctx.to_string())
                                .map(|room| room.clone())
                            {
                                let sess_addr = ctx.address();

                                // Ensure that the user is permitted to send messages in the room
                                // and as the user
                                let authenticate_and_pub_msg_fut = self
                                    .auth
                                    .send(AssertContextAccessPermissible {
                                        ctx: Some(msg.ctx.clone()),
                                        sending_alias: Some(msg.sender.clone()),
                                        session: Some(sess_addr),
                                        email: None,
                                    })
                                    .into_actor(self)
                                    .map(move |res, _act, ctx| {
                                        match res
                                            .map_err(|e| AuthError::OauthError(e.to_string()))
                                            .flatten()
                                        {
                                            Ok(_) => {
                                                debug!(
                                                    "publishing message from user {}",
                                                    msg.sender
                                                );
                                                room.do_send(PubMsg(msg))
                                            }
                                            Err(e) => ctx.text(format!("error: {:?}", e)),
                                        }
                                    });

                                ctx.spawn(authenticate_and_pub_msg_fut);
                            } else {
                                ctx.text("error: room does not exist")
                            }
                        }
                        Err(e) => ctx.text(format!("error: {:?}", e)),
                    },
                    // The user wishes to register a new alias
                    CmdTypes::UseAlias => {
                        if let Some(alias) = cmd.args.pop() {
                            // Asynchronously register the alias AND afterwards, ensure no error was
                            // returned. Communicate to the user if one was
                            let register_alias_fut = fut::wrap_future::<_, Self>(
                                self.auth.send(RegisterAlias(alias, ctx.address())),
                            )
                            .map(|res, _act, ctx| match res {
                                Ok(res) => match res {
                                    Ok(_) => (),
                                    Err(e) => ctx.text(format!("error: {:?}", e)),
                                },
                                Err(e) => ctx.text(format!("error: {:?}", e)),
                            });

                            ctx.spawn(register_alias_fut);
                        } else {
                            ctx.text(format!("error: missing alias"))
                        }
                    }
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
