pub mod cmd;
pub mod msg;
pub mod room;

use actix::{
    fut,
    prelude::{Future, Request},
    Actor, ActorFuture, Addr, AsyncContext, Context, Handler, 
    StreamHandler,
};
use actix_web_actors::ws::{Message as WsMessage, ProtocolError, WebsocketContext};
use cmd::{Cmd, CmdTypes, JoinRoom};
use msg::NotifyTxt;
use room::{Room, RoomError, SubscribeToRoom};
use std::collections::HashMap;

/// Houses any number of chat rooms.
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

impl Handler<JoinRoom> for Hub {
    type Result = Result<Addr<Room>, RoomError>;

    fn handle(&mut self, msg: JoinRoom, ctx: &mut Self::Context) -> Result<Addr<Room>, RoomError> {
        let room = self.topics.get(&msg.0).ok_or(RoomError::RoomDoesNotExist)?;
        room.do_send(SubscribeToRoom(msg.1));

        // TODO: BLOCK NON-PRIVILEGED USERS

        Ok(room.clone())
    }
}

/// A client connected to the hub.
pub struct WsSocket {
    hub: Addr<Hub>,
    joined_rooms: HashMap<String, Addr<Room>>,
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
                        // Join the room
                        let res = self.hub.send(JoinRoom(cmd.args.remove(0), ctx.address().recipient()));

                        // Record the address of the room after joining
                        let record_room_fut = fut::wrap_future::<_, Self>(res).map(|res, act, ctx| {
                            match res {
                                Ok(v) => {
                                    Ok(())
                                },
                                Err(e) => Err(()),
                            };
                        });

                        ctx.spawn(record_room_fut);
                    }
                    CmdTypes::Msg => (),
                },
                Err(e) => ctx.text(format!("error: {:?}", e)),
            },
            Ok(WsMessage::Binary(bin)) => ctx.binary(bin),
            _ => (),
        }
    }
}

impl Handler<NotifyTxt> for WsSocket {
    type Result = ();

    fn handle(&mut self, msg: NotifyTxt, ctx: &mut Self::Context) {}
}
