pub mod msg;
pub mod room;
pub mod cmd;

use actix::{Actor, Addr, Context};
use room::Room;
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
