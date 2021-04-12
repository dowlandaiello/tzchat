use actix::{Actor, Addr, Context, Handler};
use super::WsSocket;
use std::{collections::{HashMap, HashSet}, sync::Weak, fmt};

/// Acquires a semi-permanent, exclusive lock on the username for the user with the given session.
/// The alias shall persist, after the session is closed, but not after the server closes.
#[derive(Message)]
#[rtype(result = "Result<(), AuthError>")]
pub struct RegisterAlias(pub String, pub Addr<WsSocket>);

/// Any error while registering, logging in, accessing a resource, etc.
#[derive(Debug)]
pub enum AuthError {
    AliasTaken,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AliasTaken => write!(f, "username taken"),
        }
    }
}

#[derive(Default)]
pub struct Authenticator {
    // The usernames claimed by an individual with a particular email
    claimed_usernames: HashMap<String, HashSet<String>>,

    // A user's session is represented by their socket connection. A user can be authenticated
    // through one of two ways:
    // - Session token as cookie
    // - Session token generated after google login from email
    sessions: HashMap<Addr<WsSocket>, Weak<String>>,
}

impl Actor for Authenticator {
    type Context = Context<Self>;
}

impl Handler<RegisterAlias> for Authenticator {
    type Result = Result<(), AuthError>;

    fn handle(&mut self, msg: RegisterAlias, ctx: &mut Self::Context) -> Result<(), AuthError> {
        if self.claimed_usernames.contains(msg.0) {
            
        }
    }
}
