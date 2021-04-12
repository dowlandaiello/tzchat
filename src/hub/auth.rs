use super::WsSocket;
use actix::{Actor, Addr, Context, Handler};
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
    rc::Rc,
};

/// Acquires a semi-permanent, exclusive lock on the username for the user with the given session.
/// The alias shall persist, after the session is closed, but not after the server closes.
#[derive(Message)]
#[rtype(result = "Result<(), AuthError>")]
pub struct RegisterAlias(pub String, pub Addr<WsSocket>);

/// Any error while registering, logging in, accessing a resource, etc.
#[derive(Debug)]
pub enum AuthError {
    AliasTaken,
    SessionNonexistent,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AliasTaken => write!(f, "username taken"),
        }
    }
}

impl Error for AuthError {}

#[derive(Default)]
pub struct Authenticator {
    // The usernames claimed by an individual with a particular email
    user_aliases: HashMap<String, HashSet<Rc<String>>>,

    // All of the usernames claimed by users
    claimed_usernames: HashSet<Rc<String>>,

    // A user's session is represented by their socket connection. A user can be authenticated
    // through one of two ways:
    // - Session token as cookie
    // - Session token generated after google login from email
    sessions: HashMap<Addr<WsSocket>, Rc<String>>,
}

impl Actor for Authenticator {
    type Context = Context<Self>;
}

impl Handler<RegisterAlias> for Authenticator {
    type Result = Result<(), AuthError>;

    fn handle(&mut self, msg: RegisterAlias, ctx: &mut Self::Context) -> Result<(), AuthError> {
        if self.claimed_usernames.contains(&msg.0) {
            return Err(AuthError::AliasTaken);
        }

        let email = self.sessions.get(&msg.1).ok_or(AuthError::SessionNonexistent)?;
        let username = Rc::new(msg.0);

        self.claimed_usernames.insert(username.clone());
        self.user_aliases.entry(email).or_insert([]);
    }
}
