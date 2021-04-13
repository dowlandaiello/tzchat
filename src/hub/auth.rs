use super::{msg::MsgContext, WsSocket};
use actix::{Actor, Addr, Context, Handler};
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
    sync::Arc,
};

/// Acquires a semi-permanent, exclusive lock on the username for the user with the given session.
/// The alias shall persist, after the session is closed, but not after the server closes.
#[derive(Message)]
#[rtype(result = "Result<(), AuthError>")]
pub struct RegisterAlias(pub String, pub Addr<WsSocket>);

/// Produces an authentication error if the session indicated by the address is not allowed to
#[derive(Message)]
#[rtype(result = "Result<(), AuthError>")]
pub struct AssertContextAccessPermissible {
    pub ctx: Option<MsgContext>,
    pub sending_alias: Option<Arc<String>>,
    pub session: Addr<WsSocket>,
}

/// Any error while registering, logging in, accessing a resource, etc.
#[derive(Debug)]
pub enum AuthError {
    AliasTaken,
    SessionNonexistent,
    PermissionDenied,
    IllegalAlias,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AliasTaken => write!(f, "username taken"),
            Self::SessionNonexistent => write!(f, "session does not exist"),
            Self::PermissionDenied => write!(f, "access to the requested resource denied"),
            Self::IllegalAlias => write!(f, "illegal username"),
        }
    }
}

impl Error for AuthError {}

#[derive(Default)]
pub struct Authenticator {
    // The usernames claimed by an individual with a particular email
    user_aliases: HashMap<Arc<String>, HashSet<Arc<String>>>,

    // All of the usernames claimed by users
    claimed_usernames: HashSet<Arc<String>>,

    // A user's session is represented by their socket connection. A user can be authenticated
    // through one of two ways:
    // - Session token as cookie
    // - Session token generated after google login from email
    sessions: HashMap<Addr<WsSocket>, Arc<String>>,
}

impl Actor for Authenticator {
    type Context = Context<Self>;
}

impl Handler<RegisterAlias> for Authenticator {
    type Result = Result<(), AuthError>;

    fn handle(&mut self, msg: RegisterAlias, _ctx: &mut Self::Context) -> Result<(), AuthError> {
        if self.claimed_usernames.contains(&msg.0) {
            return Err(AuthError::AliasTaken);
        }

        match msg {
            RegisterAlias(username, session) => {
                // Don't clone the username around, share a copy between reprs
                let shared_username: Arc<String> = Arc::new(username);
                let email = self
                    .sessions
                    .get(&session)
                    .ok_or(AuthError::SessionNonexistent)?;

                self.claimed_usernames.insert(shared_username.clone());

                // If the user already has some usernames registered, simply add the username to
                // those. Otherwise, create the new record with just the one username.
                if let Some(existing_aliases) = self.user_aliases.get_mut(email) {
                    existing_aliases.insert(shared_username);
                } else {
                    self.user_aliases
                        .insert(email.clone(), vec![shared_username].into_iter().collect());
                }
            }
        }

        Ok(())
    }
}

impl Handler<AssertContextAccessPermissible> for Authenticator {
    type Result = Result<(), AuthError>;

    fn handle(
        &mut self,
        msg: AssertContextAccessPermissible,
        _ctx: &mut Self::Context,
    ) -> Result<(), AuthError> {
        // The usernames associated with the current user. This is found because after the user
        // logs on, their session is matched with an email, which persists between sessions.
        let session_aliases = self
            .user_aliases
            .get(
                self.sessions
                    .get(&msg.session)
                    .ok_or(AuthError::SessionNonexistent)?,
            )
            .ok_or(AuthError::SessionNonexistent)?;

        // If the user is claiming they are in a direct message, ensure that they own the alias
        // they are using in the direct message and that they are IN the message
        if let Some(ctx) = msg.ctx {
            if let MsgContext::Whisper(whisper_members) = ctx {
                if whisper_members
                    .intersection(session_aliases)
                    .next()
                    .is_none()
                {
                    return Err(AuthError::PermissionDenied);
                }
            }
        }

        // Ensure that the user is not claiming to be another person
        if let Some(sender) = msg.sending_alias {
            if !self
                .user_aliases
                .get(
                    self.sessions
                        .get(&msg.session)
                        .ok_or(AuthError::SessionNonexistent)?,
                )
                .ok_or(AuthError::SessionNonexistent)?
                .contains(&sender)
            {
                return Err(AuthError::IllegalAlias);
            }
        }

        Ok(())
    }
}
