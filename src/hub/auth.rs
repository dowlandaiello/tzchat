use super::{msg::MsgContext, WsSocket};
use actix::{Actor, Addr, Context, Handler};
use actix_web::http::Cookie;
use blake3::Hash;
use ed25519_dalek::Keypair;
use oauth2::{CsrfToken, PkceCodeVerifier};
use rand::Rng;
use ring::{
    aead::{Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM},
    error::Unspecified,
};
use std::{
    collections::{HashMap, HashSet},
    default::Default,
    error::Error,
    fmt,
    sync::Arc,
};

/// Returns an error if the given JWT is not valid. Returns the enclosed email if valid.
#[derive(Message)]
#[rtype(result = "Result<(), AuthError>")]
pub struct AssertJwtValid<'a>(pub Cookie<'a>);

/// Instructs the authenticator to treat the session as though it has the identity of the indicated
/// user. Note: do not use this message unless the user has ALREADY been authenticated.
#[derive(Message)]
#[rtype(result = "")]
pub struct AssumeIdentity {
    pub session: Addr<WsSocket>,

    pub email: String,
}

/// Acquires an encrypted unique identifier for a session with the provided auth challenge belongig
/// to it. Encrypted UID should be saved client-side to allow access after client consents.
#[derive(Message)]
#[rtype(result = "Result<Vec<u8>, AuthError>")]
pub struct RegisterSessionChallenge(pub OauthSessionChallenge);

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
    InvalidToken,
    DecryptionError,
    EncryptionError,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AliasTaken => write!(f, "username taken"),
            Self::SessionNonexistent => write!(f, "session does not exist"),
            Self::PermissionDenied => write!(f, "access to the requested resource denied"),
            Self::IllegalAlias => write!(f, "illegal username"),
            Self::InvalidToken => write!(f, "invalid token"),
            Self::DecryptionError => write!(f, "failed to decrypt message"),
            Self::EncryptionError => write!(f, "failed to encrypt message"),
        }
    }
}

impl Error for AuthError {}

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

    // The keypair used by the authenticator to sign claims relating to use identity claims. This
    // bypasses the need for repetitive calls to google cloud, requiring only one call per user per
    // device.
    claimant_keypair: Keypair,

    // The random number generator used by the authenticator
    rng: rand::rngs::ThreadRng,

    // PKCE challenges issued to users, identified by unique UIDs issued to users
    session_challenges: HashMap<Hash, OauthSessionChallenge>,

    // The key used to encrypt cookie / session variables
    cookie_enc_keypair: (
        SealingKey<AuthenticatorUidGen>,
        OpeningKey<AuthenticatorUidGen>,
    ),

    // The nonce generator used for making keypairs and identifying users
    nonce_gen: AuthenticatorUidGen,
}

/// Generates a unique nonce, or UID for a user. Used for encrypting user details and uniquely
/// identifying users. The same nonce should never be used more than once, hence the name.
#[derive(Default)]
pub struct AuthenticatorUidGen {
    // The random number generator used to generate nonces from the seed (index)
    rng: rand::rngs::ThreadRng,
}

impl NonceSequence for AuthenticatorUidGen {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        Ok(Nonce::assume_unique_for_key(self.rng.gen()))
    }
}

/// Oauth sessions must have certain details persisted server-side that are used to ensure that a
/// man-in-the-middle attack isn't happening.
pub struct OauthSessionChallenge {
    // The pkce token itself doesn't need to be persisted. Verifier can be used to ensure integrity
    pkce_code_verifier: PkceCodeVerifier,

    // The token generated by oauth lib. Should be the same returned by the authorization server
    csrf_token: CsrfToken,
}

impl Default for Authenticator {
    fn default() -> Self {
        let mut rng = rand::thread_rng();

        // Generate an initial nonce for the opening and sealing keys
        let mut nonce_gen = AuthenticatorUidGen::default();
        let seed_nonce = nonce_gen.advance().expect("failed to obtain a seed nonce");

        Self {
            user_aliases: Default::default(),
            claimed_usernames: Default::default(),
            sessions: Default::default(),
            claimant_keypair: Keypair::generate(&mut rng),
            cookie_enc_keypair: (
                SealingKey::new(
                    // NOTE: This shouldn't ever fail, but if it does, that's fine, because it will
                    // only fail ONCE, at the very start. Panicking here is completely acceptable.
                    UnboundKey::new(&AES_256_GCM, seed_nonce.as_ref())
                        .expect("failed to obtain a sealing key"),
                    AuthenticatorUidGen::default(),
                ),
                OpeningKey::new(
                    UnboundKey::new(&AES_256_GCM, seed_nonce.as_ref())
                        .expect("failed to obtain an opening key"),
                    AuthenticatorUidGen::default(),
                ),
            ),
            nonce_gen,
            rng,
            session_challenges: HashMap::new(),
        }
    }
}

/*
 * TODO - for tomorrow:
 * [] Add a new message type to decrypt and validate session cookies
 * [] Check for session cookie denoting already logged in on http_entry /index.html call
 * [] Send new session cookie method and await response
 */

impl Actor for Authenticator {
    type Context = Context<Self>;
}

impl<'a> Handler<AssertJwtValid<'a>> for Authenticator {
    type Result = Result<(), AuthError>;

    fn handle(&mut self, msg: AssertJwtValid, _ctx: &mut Self::Context) -> Result<String, AuthError> {
        let mut unencrypted_jwt = msg.0.to_string().into_bytes();
        self.cookie_enc_keypair.1.open_in_place(Aad::empty(), &mut unencrypted_jwt).map_err(|_| AuthError::DecryptionError)?;

        let sig
    }
}

/// Allows the HTTP server to log the user in after checking their identity by verifying ecdsa
/// details.
impl Handler<AssumeIdentity> for Authenticator {
    type Result = ();

    fn handle(&mut self, msg: AssumeIdentity, _ctx: &mut Self::Context) {
        self.sessions.insert(msg.session, Arc::new(msg.email));
    }
}

/// Allows the HTTP server to persist and verify challenge details for OAuth.
impl Handler<RegisterSessionChallenge> for Authenticator {
    type Result = Result<Vec<u8>, AuthError>;

    fn handle(
        &mut self,
        msg: RegisterSessionChallenge,
        _ctx: &mut Self::Context,
    ) -> Result<Vec<u8>, AuthError> {
        // Generate a unique identifier for the user
        let uid = blake3::hash(
            self.nonce_gen
                .advance()
                .map(|nonce| nonce.as_ref())
                .map_err(|_| AuthError::EncryptionError)?,
        );

        // Encrypt the user's session token. The original UID must be cloned, since we need to
        // encrypt and own it
        let mut client_ver = uid.as_bytes().to_vec();
        self.cookie_enc_keypair
            .0
            .seal_in_place_append_tag(Aad::empty(), &mut client_ver)
            .map(|_| client_ver)
            .map_err(|_| AuthError::EncryptionError)
    }
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
