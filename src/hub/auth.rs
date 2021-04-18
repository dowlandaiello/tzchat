use super::{msg::MsgContext, WsSocket};
use actix::{Actor, Addr, Context, Handler, ResponseFuture};
use actix_web::{
    dev::HttpResponseBuilder,
    error::ResponseError,
    http::{header, Cookie, StatusCode},
    HttpResponse,
};
use blake3::Hash;
use ed25519_dalek::{Keypair, Signature};
use futures::{future, FutureExt, TryFutureExt};
use oauth2::{
    basic::BasicClient, reqwest::{async_http_client, self}, AsyncCodeTokenRequest, AuthorizationCode,
    CsrfToken, PkceCodeVerifier,
};
use rand::Rng;
use ring::{
    aead::{Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM},
    error::Unspecified,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
    default::Default,
    error::Error,
    fmt,
    sync::Arc,
};

/// Two types of sessions exist: ones used for challenges, which are destroyed in a very short
/// timeframe, and longer-term sessions used for identification until the user deletes them.
pub const HTTP_JWT_COOKIE_NAME: &str = "perm_session";

/// See above
pub const HTTP_CHALLENGE_COOKIE_NAME: &str = "oauth_session";

/// Asserts that the oauth challenge has retained its integrity, while issuing the user a
/// longer-term JWT session token for WS communication.
#[derive(Message)]
#[rtype(result = "Result<String, AuthError>")]
pub struct ExecuteChallenge<'a> {
    /// The encrypted UID linking the user to their challenge validators
    pub uid_cookie: Cookie<'a>,

    /// The `state` variable returned by Google. Should match our records
    pub csrf_token: CsrfToken,

    /// The token issued by the oauth server to grant access to the email API
    pub authorization_code: AuthorizationCode,

    /// The oauth client to use for acquiring user details
    pub client: &'a BasicClient,
}

/// Returns an error if the given JWT is not valid. Returns the enclosed email if valid.
#[derive(Message)]
#[rtype(result = "Result<String, AuthError>")]
pub struct AssertJwtValid<'a>(pub Cookie<'a>);

/// A JWT issued and signed by the server attesting that the user owns the email.
#[derive(Serialize, Deserialize)]
pub struct IdentityAttestation {
    /// The email the server attests that the user owns
    pub email: String,

    /// The attestation
    pub sig: Signature,
}

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
    NotStudent,
    IllegalAlias,
    InvalidToken,
    DecryptionError,
    EncryptionError,
    OauthError(String),
    SerializationError(String),
}

/// Clears all of the session cookies for a response.
macro_rules! clear_cookies {
    ($res:ident) => {{
        $res.del_cookie(HTTP_JWT_COOKIE_NAME);
        $res.del_cookie(HTTP_CHALLENGE_COOKIE_NAME);

        $res
    }};
}

impl ResponseError for AuthError {
    fn error_response(&self) -> HttpResponse {
        // Generate a base response
        let mut res = HttpResponseBuilder::new(self.status_code())
            .set_header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(self.to_string());

        // Perform additional functions to safeguard user functionality
        match self {
            Self::SessionNonexistent => clear_cookies!(res),
            Self::InvalidToken => clear_cookies!(res),
            _ => res,
        }
    }

    fn status_code(&self) -> StatusCode {
        match self {
            Self::AliasTaken => StatusCode::CONFLICT,
            Self::SessionNonexistent => StatusCode::UNAUTHORIZED,
            Self::PermissionDenied | Self::NotStudent => StatusCode::FORBIDDEN,
            Self::IllegalAlias | Self::InvalidToken => StatusCode::BAD_REQUEST,
            Self::DecryptionError | Self::EncryptionError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::SerializationError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AliasTaken => write!(f, "username taken"),
            Self::SessionNonexistent => write!(f, "session does not exist"),
            Self::PermissionDenied => write!(f, "access to the requested resource denied"),
            Self::NotStudent => write!(f, "tzhs.chat is only accessible to students with @stu.socsd.org emails at this point in time"),
            Self::IllegalAlias => write!(f, "illegal username"),
            Self::InvalidToken => write!(f, "invalid token"),
            Self::DecryptionError => write!(f, "failed to decrypt message"),
            Self::EncryptionError => write!(f, "failed to encrypt message"),
            Self::SerializationError(e) => write!(f, "failed to serialize message: {}", e),
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
    pub(crate) pkce_code_verifier: PkceCodeVerifier,

    // The token generated by oauth lib. Should be the same returned by the authorization server
    pub(crate) csrf_token: CsrfToken,
}

impl Default for Authenticator {
    fn default() -> Self {
        let mut rng = rand::thread_rng();

        // Generate an initial nonce for the opening and sealing keys
        let key_seed: [u8; 32] = rng.gen();

        Self {
            user_aliases: Default::default(),
            claimed_usernames: Default::default(),
            sessions: Default::default(),
            claimant_keypair: Keypair::generate(&mut rng),
            cookie_enc_keypair: (
                SealingKey::new(
                    // NOTE: This shouldn't ever fail, but if it does, that's fine, because it will
                    // only fail ONCE, at the very start. Panicking here is completely acceptable.
                    UnboundKey::new(&AES_256_GCM, key_seed.as_ref())
                        .expect("failed to obtain a sealing key"),
                    AuthenticatorUidGen::default(),
                ),
                OpeningKey::new(
                    UnboundKey::new(&AES_256_GCM, key_seed.as_ref())
                        .expect("failed to obtain an opening key"),
                    AuthenticatorUidGen::default(),
                ),
            ),
            nonce_gen: AuthenticatorUidGen::default(),
            rng,
            session_challenges: HashMap::new(),
        }
    }
}

/*
 * TODO - for tomorrow:
 * [*] Add a new message type to decrypt and validate session cookies
 * [] Check for session cookie denoting already logged in on http_entry /index.html call
 * [] Send new session cookie method and await response
 */

impl Actor for Authenticator {
    type Context = Context<Self>;
}

impl<'a> Handler<ExecuteChallenge<'a>> for Authenticator {
    type Result = ResponseFuture<Result<String, AuthError>>;

    fn handle(&mut self, msg: ExecuteChallenge, ctx: &mut Self::Context) -> Self::Result {
        // The user will provide an ENCRYPTED UID linking to their CSRF and PKCE validators
        let mut decrypted_challenge_uid = msg.uid_cookie.to_string().into_bytes();

        Box::pin(
            future::ready(
                self.cookie_enc_keypair
                    .1
                    .open_in_place(Aad::empty(), &mut decrypted_challenge_uid)
                    .map_err(|_| AuthError::DecryptionError)
                    // Get the verifiers for the user's challenge CSRF and PKCE
                    .and_then(|_| {
                        self.session_challenges
                            .remove(&Hash::from(
                                <Vec<u8> as TryInto<[u8; 32]>>::try_into(decrypted_challenge_uid)
                                    .map_err(|_| AuthError::DecryptionError)?,
                            ))
                            .ok_or(AuthError::SessionNonexistent)
                    }),
            )
            // Swap the auth token for an access token
            .and_then(|challenge_verifiers| {
                msg.client
                    .exchange_code(msg.authorization_code)
                    .set_pkce_verifier(challenge_verifiers.pkce_code_verifier)
                    .request_async(async_http_client)
                    .map_err(|e| AuthError::OauthError(e.to_string()))
            })
        // Use the access token to get the user's EMAIL HHHEEEHHEE
        .and_then(|access_token| {
            // TODO: NOW USE THE ACCESS TOKEN TO GET THE USER'S EMAIL AND GENERATE A JWT THAT'S IT
            // YOU DON'T NEED TO CHECK THE DOMAIN BC THAT HAPPENS ALREADY WITH THE JWT VALID
            // ATTESTATION
            reqwest::get("")
        })
        )
    }
}

impl<'a> Handler<AssertJwtValid<'a>> for Authenticator {
    type Result = Result<String, AuthError>;

    fn handle(
        &mut self,
        msg: AssertJwtValid,
        _ctx: &mut Self::Context,
    ) -> Result<String, AuthError> {
        let mut unencrypted_jwt = msg.0.to_string().into_bytes();
        self.cookie_enc_keypair
            .1
            .open_in_place(Aad::empty(), &mut unencrypted_jwt)
            .map_err(|_| AuthError::DecryptionError)?;

        // JWT's are stored as serde/bincode-encoded bytes on the client's end. Deserialize and
        // verify it. Then, move out the email.
        let jwt: IdentityAttestation = bincode::deserialize(&unencrypted_jwt)
            .map_err(|e| AuthError::SerializationError(e.to_string()))?;

        // Only students in the student domain of SOCSD can log in
        if !jwt.email.ends_with("@stu.socsd.org") {
            return Err(AuthError::NotStudent);
        }

        self.claimant_keypair
            .verify(jwt.email.as_bytes(), &jwt.sig)
            .map(|_| jwt.email)
            .map_err(|_| AuthError::InvalidToken)
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
        let nonce = self
            .nonce_gen
            .advance()
            .map_err(|_| AuthError::EncryptionError)?;
        let uid = blake3::hash(nonce.as_ref());

        // Persist the challenge
        self.session_challenges.insert(uid, msg.0);

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
