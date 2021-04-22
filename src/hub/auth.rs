use super::{msg::MsgContext, WsSocket};
use actix::{Actor, Addr, Context, Handler, ResponseFuture};
use actix_web::{
    dev::HttpResponseBuilder,
    error::ResponseError,
    http::{header, Cookie, StatusCode},
    HttpResponse,
};
use awc::Client;
use blake3::Hash;
use ed25519_dalek::{Keypair, Signature, Signer};
use futures::{future, TryFutureExt};
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AsyncCodeTokenRequest, AuthorizationCode,
    CsrfToken, PkceCodeVerifier, TokenResponse,
};
use rand::Rng;
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
pub struct ExecuteChallenge {
    /// The UID linking the user to their challenge validators
    pub uid_cookie: Cookie<'static>,

    /// The `state` variable returned by Google. Should match our records
    pub csrf_token: CsrfToken,

    /// The token issued by the oauth server to grant access to the email API
    pub authorization_code: AuthorizationCode,

    /// The oauth client to use for acquiring user details
    pub client: Arc<BasicClient>,
}

/// Lists the aliases belonging to the user.
#[derive(Message)]
#[rtype(result = "Result<Vec<Arc<String>>, AuthError>")]
pub struct ListAliases(pub Arc<String>);

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

/// Acquires a unique identifier for a session with the provided auth challenge belongig
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
            Self::SerializationError(_) | Self::OauthError(_) => StatusCode::INTERNAL_SERVER_ERROR,
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
            Self::OauthError(e) => write!(f, "encountered an error while authenticating: {}", e),
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
    claimant_keypair: Arc<Keypair>,

    // The random number generator used by the authenticator
    rng: rand::rngs::ThreadRng,

    // PKCE challenges issued to users, identified by unique UIDs issued to users
    session_challenges: HashMap<Hash, OauthSessionChallenge>,

    // The http client used for interfacing with google oauth APIs
    http_client: Arc<Client>,
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

        Self {
            user_aliases: Default::default(),
            claimed_usernames: Default::default(),
            sessions: Default::default(),
            claimant_keypair: Arc::new(Keypair::generate(&mut rng)),
            rng,
            session_challenges: HashMap::new(),
            http_client: Arc::new(Client::default()),
        }
    }
}

impl Actor for Authenticator {
    type Context = Context<Self>;
}

impl Handler<ExecuteChallenge> for Authenticator {
    type Result = ResponseFuture<Result<String, AuthError>>;

    fn handle(&mut self, msg: ExecuteChallenge, _ctx: &mut Self::Context) -> Self::Result {
        // The user will provide an UNENCRYPTED UID linking to their CSRF and PKCE validators
        let decrypted_challenge_uid =
            if let Some(b64_challenge_uid) = msg.uid_cookie.to_string().split("=").nth(1) {
                if let Ok(challenge_uid) = base64::decode(b64_challenge_uid) {
                    challenge_uid
                } else {
                    return Box::pin(future::ready(Err(AuthError::DecryptionError)));
                }
            } else {
                return Box::pin(future::ready(Err(AuthError::InvalidToken)));
            };

        let http_client = self.http_client.clone();

        /// An email belonging to a user
        #[derive(Deserialize)]
        struct Entry {
            value: String,
        }

        #[derive(Deserialize)]
        struct PeopleApiResponse {
            #[serde(alias = "emailAddresses")]
            email_addresses: Vec<Entry>,
        }

        // Get the verifiers for the user's challenge CSRF and PKCE
        let challenge_verifiers = <&[u8] as TryInto<[u8; 32]>>::try_into(&decrypted_challenge_uid)
            .map_err(|_| AuthError::DecryptionError)
            .and_then(|challenge_uid| {
                self.session_challenges
                    .remove(&Hash::from(challenge_uid))
                    .ok_or(AuthError::SessionNonexistent)
            });

        let jwt_signer = self.claimant_keypair.clone();

        Box::pin(async move {
            let verifiers = challenge_verifiers?;

            // Validate the oauth state
            (verifiers.csrf_token.secret() == msg.csrf_token.secret())
                .then(|| ())
                .ok_or(AuthError::InvalidToken)?;

            // Swap the auth token for an access token
            let access_token = msg
                .client
                .exchange_code(msg.authorization_code)
                .set_pkce_verifier(verifiers.pkce_code_verifier)
                .request_async(async_http_client)
                .map_err(|e| AuthError::OauthError(e.to_string()))
                .map_ok(|token| <String as Clone>::clone(token.access_token().secret()))
                .await?;

            // Use the access token to get the user's EMAIL HHHEEEHHEE
            let mut gapi_response = http_client
                .get("https://people.googleapis.com/v1/people/me?personFields=emailAddresses")
                .bearer_auth(access_token)
                .header("Accept", "application/json")
                .send()
                .map_err(|e| AuthError::OauthError(e.to_string()))
                .await?;
            // Parse the google people API response
            let res = gapi_response
                .json::<PeopleApiResponse>()
                .map_err(|e| AuthError::OauthError(e.to_string()))
                .await?;
            let email = res
                .email_addresses
                .into_iter()
                .map(|entry: Entry| entry.value)
                .find(|email| email.ends_with("@stu.socsd.org"))
                .ok_or(AuthError::NotStudent)?;

            // Generate a JWT from the email
            let jwt = bincode::serialize(&IdentityAttestation {
                sig: jwt_signer.sign(email.as_bytes()),
                email,
            })
            .map_err(|e| AuthError::SerializationError(e.to_string()))?;

            Ok(base64::encode(jwt))
        })
    }
}

impl<'a> Handler<AssertJwtValid<'a>> for Authenticator {
    type Result = Result<String, AuthError>;

    fn handle(
        &mut self,
        msg: AssertJwtValid,
        _ctx: &mut Self::Context,
    ) -> Result<String, AuthError> {
        let b64_jwt = msg
            .0
            .to_string()
            .split("=")
            .nth(1)
            .map(|s| s.to_owned())
            .ok_or(AuthError::InvalidToken)?;

        // The JWT is encoded in base64. Decode it
        let jwt =
            base64::decode(b64_jwt).map_err(|e| AuthError::SerializationError(e.to_string()))?;

        // JWT's are stored as serde/bincode-encoded bytes on the client's end. Deserialize and
        // verify it. Then, move out the email.
        let jwt: IdentityAttestation =
            bincode::deserialize(&jwt).map_err(|e| AuthError::SerializationError(e.to_string()))?;

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
        let uid = blake3::hash(self.rng.gen::<[u8; 32]>().as_ref());

        // Persist the challenge
        self.session_challenges.insert(uid, msg.0);

        // Give the user their unique session ID
        Ok(uid.as_bytes().to_vec())
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

impl Handler<ListAliases> for Authenticator {
    type Result = Result<Vec<Arc<String>>, AuthError>;

    fn handle(
        &mut self,
        msg: ListAliases,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        Ok(self.user_aliases
            .get(&msg.0)
            .map(|aliases| aliases.iter().cloned().collect::<Vec<Arc<String>>>())
            .unwrap_or(Vec::new()))
    }
}
