use super::hub::{
    auth::{
        AssertContextAccessPermissible, AssertJwtValid, AssumeIdentity, AuthError, Authenticator,
        ExecuteChallenge, ListAliases, OauthSessionChallenge, RegisterSessionChallenge,
        HTTP_CHALLENGE_COOKIE_NAME, HTTP_JWT_COOKIE_NAME,
    },
    msg::MsgContext,
    CreateRoom, Hub, ListRooms, WsSocket,
};
use actix::Addr;
use actix_files::NamedFile;
use actix_web::{
    error,
    http::Cookie,
    web::{self, Query},
    Error, HttpMessage, HttpRequest, HttpResponse,
};
use actix_web_actors::ws;
use futures::stream::{self, StreamExt};
use oauth2::{basic::BasicClient, AuthorizationCode, CsrfToken, PkceCodeChallenge, Scope};
use serde::Deserialize;
use std::{collections::HashSet, path::PathBuf, sync::Arc};

// Derives the email from the session cookie
macro_rules! get_session_email {
    ($auth:ident, $req:ident) => {
        // Ask the authenticator to validate and acquire the user's email from the JWT
        $auth
            .send(AssertJwtValid(
                $req.cookie(HTTP_JWT_COOKIE_NAME)
                    .ok_or(AuthError::SessionNonexistent)?,
            ))
            .await
            .map_err(|e| error::ErrorInternalServerError(e))??
    };
}

/// Establishes a websockets connection to the server
pub async fn ws_index(
    req: HttpRequest,
    hub: web::Data<Addr<Hub>>,
    auth: web::Data<Addr<Authenticator>>,
    stream: web::Payload,
) -> Result<HttpResponse, Error> {
    // Ensure both that the JWT session exists and that it is valid
    let jwt_cookie = req
        .cookie(HTTP_JWT_COOKIE_NAME)
        .ok_or(AuthError::InvalidToken)?;
    let email = auth
        .send(AssertJwtValid(jwt_cookie))
        .await
        .map_err(|e| error::ErrorInternalServerError(e))??;

    // Start the websocket chat
    let (session, resp) = ws::start_with_addr(
        WsSocket::new((**hub).to_owned(), (**auth).to_owned()),
        &req,
        stream,
    )
    .map_err(|e| {
        error!("{:?}", e);
        e
    })?;

    // The user has now been authenticated
    auth.do_send(AssumeIdentity { session, email });

    Ok(resp)
}

/// The state and token returned by Google
#[derive(Deserialize)]
pub struct OauthCallbackArgs {
    state: String,
    code: String,
}

/// Handle Google's redirect containing final oauth details.
pub async fn oauth_callback(
    req: HttpRequest,
    Query(oauth_args): Query<OauthCallbackArgs>,
    auth: web::Data<Addr<Authenticator>>,
    client: web::Data<Arc<BasicClient>>,
) -> Result<HttpResponse, Error> {
    // Challenges are persisted between before consent and at callback
    let uid_cookie = req
        .cookie(HTTP_CHALLENGE_COOKIE_NAME)
        .ok_or(AuthError::SessionNonexistent)?;

    match oauth_args {
        OauthCallbackArgs { state, code } => {
            let challenge = ExecuteChallenge {
                uid_cookie,
                csrf_token: CsrfToken::new(state),
                authorization_code: AuthorizationCode::new(code),
                client: (**client).clone(),
            };

            // Let the authenticator exchange the code and validate the user's identity. We will now have
            // a base64 JWT to save in a cookie
            let jwt = auth
                .send(challenge)
                .await
                .map_err(|e| error::ErrorInternalServerError(e))??;

            // Send the user to the homepage and save the JWT as a cookie
            Ok(HttpResponse::TemporaryRedirect()
                .set_header("Location", "/index.html")
                .cookie(Cookie::build(HTTP_JWT_COOKIE_NAME, jwt).path("/").finish())
                .finish())
        }
    }
}

/// Serves the static UI after logging the user in
pub async fn ui_index(
    req: HttpRequest,
    auth: web::Data<Addr<Authenticator>>,
    client: web::Data<Arc<BasicClient>>,
) -> Result<HttpResponse, Error> {
    // Automatically sign the user in before they view the UI if they aren't already (don't verify
    // now. even hackers should be able to view the UI :D)
    if req.cookie(HTTP_JWT_COOKIE_NAME).is_none() {
        // The user is not already logged in on this device. Hence, we need to send them through an
        // oauth flow to get their consent if needed but always get their email and then set a
        // semi-perm session
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let (auth_url, csrf_token) = client
            .authorize_url(CsrfToken::new_random)
            // tzhs.chat only needs one scope, the email scope, to function
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/userinfo.profile".to_owned(),
            ))
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/userinfo.email".to_owned(),
            ))
            .set_pkce_challenge(pkce_challenge)
            .url();

        // Inform the authenticator of our new session challenge details that MUST be verified
        // when /callback is hit
        let challenge_session = auth
            .send(RegisterSessionChallenge(OauthSessionChallenge {
                pkce_code_verifier: pkce_verifier,
                csrf_token,
            }))
            .await
            .map_err(|e| error::ErrorInternalServerError(e))??;

        return Ok(HttpResponse::TemporaryRedirect()
            .set_header("Location", auth_url.as_str())
            // Save the unique identifier for the user's challenge as a session cookie
            .cookie(
                Cookie::build(
                    HTTP_CHALLENGE_COOKIE_NAME,
                    base64::encode(challenge_session),
                )
                .path("/")
                .finish(),
            )
            .finish());
    }

    let path: PathBuf = "static/index.html".parse().unwrap();
    Ok(NamedFile::open(path)?.into_response(&req)?)
}

/// Gets a list of aliases belonging to the currently authenticated user.
pub async fn get_authenticated_aliases(
    req: HttpRequest,
    auth: web::Data<Addr<Authenticator>>,
) -> Result<HttpResponse, Error> {
    // Ask the authenticator to validate and acquire the user's email from the JWT
    let email = get_session_email!(auth, req);

    // Get the authenticated user's aliases. We'll need to clone each of the aliases, since Serde
    // shouldn't do it for us.
    let aliases = auth
        .send(ListAliases(Arc::new(email)))
        .await
        .map_err(|e| error::ErrorInternalServerError(e))??
        .into_iter()
        .map(|arc_alias: Arc<String>| (*arc_alias).clone())
        .collect::<Vec<String>>();

    // Respond with these aliases as JSON
    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .json(aliases))
}

/// Gets a list of the open channels that the user is allowed to be in.
pub async fn get_allowed_rooms(
    req: HttpRequest,
    auth: web::Data<Addr<Authenticator>>,
    hub: web::Data<Addr<Hub>>,
) -> Result<HttpResponse, Error> {
    // Ask the authenticator to validate and acquire the user's email from the JWT
    let sess_email = Arc::new(get_session_email!(auth, req));
    let rooms_stream = stream::iter(
        hub.send(ListRooms)
            .await
            .map_err(|e| error::ErrorInternalServerError(e))?
            .0
            .into_iter(),
    );

    let auth_addr: Addr<Authenticator> = (**auth).clone();

    // Only include rooms in the response that the currently authenticated user has access to
    let rooms: Vec<String> = {
        let auth_addr = &auth_addr;
        let sess_email = &sess_email;

        rooms_stream
            .filter_map(|room| async move {
                auth_addr
                    .clone()
                    .send(AssertContextAccessPermissible {
                        ctx: Some(MsgContext::Channel(room.clone())),
                        session: None,
                        email: Some(sess_email.clone()),
                        sending_alias: None,
                    })
                    .await
                    .map_err(|e| AuthError::OauthError(e.to_string()))
                    .flatten()
                    .ok()
                    .map(|_| room)
            })
            .collect::<Vec<String>>()
            .await
    };

    // Respond with the rooms that the user can view
    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .json(rooms))
}

#[derive(Deserialize)]
pub struct ReqCreateRoom {
    users: Vec<String>,
}

/// Creates a new room from the list of usernames or single channel name given in the request.
#[actix_web::post("/api/room")]
pub async fn create_room(
    req: HttpRequest,
    req_room: web::Json<ReqCreateRoom>,
    auth: web::Data<Addr<Authenticator>>,
    hub: web::Data<Addr<Hub>>,
) -> Result<HttpResponse, Error> {
    // Authenticate the user
    let email = Some(Arc::new(get_session_email!(auth, req)));

    let ReqCreateRoom { mut users } = req_room.0;

    // Turn a Vec<String> into HashSet<Arc<String>>
    let ctx = match users.len() {
        1 => MsgContext::Channel(
                users
                .pop()
                .ok_or(error::ErrorInternalServerError("invalid room"))?,
        ),
        _ => MsgContext::Whisper(
                users
                .into_iter()
                .map(|user| Arc::new(user))
                .collect::<HashSet<Arc<String>>>(),
        ),
    };

    // Ensure the user is allowed to access the channel they want to create
    auth.send(AssertContextAccessPermissible {
        ctx: Some(ctx.clone()),
        email,
        sending_alias: None,
        session: None,
    })
    .await
    .map_err(|e| error::ErrorInternalServerError(e))??;

    // Create the room
    hub.send(CreateRoom(ctx))
        .await
        .map_err(|e| error::ErrorInternalServerError(e))??;

    Ok(HttpResponse::Ok().finish())
}
