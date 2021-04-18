use super::hub::{
    auth::{
        AssertJwtValid, AssumeIdentity, Authenticator, OauthSessionChallenge,
        AuthError,
        RegisterSessionChallenge, HTTP_CHALLENGE_COOKIE_NAME, HTTP_JWT_COOKIE_NAME,
    },
    Hub, WsSocket,
};
use actix::Addr;
use actix_files::NamedFile;
use actix_web::{error, http::Cookie, web, Error, HttpMessage, HttpRequest, HttpResponse};
use actix_web_actors::ws;
use oauth2::{basic::BasicClient, CsrfToken, PkceCodeChallenge, Scope};
use std::{sync::Arc, path::PathBuf};


pub async fn ws_index(req: HttpRequest,
    hub: web::Data<Addr<Hub>>,
    auth: web::Data<Addr<Authenticator>>,
    stream: web::Payload,
) -> Result<HttpResponse, Error> {
    // Ensure both that the JWT session exists and that it is valid
    let jwt_cookie = req.cookie(HTTP_JWT_COOKIE_NAME).ok_or(AuthError::InvalidToken)?;
    let email = auth.send(AssertJwtValid(jwt_cookie)).await.map_err(|e| error::ErrorInternalServerError(e))??;

    // Start the websocket chat
    let (session, resp) = ws::start_with_addr(WsSocket::new((**hub).to_owned()), &req, stream)?;

    // The user has now been authenticated
    auth.do_send(AssumeIdentity { session, email });

    Ok(resp)
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
            .cookie(Cookie::new(HTTP_CHALLENGE_COOKIE_NAME, base64::encode(challenge_session)))
            .finish());
    }

    let path: PathBuf = "static/index.html".parse().unwrap();
    Ok(NamedFile::open(path)?.into_response(&req)?)
}
