use super::hub::{Hub, WsSocket};
use actix::Addr;
use actix_files::NamedFile;
use actix_web::{web, Error, HttpRequest, HttpResponse, Responder};
use actix_web_actors::ws;
use oauth2::basic::BasicClient;
use std::{sync::Arc, path::PathBuf};

/// The /ws entrypoint to the tzhs chat
pub async fn ws_index(
    req: HttpRequest,
    data: web::Data<Addr<Hub>>,
    stream: web::Payload,
) -> Result<HttpResponse, Error> {
    // If the user is already signed in, verify their details and then proceed
    ws::start(WsSocket::new((**data).to_owned()), &req, stream)
}
