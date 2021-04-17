use actix::Addr;
use actix_web::{HttpRequest, web, HttpResponse, Error, Responder};
use actix_web_actors::ws;
use super::hub::{Hub, WsSocket};
use oauth2::basic::BasicClient;
use std::sync::Arc;

/// The /ws entrypoint to the tzhs chat
pub async fn ws_index(req: HttpRequest, data: web::Data<Addr<Hub>>, stream: web::Payload) -> Result<HttpResponse, Error> {
    // If the user is already signed in, verify their details and then proceed
    ws::start(WsSocket::new((**data).to_owned()), &req, stream)
}

#[get("/index.html")]
pub async fn ui_index(req: HttpRequest, data: web::Data<Arc<BasicClient>>) -> impl Responder {
}
