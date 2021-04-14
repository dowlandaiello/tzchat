use actix::Addr;
use actix_web::{HttpRequest, web, HttpResponse, Error};
use actix_web_actors::ws;
use super::hub::{Hub, WsSocket};

/// The /ws entrypoint to the tzhs chat
pub async fn index(req: HttpRequest, data: web::Data<Addr<Hub>>, stream: web::Payload) -> Result<HttpResponse, Error> {
    ws::start(WsSocket::new((**data).to_owned()), &req, stream)
}

pub async fn
