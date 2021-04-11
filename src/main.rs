use actix::Actor;
use actix_web::{web, App, HttpServer};
use tzc::{http_entry::index, hub::Hub};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let hub_addr = web::Data::new(Hub::start_default());

    HttpServer::new(move || {
        App::new()
            .data(hub_addr.clone())
            .route("/ws/", web::get().to(index))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
