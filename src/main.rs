use actix::{Actor, Addr};
use actix_web::{web, App, HttpServer};
use tzc::{http_entry::index, hub::Hub};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    let hub_addr: Addr<Hub> = Hub::start_default();

    HttpServer::new(move || {
        App::new()
            .data(hub_addr.clone())
            .route("/ws/", web::get().to(index))
    })
    .bind("127.0.0.1:42069")?
    .run()
    .await
}
