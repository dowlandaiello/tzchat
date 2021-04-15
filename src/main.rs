use actix::{Actor, Addr};
use actix_web::{web, App, HttpServer};
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use std::{env, sync::Arc};
use tzc::{http_entry::{ws_index, ui_index}, hub::Hub};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    // Expected oauth environment variables are:
    // - TZ_CLIENT_ID
    // - TZ_SECRET
    let oauth_client = Arc::new(
        BasicClient::new(
            ClientId::new(env::var("TZ_CLIENT_ID").expect("missing TZ_CLIENT_ID variable")),
            Some(ClientSecret::new(
                env::var("TZ_SECRET").expect("missing TZ_SECRET variable"),
            )),
            AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_owned())
                .expect("failed to parse auth URL"),
            Some(
                TokenUrl::new("https://oauth2.googleapis.com/token".to_owned())
                    .expect("failed to parse token URL"),
            ),
        )
        .set_redirect_url(
            RedirectUrl::new(
                // If the user specifies that they are running in a dev environment, use localhost
                // as the default redirect URL
                if env::var("DEV")
                    .map(|dev_var| dev_var.parse::<bool>().unwrap())
                    .unwrap_or(false)
                {
                    "http://localhost:8080/oauth/callback".to_owned()
                } else {
                    "https://tzhs.chat/oauth/callback".to_owned()
                },
            )
            .expect("failed to parse redirect URL"),
        ),
    );
    let hub_addr: Addr<Hub> = Hub::start_default();

    HttpServer::new(move || {
        App::new()
            .data(hub_addr.clone())
            .data(oauth_client.clone())
            .route("/ws/", web::get().to(ws_index))
            .service(ui_index)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
