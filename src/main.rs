use actix::{Actor, Addr};
use actix_files::Files;
use actix_web::{web, App, HttpServer};
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use rustls::{internal::pemfile, NoClientAuth, ServerConfig};
use std::{
    env,
    fs::File,
    io::{BufReader, Error, ErrorKind},
    sync::Arc,
};
use tzc::{
    http_entry::{oauth_callback, ui_index, ws_index},
    hub::{auth::Authenticator, Hub},
};

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
    // Load the SSL config by reading env variables for cert and key paths
    let ssl_config = {
        // NOTE: The SSL_CERT_PATH and SSL_KEY_PATH environment variables can be used to specify
        // where SSL files lie
        let mut cert_file = BufReader::new(File::open(
            env::var("SSL_CERT_PATH").unwrap_or("cert.pem".to_owned()),
        )?);
        let mut key_file = BufReader::new(File::open(
            env::var("SSL_KEY_PATH").unwrap_or("key.pem".to_owned()),
        )?);

        let certs = pemfile::certs(&mut cert_file)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "failedd to decode SSL cert"))?;
        let key = pemfile::pkcs8_private_keys(&mut key_file)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "failed to decode SSL key"))
            .map(|mut keys| keys.remove(0))?;

        // Register cert and keys with an empty SSL config
        let mut conf = ServerConfig::new(NoClientAuth::new());
        conf.set_single_cert(certs, key)
            .map_err(|e| Error::new(ErrorKind::Other, e))?;
        conf
    };

    let hub_addr: Addr<Hub> = Hub::start_default();
    let auth_addr: Addr<Authenticator> = Authenticator::start_default();

    HttpServer::new(move || {
        App::new()
            .data(hub_addr.clone())
            .data(auth_addr.clone())
            .data(oauth_client.clone())
            .route("/index.html", web::get().to(ui_index))
            .route("/", web::get().to(ui_index))
            .service(web::resource("/oauth/callback").route(web::get().to(oauth_callback)))
            .service(web::resource("/ws/").route(web::get().to(ws_index)))
            // When users request files like index.html, just get them from the static folder
            .service(Files::new("/", "./static"))
    })
    .bind_rustls("0.0.0.0:3327", ssl_config)?
    .bind("0.0.0.0:3328")?
    .run()
    .await
}
