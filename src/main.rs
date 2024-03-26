mod http_client;
mod tls_util;
mod util;
use util::parse_arguments;

use http_client::HttpClient;
use tls_util::{connect_tls, read_message, send_message};

#[macro_use]
extern crate lazy_static;

#[tokio::main]
async fn main() {
    // Get the parsed arguments
    let _matches = parse_arguments();
    // Get the values of the arguments
    let server = _matches
        .get_one::<String>("server")
        .map(String::as_str)
        .unwrap();
    let port = _matches
        .get_one::<String>("port")
        .map(String::as_str)
        .unwrap();
    let username = _matches
        .get_one::<String>("username")
        .map(String::as_str)
        .unwrap();
    let password = _matches
        .get_one::<String>("password")
        .map(String::as_str)
        .unwrap();

    // Create a new HTTP client before login
    let mut client = HttpClient::new(server, port).await;

    // Get the CSRF token before login
    let csrf_tokens = client
        .get_csfr_token_and_sessionID_before_login("/accounts/login/")
        .await;

    // Login to the server
    client
        .login(
            "/accounts/login/",
            &format!(
                "username={}&password={}&csrfmiddlewaretoken={}&next=/fakebook/",
                username, password, csrf_tokens[1]
            ),
            &csrf_tokens[0],
            &csrf_tokens[2],
        )
        .await
        .unwrap();

    // Start web scraping
    client.start_web_scraping(server, port, "", true).await;
}
