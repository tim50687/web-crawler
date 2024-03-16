
mod util;
mod tls_util;
mod http_client;
use util::parse_arguments;

use tls_util::{connect_tls, send_message, read_message};
use http_client::HttpClient;
fn main() {
    // Get the parsed arguments
    let _matches = parse_arguments();
    // Get the values of the arguments
    let server = _matches.get_one::<String>("server").map(String::as_str).unwrap();
    let port = _matches.get_one::<String>("port").map(String::as_str).unwrap();
    let username = _matches.get_one::<String>("username").map(String::as_str).unwrap();
    let password = _matches.get_one::<String>("password").map(String::as_str).unwrap();

    // Create a new HTTP client before login
    let mut client = HttpClient::new(server, port);

    // Get the CSRF token before login
    let csrf_tokens = client.get_csfr_token_before_login(server, port, "/accounts/login/");

    // Login to the server
    client.login(server, port, "/accounts/login/", &format!("username={}&password={}&csrfmiddlewaretoken={}&next=/fakebook/", username, password, csrf_tokens[1]), &csrf_tokens[0]).unwrap();

    // Start web scraping
    let response =  client.start_web_scraping(server, port, "/fakebook/", true);
    println!("{}", response);

    
    
}


