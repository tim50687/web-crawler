
mod util;
mod tls_util;
use util::parse_arguments;

use tls_util::{connect_tls, send_message, read_message};
fn main() {
    // Get the parsed arguments
    let _matches = parse_arguments();
    // Get the values of the arguments
    let server = _matches.get_one::<String>("server").map(String::as_str).unwrap();
    let port = _matches.get_one::<String>("port").map(String::as_str).unwrap();
    let username = _matches.get_one::<String>("username").map(String::as_str).unwrap();
    let password = _matches.get_one::<String>("password").map(String::as_str).unwrap();

    // Get the TLS stream
    let mut stream = connect_tls(server, port).expect("Failed to connect");

    // Try to get the home page
    let request = format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", server);

    send_message(&mut stream, &request); 

    // Read the response
    let response = read_message(&mut stream);

    println!("{}", response);
    
}


