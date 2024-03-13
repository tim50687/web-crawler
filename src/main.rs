
mod util;
use util::parse_arguments;

fn main() {
    // Get the parsed arguments
    let _matches = parse_arguments();
    // Get the values of the arguments
    let server = _matches.get_one::<String>("server").map(String::as_str).unwrap();
    let port = _matches.get_one::<String>("port").map(String::as_str).unwrap();
    let username = _matches.get_one::<String>("username").map(String::as_str).unwrap();
    let password = _matches.get_one::<String>("password").map(String::as_str).unwrap();

    println!("Server: {}", server);
    println!("Port: {}", port);
    println!("Username: {}", username);
    println!("Password: {}", password);
}