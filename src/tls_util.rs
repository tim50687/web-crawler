use std::net::TcpStream;
use std::io::{BufReader, Read, Write, BufRead};
use native_tls::{ TlsStream, TlsConnector};


use crate::http_client::HttpClient;

// Create TLS stream
pub fn connect_tls(host: &str, port: &str) -> Result<TlsStream<TcpStream>, Box<dyn std::error::Error>> {
    let stream = TcpStream::connect(format!("{}:{}", host, port))?;
    let connector = TlsConnector::new()?;
    let stream = connector.connect(host, stream)?;
    Ok(stream)
}

// Send message
pub fn send_message(stream: &mut TlsStream<TcpStream>, message: &str) -> () {
    let req_bytes = message.as_bytes();
    match stream.write(req_bytes) {
    Ok(_) => (),
    Err(e) => eprintln!("Failed to send message: {}", e),
}
}

// Read message
pub fn read_message(stream: &mut TlsStream<TcpStream>) -> String {
    let mut response = String::new();
    let mut conn = BufReader::new(stream);

    // Find the end of the header
    let mut end_of_headers = false;
    while !end_of_headers {
        let mut line = String::new();
        let bytes_read = conn.read_line(&mut line);
        if line == "\r\n" {
            end_of_headers = true;
        } else {
            response.push_str(&line);
        }
    }

    // Get the content length
    let content_length = HttpClient::find_content_length(&response);

    // Read the specified number of bytes for the payload
    let mut payload = vec![0; content_length];
    conn.read_exact(&mut payload);
    // Combine headers and payload into a full response
    let full_response = response.clone() + &String::from_utf8_lossy(&payload);

    full_response
}
