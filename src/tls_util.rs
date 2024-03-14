use std::net::TcpStream;
use std::io::{BufReader, Read, Write};
use native_tls::{ TlsStream, TlsConnector};

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
    conn.read_to_string(&mut response).unwrap();
    response
}