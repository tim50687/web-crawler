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
    let mut response_header = String::new();
    let mut conn = BufReader::new(stream);

    // Make a flag that represent the response_header is chunked or not
    let mut chunked = false;

    // Find the end of the header
    let mut end_of_headers = false;
    while !end_of_headers {
        let mut line = String::new();
        let bytes_read = conn.read_line(&mut line);
        // Check if it's chunked
        if line.contains("Transfer-Encoding: chunked") {
            chunked = true;
        }
        if line == "\r\n" {
            end_of_headers = true;
        } else {
            response_header.push_str(&line);
        }
    }


    let mut chunked_body = Vec::new();

    // If the response_header is chunked, read the chunks
    if chunked {

        loop {
            // Read the chunk size
            let mut size_str = String::new();
            conn.read_line(&mut size_str);
            let size_hex = size_str.trim_end_matches("\r\n");
            let size = usize::from_str_radix(size_hex, 16);
    
            if size == Ok(0) {
                break;
            }
            // Read the chunk
            let mut chunk = vec![0; size.unwrap()];
            conn.read_exact(&mut chunk);
            chunked_body.extend_from_slice(&chunk);

            // Consume the trailing CRLF
            conn.read_line(&mut String::new());

        }
        return response_header.clone() + &String::from_utf8_lossy(&chunked_body);

    } else { // Not chunked, read the rest of the response_header

        // Get the content length
        let content_length = HttpClient::find_content_length(&response_header);
        // Read the specified number of bytes for the payload
        let mut payload = vec![0; content_length];
        conn.read_exact(&mut payload);
        // Combine headers and payload into a full response_header
        return  response_header.clone() + &String::from_utf8_lossy(&payload);
    }

}
