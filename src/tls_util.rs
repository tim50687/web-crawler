// use std::net::TcpStream;
// use std::io::{BufReader, Read, Write, BufRead};
use native_tls;
// use std::time::Duration;

use tokio::net::TcpStream;
use tokio_native_tls::{TlsConnector, TlsStream};
// use native_tls::Identity;
use tokio::time::timeout;
use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncBufReadExt, BufReader, AsyncReadExt};

use crate::http_client::HttpClient;

// Create TLS stream
pub async fn connect_tls(host: &str, port: &str) -> Result<TlsStream<TcpStream>, Box<dyn std::error::Error>> {
    let stream = TcpStream::connect(format!("{}:{}", host, port)).await?;
    let connector = TlsConnector::from(native_tls::TlsConnector::builder().build()?);
    let mut stream = connector.connect(host, stream).await?;
    Ok(stream)
}

// Send message
pub async fn send_message(stream: &mut TlsStream<TcpStream>, message: &str) -> () {
    // println!("Sending message: {}", message);
    let req_bytes = message.as_bytes();
    match stream.write(req_bytes).await {
    Ok(_) => (),
    Err(e) => eprintln!("Failed to send message: {}", e),
}
}

// Read message
pub async fn read_message(stream: &mut TlsStream<TcpStream>) -> Result<String, String> {
    let mut response_header = String::new();
    let mut conn = BufReader::new(stream);

    // Make a flag that represent the response_header is chunked or not
    let mut chunked = false;

    // Find the end of the header
    let mut end_of_headers = false;
    while !end_of_headers {
        let mut line = String::new();
        // Read line and check if timeout
        let duration = tokio::time::Duration::from_secs(5); // set timeout to 5 seconds
        match timeout(duration, conn.read_line(&mut line)).await {
            Ok(Ok(0)) => return Err("Connection closed by peer".to_string()),
            Ok(Ok(_)) => {
                if line.contains("Transfer-Encoding: chunked") {
                    chunked = true;
                }
                if line == "\r\n" {
                    end_of_headers = true;
                } else {
                    response_header.push_str(&line);
                }
            },
            Ok(Err(e)) => return Err(format!("Error reading line: {}", e)),
            Err(_) => return Err("Read line timeout".to_string()),
        }
    }
    // println!("response_header: {}", response_header);


    let mut chunked_body = Vec::new();

    // If the response_header is chunked, read the chunks
    if chunked {
        println!("chunked chunk chunk chunk chunk");
        loop {
            // Read the chunk size
            let mut size_str = String::new();
            // Read line and check if timeout
            let duration = tokio::time::Duration::from_secs(5); // set timeout to 5 seconds
            match timeout(duration, conn.read_line(&mut size_str)).await {
                Ok(Ok(0)) => return Err("Connection closed by peer".to_string()),
                Ok(Ok(_)) => (),
                Ok(Err(e)) => return Err(format!("Error reading line: {}", e)),
                Err(_) => return Err("Read line timeout".to_string()),
            }
            // get the size of the chunk
            let size_hex = size_str.trim_end_matches("\r\n");
            let size = usize::from_str_radix(size_hex, 16);
            println!("123");
            if size == Ok(0) {
                break;
            }
            // Read the chunk
            let mut chunk = vec![0; size.unwrap()];
            // Read chunk and check if timeout
            match timeout(duration, conn.read_exact(&mut chunk)).await {
                Ok(Ok(0)) => return Err("Connection closed by peer".to_string()),
                Ok(Ok(_)) => (),
                Ok(Err(e)) => return Err(format!("Error reading chunk: {}", e)),
                Err(_) => return Err("Read chunk timeout".to_string()),
            }
            chunked_body.extend_from_slice(&chunk);

            // Consume the trailing CRLF and check if timeout
            let mut crlf = [0; 2];
            match timeout(duration, conn.read_exact(&mut crlf)).await {
                Ok(Ok(0)) => return Err("Connection closed by peer".to_string()),
                Ok(Ok(_)) => (),
                Ok(Err(e)) => return Err(format!("Error reading CRLF: {}", e)),
                Err(_) => return Err("Read CRLF timeout".to_string()),
            }

        }
        return Ok(response_header.clone() + &String::from_utf8_lossy(&chunked_body));

    } else { // If not chunked, read the rest of the response_header

        // Get the content length
        let content_length = HttpClient::find_content_length(&response_header);
        // println!("content_length: {}", content_length);
        // Read the specified number of bytes for the payload
        let mut payload = vec![0; content_length];
        // Read payload and check if timeout
        let duration = tokio::time::Duration::from_secs(5); // set timeout to 5 seconds
        match timeout(duration, conn.read_exact(&mut payload)).await {
            // Ok(Ok(0)) => return Err("Connection closed by peer".to_string()),
            Ok(Ok(_)) => (),
            Ok(Err(e)) => return Err(format!("Error reading payload: {}", e)),
            Err(_) => return Err("Read payload timeout".to_string()),
        }
        // Combine headers and payload into a full response_header
        return  Ok(response_header.clone() + &String::from_utf8_lossy(&payload));
    }

}
