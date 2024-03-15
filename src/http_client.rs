use std::collections::HashMap;
use native_tls::{ TlsStream, TlsConnector};
use std::net::TcpStream;
use crate::{connect_tls, send_message, read_message};

pub struct HttpClient {
    stream: Option<TlsStream<TcpStream>>,
    cookies: HashMap<String, String>,
}


impl HttpClient {
    pub fn new() -> HttpClient {
        HttpClient {
            stream: None,
            cookies: HashMap::new(),
        }
    }
    // This function will send a GET request
    pub fn get(&mut self, host: &str, port: &str, path: &str, alive: bool) -> String {
        self.ensure_connection(host, port);
        let request;
        if alive {
            request = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: Keep-Alive\r\n\r\n", path, host);
        } else {
            request = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: Close\r\n\r\n", path, host);
        }
        println!("{}", request);
        send_message(&mut self.stream.as_mut().unwrap(), &request);
        read_message(&mut self.stream.as_mut().unwrap())
    }

    // This function will send a POST request
    pub fn post(&mut self, host: &str, port: &str, path: &str, data: &str, csrf_token: &str, alive: bool) -> Result<String, Box<dyn std::error::Error>> {
        self.ensure_connection(host, port);
        let request;
        if alive {
            request = format!("POST {} HTTP/1.1\r\nHost: {}\r\nConnection: Keep-Alive\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nCookie: csrftoken={}\r\n\r\n{}", path, host, data.len(), csrf_token, data);
        } else {
            request = format!("POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nCookie: csrftoken={}\r\n\r\n{}", path, host, data.len(), csrf_token, data);
        }
        send_message(&mut self.stream.as_mut().unwrap(), &request);
        Ok(read_message(&mut self.stream.as_mut().unwrap()))
    }

    // This function will login to the server
    pub fn login(&mut self, host: &str, port: &str, path: &str, data: &str, csrf_token: &str) -> Result<String, Box<dyn std::error::Error>> {
        
        let response =  self.post(host, port, path, data, csrf_token, false);
        // reset the connection
        self.reset_connection();
        response
    }

    // This function will get the CSRF token
    pub fn get_csfr_token(&mut self, host: &str, port: &str, path: &str) -> Vec<String> {
        // Get the response
        let response = self.get(host, port, path, false);
        // Get CSRF token in the headers
        let parts = response.split("csrftoken=").collect::<Vec<&str>>()[1].split(";").collect::<Vec<&str>>();
        let csrf_header = parts[0];
        // Get CSRF token in the payload
        let parts = response.split("csrfmiddlewaretoken").collect::<Vec<&str>>()[1].split("\"").collect::<Vec<&str>>();
        let csrf_payload = parts[2];
        println!("{} {}", csrf_header, csrf_payload);

        // reset the connection
        self.reset_connection();

        vec![csrf_header.to_string(), csrf_payload.to_string()]
    }

    // This function will ensure that the connection is established
    fn ensure_connection(&mut self, host: &str, port: &str) -> () {
        if self.stream.is_none() {
            self.stream = Some(connect_tls(host, port).expect("Failed to connect"));
        }
    }
    // This function will reset the connection
    fn reset_connection(&mut self) {
        self.stream = None;
    }
}
