use std::collections::HashMap;
use native_tls::{ TlsStream, TlsConnector};
use std::net::TcpStream;
use regex::Regex;
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

        // Get the CSRF token and session id
        let binding = String::from("");
        let csrf_token = self.cookies.get("csrftoken").unwrap_or(&binding);
        let sessionid = self.cookies.get("sessionid").unwrap_or(&binding);
        if alive {
            request = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: Keep-Alive\r\nCookie: csrftoken={}; sessionid={}\r\n\r\n", path, host, csrf_token, sessionid);
        } else {
            request = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nCookie: csrftoken={}; sessionid={}\r\n\r\n", path, host, csrf_token, sessionid);
        }

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

    // Start web scraping and get the secret message
    pub fn start_web_scraping(&mut self, host: &str, port: &str, path: &str, alive: bool) -> String {
        let response = self.get(host, port, path, alive);
        response
    }

    // This function will login to the server
    pub fn login(&mut self, host: &str, port: &str, path: &str, data: &str, csrf_token: &str) -> Result<(), Box<dyn std::error::Error>> {
        
        let response =  self.post(host, port, path, data, csrf_token, false)?;

        // Get the session id and csfr token
        let parts = response.split("csrftoken=").collect::<Vec<&str>>()[1].split(";").collect::<Vec<&str>>();
        let csrf_token = parts[0];
        let parts = response.split("sessionid=").collect::<Vec<&str>>()[1].split(";").collect::<Vec<&str>>();
        let session_id = parts[0];
        
        // Store the session id and csrf token
        self.cookies.insert("csrftoken".to_string(), csrf_token.to_string());
        self.cookies.insert("sessionid".to_string(), session_id.to_string());
        // reset the connection
        self.reset_connection();
        // response
        Ok(())
    }

    // This function will get the CSRF token before login
    pub fn get_csfr_token_before_login(&mut self, host: &str, port: &str, path: &str) -> Vec<String> {
        // Get the response
        let response = self.get(host, port, path, false);
        // Get CSRF token in the headers
        let parts = response.split("csrftoken=").collect::<Vec<&str>>()[1].split(";").collect::<Vec<&str>>();
        let csrf_header = parts[0];
        // Get CSRF token in the payload
        let parts = response.split("csrfmiddlewaretoken").collect::<Vec<&str>>()[1].split("\"").collect::<Vec<&str>>();
        let csrf_payload = parts[2];

        // reset the connection
        self.reset_connection();

        vec![csrf_header.to_string(), csrf_payload.to_string()]
    }

    // This function will find the content length in the response
    pub fn find_content_length(response: &str) -> usize {
        // Define the regex pattern to match the content length
        let content_length_pattern = Regex::new(r"content-length: (\d+)").unwrap();

        // Search for and collect the first match
        let content_length = content_length_pattern.captures(response).unwrap()[1].parse::<usize>().unwrap();

        content_length
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

    fn find_secret_flags(response: &str) -> Vec<String> {
        // Define the regex pattern to match the secret flags
        let flag_pattern = Regex::new(r"<h3 class='secret_flag' style='color:red'>FLAG: ([a-zA-Z0-9]{64})</h3>").unwrap();

        // Search for and collect all matches
        let mut flags = Vec::new();
        for cap in flag_pattern.captures_iter(response) {
            flags.push(cap[1].to_string());
        }

        flags
    }

    

    
}
