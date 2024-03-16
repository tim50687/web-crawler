use std::{collections::{HashMap, VecDeque}, hash::Hash};
use native_tls::{ TlsStream, TlsConnector};
use std::net::TcpStream;
use regex::Regex;
use crate::{connect_tls, send_message, read_message};

pub struct HttpClient {
    stream: Option<TlsStream<TcpStream>>,
    cookies: HashMap<String, String>,
    url_queue: VecDeque<String>, // Queue of URLs to visit
    visited_urls: HashMap<String, bool>, // URLs that have been visited
    // Store secret flags
    secret_flags: Vec<String>,
}


impl HttpClient {
    pub fn new(host: &str, port: &str) -> HttpClient {
        HttpClient {
            stream: Some(connect_tls(host, port).expect("Failed to connect")),
            cookies: HashMap::new(),
            url_queue: VecDeque::new(),
            visited_urls: HashMap::new(),
            secret_flags: Vec::new(),
        }
    }
    // This function will send a GET request
    pub fn get(&mut self, host: &str, port: &str, path: &str, alive: bool) -> String {
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
        // Using BFS to visit all the pages
        // Add the root page to the queue
        self.enqueue_url(path.to_string());
        // Start traversing the pages until queue is empty or the 5 secret flags are found
        while  !self.url_queue.is_empty() && self.secret_flags.len() < 5 {
            // Get the next URL from the queue
            let url = self.dequeue_url().unwrap();
            // Mark the URL as visited
            self.mark_url_visited(&url);

            let path = "/fakebook/".to_string() + &url;
            // Get the response
            let response = self.get(host, port, &path, alive);
            return response;
            // // Find the secret flags in the response
            // let flags = HttpClient::find_secret_flags(&response);
            // // Add the flags to the secret flags
            // for flag in flags {
            //     self.secret_flags.push(flag);
            // }

            // // Add all the friend's pages to the queue
            // let friend_pattern = Regex::new(r#"href="/fakebook/(\d+)/""#).unwrap();
            // for friend in friend_pattern.captures_iter(&response) {
            //     self.enqueue_url(friend[1].to_string());
            // }
        }

        // Return the secret flags
        self.secret_flags.join("\n")
    }

    // This function will login to the server
    pub fn login(&mut self, host: &str, port: &str, path: &str, data: &str, csrf_token: &str) -> Result<(), Box<dyn std::error::Error>> {
        
        let response =  self.post(host, port, path, data, csrf_token, true)?;

        // Get the session id and csfr token
        let parts = response.split("csrftoken=").collect::<Vec<&str>>()[1].split(";").collect::<Vec<&str>>();
        let csrf_token = parts[0];
        let parts = response.split("sessionid=").collect::<Vec<&str>>()[1].split(";").collect::<Vec<&str>>();
        let session_id = parts[0];
        
        // Store the session id and csrf token
        self.cookies.insert("csrftoken".to_string(), csrf_token.to_string());
        self.cookies.insert("sessionid".to_string(), session_id.to_string());

        // response
        Ok(())
    }

    // This function will get the CSRF token before login
    pub fn get_csfr_token_before_login(&mut self, host: &str, port: &str, path: &str) -> Vec<String> {
        // Get the response
        let response = self.get(host, port, path, true);
        // Get CSRF token in the headers
        let parts = response.split("csrftoken=").collect::<Vec<&str>>()[1].split(";").collect::<Vec<&str>>();
        let csrf_header = parts[0];
        // Get CSRF token in the payload
        let parts = response.split("csrfmiddlewaretoken").collect::<Vec<&str>>()[1].split("\"").collect::<Vec<&str>>();
        let csrf_payload = parts[2];


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

    // This function will reset the connection
    fn reset_connection(&mut self) {
        
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

    // Adds a URL to the queue if it hasn't been visited
    fn enqueue_url(&mut self, url: String) {
        if !self.visited_urls.contains_key(&url) {
            self.url_queue.push_back(url);
        }
    }

    // Marks a URL as visited
    fn mark_url_visited(&mut self, url: &str) {
        self.visited_urls.insert(url.to_string(), true);
    }

    // Retrieves the next URL from the queue, if available
    fn dequeue_url(&mut self) -> Option<String> {
        self.url_queue.pop_front()
    }

    

    
}
