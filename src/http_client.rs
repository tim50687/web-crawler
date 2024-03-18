use std::collections::{HashMap, VecDeque};
use native_tls::TlsStream;
use std::net::TcpStream;
use regex::Regex;
use std::sync::{Arc, Mutex};
use std::thread;
use log::{info, warn, debug, error};
use crate::{connect_tls, send_message, read_message};

pub struct HttpClient {
    stream: Option<TlsStream<TcpStream>>, // Open one stream first for Login and get CSRF token
    cookies: Arc<Mutex<HashMap<String, String>>>, // Store cookies
    url_queue: Arc<Mutex<VecDeque<String>>>, // URLs to visit
    visited_urls: Arc<Mutex<HashMap<String, bool>>>, // URLs that have been visited
    // Store secret flags
    secret_flags: Arc<Mutex<Vec<String>>>,
}


impl HttpClient {
    pub fn new(host: &str, port: &str) -> HttpClient {
        HttpClient {
            stream: Some(connect_tls(host, port).expect("Failed to connect")),
            cookies: Arc::new(Mutex::new(HashMap::new())),
            url_queue: Arc::new(Mutex::new(VecDeque::new())),
            visited_urls: Arc::new(Mutex::new(HashMap::new())),
            secret_flags: Arc::new(Mutex::new(Vec::new())),
        }
    }
    // This function will send a GET request
    pub fn get(&mut self, host: &str, port: &str, path: &str, alive: bool) -> String {
        let request;

        // Get the CSRF token and session id
        let binding = String::from("");
        let cookies_lock = self.cookies.lock().unwrap(); // Lock the cookies
        let csrf_token = cookies_lock.get("csrftoken").unwrap_or(&binding);
        let sessionid = cookies_lock.get("sessionid").unwrap_or(&binding);
        if alive {
            request = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: Keep-Alive\r\nCookie: csrftoken={}; sessionid={}\r\n\r\n", path, host, csrf_token, sessionid);
        } else {
            request = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nCookie: csrftoken={}; sessionid={}\r\n\r\n", path, host, csrf_token, sessionid);
        }
        println!("request is {}", request);
        send_message(&mut self.stream.as_mut().unwrap(), &request);
        match read_message(&mut self.stream.as_mut().unwrap()) {
            Ok(response) => response,
            Err(_) => "error".to_string(),
        }
    }

    // This function will send a POST request
    pub fn post(&mut self, host: &str, port: &str, path: &str, data: &str, csrf_token: &str, alive: bool) -> String {
        let request;
        if alive {
            request = format!("POST {} HTTP/1.1\r\nHost: {}\r\nConnection: Keep-Alive\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nCookie: csrftoken={}\r\n\r\n{}", path, host, data.len(), csrf_token, data);
        } else {
            request = format!("POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nCookie: csrftoken={}\r\n\r\n{}", path, host, data.len(), csrf_token, data);
        }
        send_message(&mut self.stream.as_mut().unwrap(), &request);
        match read_message(&mut self.stream.as_mut().unwrap()) {
            Ok(response) => response,
            Err(_) => "error".to_string(),
        }
    }

    // Start web scraping and get the secret message
    pub fn start_web_scraping(&mut self, host: &str, port: &str, path: &str, alive: bool) -> () {
        // Using BFS to visit all the pages
        // Add the root page to the queue
        self.enqueue_url(path.to_string());
        let url = self.dequeue_url().unwrap();
        // Mark the URL as visited

        let path = "/fakebook/".to_string() + &url;
        // Get the response of the home page
        let response = self.get(host, port, &path, alive);
        // Process root page
        self.process_page_helper(host, port, alive, response);
        
        // Multi-threading 5 threads to do the web scraping
        let num_threads = 5;
        let mut threads = Vec::new();

        for _ in 0..num_threads {
            let host = host.to_string();
            let port = port.to_string();
            let alive = alive;
            let mut client = self.clone();
            threads.push(thread::spawn(move || {
                client.process_page(&host, &port, alive);
            }));
        }

        for thread in threads {
            thread.join().unwrap();
        }


        // Start traversing the pages until queue is empty or the 5 secret flags are found
        // self.process_page(host, port, alive);
        
    }

    // This function will login to the server
    pub fn login(&mut self, host: &str, port: &str, path: &str, data: &str, csrf_token: &str) -> Result<(), Box<dyn std::error::Error>> {
        
        let response =  self.post(host, port, path, data, csrf_token, true);

        // Get the session id and csfr token
        let parts = response.split("csrftoken=").collect::<Vec<&str>>()[1].split(";").collect::<Vec<&str>>();
        let csrf_token = parts[0];
        let parts = response.split("sessionid=").collect::<Vec<&str>>()[1].split(";").collect::<Vec<&str>>();
        let session_id = parts[0];
        
        // Store the session id and csrf token
        let mut cookies_lock = self.cookies.lock().unwrap(); // Lock the cookies
        cookies_lock.insert("csrftoken".to_string(), csrf_token.to_string());
        cookies_lock.insert("sessionid".to_string(), session_id.to_string());
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

    fn clone(&self) -> HttpClient {
        HttpClient {
            stream: Some(connect_tls("www.3700.network", "443").expect("Failed to connect")), // Open new stream for each thread
            cookies: Arc::clone(&self.cookies),
            url_queue: Arc::clone(&self.url_queue),
            visited_urls: Arc::clone(&self.visited_urls),
            secret_flags: Arc::clone(&self.secret_flags),
        }
    }

    // This function will check status 302, 403 and 503
    fn check_status(response: &str) -> String {
        // Define the regex pattern to match the status code
        let status_code_pattern = Regex::new(r"HTTP/1.1 (\d+)").unwrap();

        // Search for and collect the first match
        let status_code = status_code_pattern.captures(response).unwrap()[1].parse::<u16>().unwrap();

        // Return the status code
        status_code.to_string()         
    }


    fn find_secret_flags(response: &str) -> Vec<String> {
        // Define the regex pattern to match the secret flags
        let flag_pattern = Regex::new(r"<h3 class='secret_flag' style='color:red'>([a-zA-Z0-9]{64})</h3>").unwrap();

        // Search for and collect all matches
        let mut flags = Vec::new();
        for cap in flag_pattern.captures_iter(response) {
            flags.push(cap[1].to_string());
        }

        flags
    }

    // Adds a URL to the queue if it hasn't been visited
    fn enqueue_url(&mut self, url: String) {
        let mut url_queue: std::sync::MutexGuard<'_, VecDeque<String>> = self.url_queue.lock().unwrap();
        let visited_urls = self.visited_urls.lock().unwrap();
        if !visited_urls.contains_key(&url) {
            url_queue.push_back(url);
        }
    }

    // Marks a URL as visited
    fn mark_url_visited(&mut self, url: &str) {
        let mut visited_urls = self.visited_urls.lock().unwrap();
        visited_urls.insert(url.to_string(), true);
    }

    // Retrieves the next URL from the queue, if available
    fn dequeue_url(&mut self) -> Option<String> {
        let mut url_queue = self.url_queue.lock().unwrap();
        url_queue.pop_front()
    }

    // Extract secret flags from a page and add them to the list
    fn find_and_store_secret_flags(&mut self, html: &str) {
        let flags = HttpClient::find_secret_flags(html);
        let mut secret_flags = self.secret_flags.lock().unwrap();
        for flag in flags {
            secret_flags.push(flag);
        }
    }

    // Prevent duplicate in the queue
    fn has_duplicate(&mut self, url: &str) -> bool {
        let visited_urls = self.visited_urls.lock().unwrap();
        if visited_urls.contains_key(&url.to_string()) || url.to_string() == ""{
            // println!("duplicate {}", url.to_string());
            return true;
        } 
        false
    }

    // This function will process user friend's page
    // 1. Check current page for secret flags
    // 2. Add all friends to the queue
    // 3. See if there's next page
    fn process_page(&mut self, host: &str, port: &str, alive: bool) {
        while {
            let (url_queue, secret_flags) = (self.url_queue.lock().unwrap(), self.secret_flags.lock().unwrap());
            println!("map {:?}", self.visited_urls.lock().unwrap().len());
            println!("queue {:?}", url_queue.len());
            println!("secret flag{:?}", secret_flags.len());
            !url_queue.is_empty() && secret_flags.len() != 5
        } {
            
            // Get the next URL from the queue
            let mut url = self.dequeue_url().unwrap();
            // println!("url {}", url);
            
            
            // If last character is '/', remove it
            if url.chars().last().unwrap() == '/' {
                url = url[..url.len() - 1].to_string();
            }

            let path = "/fakebook/".to_string() + &url + "/";
            // println!("path {}", path);
            // Get the response of the home page
            let mut response = self.get(host, port, &path, alive);
            if response == "error" {
                // Open a new stream
                self.stream = Some(connect_tls(host, port).expect("Failed to connect"));
                continue;
            }
            // check error 
            if response.contains("404") || response.contains("403") || response.contains("error"){
                error!("Error processing URL: {}", path);
            }
            
            
            // println!("home page response\n {}", response);
            // Check the status code
            let status_code = HttpClient::check_status(&response);
            // Handle the status code
            match status_code.as_str() {
                // 301 or 302
                "302" => {
                    // Get the location                  
                    let parts = response.split("location: ").collect::<Vec<&str>>();
                    // println!("parts {:?}", parts);
                    let location = parts[1].split("\r\n").collect::<Vec<&str>>()[0];
                    // Add the location to the queue
                    self.enqueue_url(location.to_string());
                    continue;
                },
                "403" | "404" => {
                    continue;
                },
                "503" => {
                    // Add the location to the queue
                    // Remove /fakebook/ from the path
                    let path = path[10..].to_string();
                    
                    self.enqueue_url(path.to_string());
                    continue;
                },
                _ => {
                    // Do nothing
                    // println!("status code {}", status_code);
                }
            }
            
            // Find the secret flags in the Home page
            self.find_and_store_secret_flags( &response);
            println!("End of user page {:?}", self.stream);
            // Go to friend's page
            // If last character is '/', remove it
            // if url.chars().last().unwrap() == '/' {
            //     println!("dwqwqdqwdqw {}", url);
            //     url = url[..url.len() - 1].to_string();
            // }
            
            let path = "/fakebook/".to_string() + &url + "/friends/1/";
            // println!("friend page path {}", path);
            response = self.get(host, port, &path, alive);
            if response == "error" {
                continue;
            }
            // check error 
            if response.contains("404") || response.contains("403") || response.contains("error"){
                error!("firend page Error processing URL: {}", path);
            }
            // println!("friend page response\n {}", response);
            // println!("response {}", response);
            // println!("Path is {} \n response is {}", url, response);
            // Process the friend's page
            self.process_page_helper(host, port, alive, response);
            // println!("so far secret flag{:?}", self.secret_flags);
            println!("End of user page and user's friend page {:?}", self.stream);
        }
    }
    
    // Helper function to process the page
    fn process_page_helper(&mut self, host: &str, port: &str, alive:bool, response: String) {
        let mut _response = response;
        let friend_pattern = Regex::new(r#"<li><a href="/fakebook/(\d+)/""#).unwrap();
        let next_page_pattern = Regex::new(r#"<a href="(/fakebook/\d+/friends/\d+/)">next</a>"#).unwrap();
        loop {
            
            // Traverse every friend's page
            // First, Find the secret flags in the friend's page
            self.find_and_store_secret_flags( &_response);
            
            // Find friend in current page
            for friend in friend_pattern.captures_iter(&_response) {
                // Check if the friend's page has been visited or is root page
                if self.has_duplicate(&friend[1]) {
                    continue;
                }
                
                self.enqueue_url(friend[1].to_string());
                // Mark the URL as visited
                self.mark_url_visited(&friend[1].to_string());
                
            }

            // See if there's next page
            let next_page = next_page_pattern.captures(&_response);
            if next_page.is_none() {
                break;
            }
            // Get the next page
            let next_page = next_page.unwrap()[1].to_string();
            // println!("next page {}", next_page);
            // Get the _response of next page
            _response = self.get(host, port, &next_page, alive);
            if _response == "error" {
                continue;
            }
            // check error 
            if _response.contains("404") || _response.contains("403") || _response.contains("error"){
                error!("Error processing URL: {}", next_page);
            }
            // println!("next page response\n {}", _response);
            println!("End of next page {:?}", self.stream);
        }
    }

    

    
}
