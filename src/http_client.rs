use crate::{connect_tls, read_message, send_message};
use regex::Regex;
use std::sync::Arc;
use std::{
    collections::{HashMap, VecDeque},
    time::Instant,
};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_native_tls::TlsStream;

lazy_static! {
    // Define the regex pattern to match the status code
    static ref STATUS_CODE_PATTERN: Regex = Regex::new(r"HTTP/1.1 (\d+)").unwrap();
    // Define the regex pattern to match href link
    static ref HREF_PATTERN: Regex = Regex::new(r#"href="(/fakebook/\d.*)""#).unwrap();
    // Define the regex pattern to match the secret flags
    static ref FLAG_PATTERN: Regex = Regex::new(r"FLAG: ([a-zA-Z0-9]{64})").unwrap();
    // Define the regex pattern to match the content length
    static ref CONTENT_LENGTH_PATTERN: Regex = Regex::new(r"content-length: (\d+)").unwrap();
}

// Struct to store the HTTP client
#[derive(Debug)]
pub struct HttpClient {
    stream: Option<TlsStream<TcpStream>>, // Open one stream first for Login and get CSRF token
    cookies: Arc<Mutex<HashMap<String, String>>>, // Store cookies
    url_queue: Arc<Mutex<VecDeque<String>>>, // URLs to visit
    visited_urls: Arc<Mutex<HashMap<String, bool>>>, // URLs that have been visited
    // Store secret flags
    secret_flags: Arc<Mutex<Vec<String>>>,
    num: u16,
    server: String,
    port: String, // thread_pool: ThreadPool
}

// Implementation of the HTTP client
impl HttpClient {
    // Constructor
    pub async fn new(host: &str, port: &str) -> HttpClient {
        HttpClient {
            stream: Some(connect_tls(host, port).await.expect("Failed to connect")),
            cookies: Arc::new(Mutex::new(HashMap::new())),
            url_queue: Arc::new(Mutex::new(VecDeque::new())),
            visited_urls: Arc::new(Mutex::new(HashMap::new())),
            secret_flags: Arc::new(Mutex::new(Vec::new())),
            num: 0,
            server: host.to_string(),
            port: port.to_string(), // thread_pool: ThreadPool::new(5)
        }
    }
    // This function will send a GET request
    pub async fn get(&mut self, path: &str, alive: bool) -> String {
        let request;
        // Get the CSRF token and session id
        let binding = String::from("");
        let cookies_lock = self.cookies.lock().await; // Lock the cookies
        let csrf_token = cookies_lock.get("csrftoken").unwrap_or(&binding).clone();
        let sessionid = cookies_lock.get("sessionid").unwrap_or(&binding).clone();
        drop(cookies_lock);
        if alive {
            request = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: Keep-Alive\r\nCookie: csrftoken={}; sessionid={}\r\nAccept-Encoding: gzip\r\n\r\n", path, self.server, csrf_token, sessionid);
        } else {
            request = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nCookie: csrftoken={}; sessionid={}\r\nAccept-Encoding: gzip\r\n\r\n", path, self.server, csrf_token, sessionid);
        }
        send_message(&mut self.stream.as_mut().unwrap(), &request).await;
        match read_message(&mut self.stream.as_mut().unwrap()).await {
            Ok(response) => response,
            Err(_) => "error".to_string(),
        }
    }

    // This function will send a POST request
    pub async fn post(
        &mut self,
        path: &str,
        data: &str,
        csrf_token: &str,
        sessionid: &str,
        alive: bool,
    ) -> String {
        let request;
        if alive {
            request = format!("POST {} HTTP/1.1\r\nHost: {}\r\nConnection: Keep-Alive\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nCookie: csrftoken={}; sessionid={}\r\n\r\n{}", path, self.server, data.len(), csrf_token, sessionid, data);
        } else {
            request = format!("POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nCookie: csrftoken={}; sessionid={}\r\n\r\n{}", path, self.server, data.len(), csrf_token,sessionid , data);
        }
        send_message(&mut self.stream.as_mut().unwrap(), &request).await;
        match read_message(&mut self.stream.as_mut().unwrap()).await {
            Ok(response) => response,
            Err(err) => err,
        }
    }

    // Start web scraping and get the secret message
    pub async fn start_web_scraping(
        &mut self,
        host: &str,
        port: &str,
        path: &str,
        alive: bool,
    ) -> () {
        // Add the root page to the queue
        self.enqueue_url("/fakebook/".to_string() + path).await;

        // Multi-threading 5 threads to do the web scraping
        let num_threads = 5;
        let mut threads = Vec::new();

        for i in 0..num_threads {
            let host = host.to_string();
            let port = port.to_string();
            let alive = alive;
            let mut client = self.clone(i as u16).await;
            let task = tokio::spawn(async move {
                // BFS to visit all the pages
                client.process_page(&host, &port, alive).await;
            });
            threads.push(task);
        }

        for task in threads {
            match task.await {
                Ok(_) => (),
                Err(_) => {}
            }
        }

        // Get the secret flags
        let secret_flags = self.secret_flags.lock().await;
        for flag in secret_flags.iter() {
            println!("{}", flag);
        }
    }

    // This function will login to the server
    pub async fn login(
        &mut self,
        path: &str,
        data: &str,
        csrf_token: &str,
        session_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let response = self.post(path, data, csrf_token, session_id, true).await;

        // Get the session id and csfr token
        let parts = response.split("csrftoken=").collect::<Vec<&str>>()[1]
            .split(";")
            .collect::<Vec<&str>>();
        let csrf_token = parts[0];
        let parts = response.split("sessionid=").collect::<Vec<&str>>()[1]
            .split(";")
            .collect::<Vec<&str>>();
        let session_id = parts[0];

        // Store the session id and csrf token
        let mut cookies_lock = self.cookies.lock().await; // Lock the cookies
        cookies_lock.insert("csrftoken".to_string(), csrf_token.to_string());
        cookies_lock.insert("sessionid".to_string(), session_id.to_string());
        // response
        Ok(())
    }

    // This function will get the CSRF token before login
    pub async fn get_csfr_token_and_sessionID_before_login(&mut self, path: &str) -> Vec<String> {
        // Get response
        let mut response = self.get(path, true).await;

        // If read message has any error. e.x. timeout
        while response == "error" {
            // Create a new socket
            self.stream = Some(
                connect_tls(&self.server, &self.port)
                    .await
                    .expect("Failed to connect"),
            );
            response = self.get(path, true).await;
        }

        // Get CSRF token in the headers
        let parts = response.split("csrftoken=").collect::<Vec<&str>>()[1]
            .split(";")
            .collect::<Vec<&str>>();
        let csrf_header = parts[0];
        // Get session id in the headers
        let parts = response.split("sessionid=").collect::<Vec<&str>>()[1]
            .split(";")
            .collect::<Vec<&str>>();
        let session_id = parts[0];
        // Get CSRF token in the payload
        let parts = response.split("csrfmiddlewaretoken").collect::<Vec<&str>>()[1]
            .split("\"")
            .collect::<Vec<&str>>();
        let csrf_payload = parts[2];

        vec![
            csrf_header.to_string(),
            csrf_payload.to_string(),
            session_id.to_string(),
        ]
    }

    // This function will find the content length in the response
    pub fn find_content_length(response: &str) -> usize {
        // Search for and collect the first match
        let content_length = CONTENT_LENGTH_PATTERN.captures(response).unwrap()[1]
            .parse::<usize>()
            .unwrap();

        content_length
    }

    // This function will clone the HTTP client
    async fn clone(&self, num: u16) -> HttpClient {
        HttpClient {
            stream: Some(
                connect_tls(&self.server, &self.port)
                    .await
                    .expect("Failed to connect"),
            ), // Open new stream for each thread
            cookies: Arc::clone(&self.cookies),
            url_queue: Arc::clone(&self.url_queue),
            visited_urls: Arc::clone(&self.visited_urls),
            secret_flags: Arc::clone(&self.secret_flags),
            num,
            server: self.server.clone(),
            port: self.port.clone(),
        }
    }

    // This function will proceed to the given url and handle the response
    async fn proceed_url(&mut self, url: &str, alive: bool) {
        let mut response;
        response = self.get(url, alive).await;

        // If read message has any error. e.x. timeout
        while response == "error" {
            // Create a new socket
            self.stream = Some(
                connect_tls(&self.server, &self.port)
                    .await
                    .expect("Failed to connect"),
            );
            response = self.get(url, alive).await;
        }

        // Split the response into header and content sections
        let res_vec: Vec<&str> = response.split("\r\n\r\n").collect();

        // Switch to a new socket if server close the current port
        if res_vec[0].contains("Connection: close") {
            self.stream = Some(
                connect_tls(&self.server, &self.port)
                    .await
                    .expect("Failed to connect"),
            );
        }

        // Get status code
        let status_code = STATUS_CODE_PATTERN.captures(res_vec[0]).unwrap()[1].to_string();

        match status_code.as_str() {
            // 301 or 302
            "302" => {
                // Get the location
                let parts = res_vec[0].split("location: ").collect::<Vec<&str>>();
                let location = parts[1].split("\r\n").collect::<Vec<&str>>()[0];
                // Add the location to the queue
                self.enqueue_url(location.to_string()).await;
            }
            "403" | "404" => {}
            "503" => {
                // Add the url back to the queue
                self.enqueue_url(url.to_string()).await;
            }
            "200" => {
                self.find_and_store_secret_flags(res_vec[1]).await;
                let mut mat_vec = vec![];
                for mat in HREF_PATTERN.captures_iter(res_vec[1]) {
                    if self.has_duplicate(&mat[1]).await {
                        continue;
                    }

                    mat_vec.push(mat[1].to_string());

                    self.mark_url_visited(&mat[1]).await;
                }
                self.enqueue_url_vec(mat_vec).await;
            }
            _ => {}
        }
    }

    // This function will scan through the html to find secret flag
    fn find_secret_flags(response: &str) -> Vec<String> {
        // Search for and collect all matches
        let mut flags = Vec::new();
        for cap in FLAG_PATTERN.captures_iter(response) {
            flags.push(cap[1].to_string());
        }

        flags
    }

    // Adds a URL to the queue
    async fn enqueue_url(&mut self, url: String) {
        let mut url_queue = self.url_queue.lock().await;
        url_queue.push_back(url);
    }

    // Adds a vector of URLs to the queue
    async fn enqueue_url_vec(&mut self, urls: Vec<String>) {
        let mut url_queue = self.url_queue.lock().await;
        for url in urls.into_iter() {
            url_queue.push_back(url);
        }
    }

    // Marks a URL as visited
    async fn mark_url_visited(&mut self, url: &str) {
        let mut visited_urls = self.visited_urls.lock().await;
        visited_urls.insert(url.to_string(), true);
    }

    // Retrieves the next URL from the queue, if available
    async fn dequeue_url(&mut self) -> Option<String> {
        let mut url_queue = self.url_queue.lock().await;
        url_queue.pop_front()
    }

    // Extract secret flags from a page and add them to the list
    async fn find_and_store_secret_flags(&mut self, html: &str) {
        let flags = HttpClient::find_secret_flags(html);
        let mut secret_flags = self.secret_flags.lock().await;
        for flag in flags {
            secret_flags.push(flag);
        }
    }

    // Prevent duplicate in the queue
    async fn has_duplicate(&mut self, url: &str) -> bool {
        let visited_urls = self.visited_urls.lock().await;
        if visited_urls.contains_key(&url.to_string()) || url.to_string() == "" {
            return true;
        }
        false
    }

    // This function will process user friend's page
    // 1. Check current page for secret flags
    // 2. Add all friends to the queue
    // 3. See if there's next page
    async fn process_page(&mut self, host: &str, port: &str, alive: bool) {
        while {
            let secret_flags = self.secret_flags.lock().await;
            secret_flags.len() != 5
        } {
            // Get the next URL from the queue
            let url = match self.dequeue_url().await {
                Some(url) => url,
                None => {
                    continue;
                }
            };

            self.proceed_url(&url, alive).await;
        }
    }
}
