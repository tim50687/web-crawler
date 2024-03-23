# Web Crawler for Fakebook

## High-level Approach
1. Parse command-line arguments to determine the server, port, username, and password.
2. Use TLS to connect to the Fakebook server
3. Send an HTTP POST request to the login form URL to authenticate with the provided username and password.
4. Start crawling the Fakebook site, parsing each page's HTML to extract flags in the specified format.
5. Use hashmap to keep tracking the page that we already crawled to prevent infinite loop.
6. Print out the five flags discovered during the crawl.

## Challenges Faced
- Implementing HTTP POST for login authentication.
- Handling HTTP status codes like 302 (redirect), 403 (forbidden), 404 (not found), and 503 (service unavailable).
- Managing cookies for session persistence.

## Testing Approach
1. Manually verify the crawler's functionality by running it with sample inputs.
2. Use unit tests to ensure that the crawler correctly handles HTTP requests, cookies, and status codes.
3. Conduct integration tests to simulate crawling on a small subset of Fakebook pages and verify flag extraction.

