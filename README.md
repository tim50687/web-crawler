# Web Crawler for Fakebook

## High-level Approach
The web crawler for Fakebook starts by parsing command-line arguments to determine the server, port, username, and password. It then establishes a TLS connection to the Fakebook server and sends an HTTP POST request to the login form URL to authenticate. Upon successful authentication, the crawler begins crawling the Fakebook site, extracting flags from each page's HTML in the specified format. To prevent infinite loops, a hashmap is used to track visited pages. Finally, the crawler prints out the five flags discovered during the crawl.

## Challenges Faced
- Implementing HTTP POST for login authentication.
- Handling HTTP status codes like 302 (redirect), 403 (forbidden), 404 (not found), and 503 (service unavailable).
- Managing cookies for session persistence.

## Testing Approach
1. Manually verify the crawler's functionality by running it with sample inputs.
2. Use unit tests to ensure that the crawler correctly handles HTTP requests, cookies, and status codes.
3. Conduct integration tests to simulate crawling on a small subset of Fakebook pages and verify flag extraction.

## Wrap Up
This web crawler project provided valuable hands-on experience with the HTTP protocol, web crawling, and handling various HTTP status codes. The implementation successfully achieved its goal of extracting the five secret flags from the Fakebook website. The challenges faced during the project, such as implementing HTTP POST and managing cookies, were overcome through research and experimentation. Overall, the project deepened understanding of web technologies and provided practical skills in web crawling and HTTP protocol handling.