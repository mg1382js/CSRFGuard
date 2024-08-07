# CSRFGuard
CSRFGuard is a simple tool for preventing Cross-Site Request Forgery (CSRF) attacks. It uses Node.js and built-in modules to generate and verify CSRF tokens, protecting web applications from CSRF attacks.

## Features
- Generates unique CSRF tokens
- Simple session management
- CSRF token verification
- Dynamic implementation with the ability to add new routes and handlers

## Installation
This project does not require any external dependencies and only requires Node.js to be installed on your system.

## Usage
1. Copy the Code
   First, save the following code in a file named server.js:

```js
const http = require('http');
const crypto = require('crypto');
const { parse } = require('querystring');

class CSRFGuard {
    constructor() {
        this.sessions = new Map(); // Simple in-memory session store
        this.routes = {}; // Object to hold route handlers
        this.initRoutes();
    }

    generateCSRFToken() {
        return crypto.randomBytes(32).toString('hex');
    }

    createSession() {
        const sessionId = crypto.randomBytes(16).toString('hex');
        const csrfToken = this.generateCSRFToken();
        this.sessions.set(sessionId, { csrfToken });
        return { sessionId, csrfToken };
    }

    validateCSRFToken(sessionId, token) {
        const session = this.sessions.get(sessionId);
        return session && token === session.csrfToken;
    }

    initRoutes() {
        // Define route handlers
        this.routes['GET /'] = (req, res) => {
            const { sessionId, csrfToken } = this.createSession();
            res.writeHead(200, {
                'Content-Type': 'text/html',
                'Set-Cookie': `session=${sessionId}`
            });
            res.end(`
                <form action="/submit" method="POST">
                    <input type="hidden" name="_csrf" value="${csrfToken}">
                    <input type="text" name="example" placeholder="Enter something">
                    <button type="submit">Submit</button>
                </form>
            `);
        };

        this.routes['POST /submit'] = (req, res) => {
            req.on('data', chunk => {
                const body = parse(chunk.toString());
                const sessionId = req.headers.cookie?.split('=')[1];

                if (this.validateCSRFToken(sessionId, body._csrf)) {
                    res.writeHead(200, { 'Content-Type': 'text/plain' });
                    res.end('Form submitted successfully');
                } else {
                    res.writeHead(403, { 'Content-Type': 'text/plain' });
                    res.end('Invalid CSRF Token');
                }
            });
        };
    }

    handleRequest(req, res) {
        const url = new URL(req.url, `http://${req.headers.host}`);
        const method = req.method;
        const routeKey = `${method} ${url.pathname}`;

        const handler = this.routes[routeKey];
        if (handler) {
            handler(req, res);
        } else {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('Not Found');
        }
    }

    startServer(port) {
        const server = http.createServer(this.handleRequest.bind(this));
        server.listen(port, () => {
            console.log(`Server running at http://localhost:${port}`);
        });
    }
}
// Usage
const csrfGuard = new CSRFGuard();
csrfGuard.startServer(3000);
```


2. Run the Server
   To start the server, run the following command in your terminal:

```bash
node server.js
The server will run on port 3000, and you can access it in your browser at http://localhost:3000.
```
3. Adding New Routes
   To add new routes and handlers, modify the initRoutes method in the CSRFGuard class. Simply add new routes and their corresponding handlers to the routes object.

4. Method Descriptions
   generateCSRFToken(): Generates a unique CSRF token.
   createSession(): Creates a new session and generates a CSRF token.
   validateCSRFToken(sessionId, token): Validates the CSRF token.
   initRoutes(): Defines routes and their handlers.
   handleRequest(req, res): Processes incoming requests and routes them to the appropriate handler.
   startServer(port): Starts the HTTP server on the specified por