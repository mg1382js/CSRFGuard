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

module.exports = CSRFGuard
