import os
import logging
from logging.handlers import RotatingFileHandler

from flask import Flask, render_template, request
from dotenv import load_dotenv


# ✅ Load environment variables from .env
load_dotenv()


# ✅ Middleware to remove default "Server" header
class RemoveServerHeaderMiddleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        def custom_start_response(status, headers, exc_info=None):
            filtered = [(k, v) for (k, v) in headers if k.lower() != "server"]
            return start_response(status, filtered, exc_info)

        return self.app(environ, custom_start_response)


# ✅ Setup Flask app
app = Flask(__name__)
app.wsgi_app = RemoveServerHeaderMiddleware(app.wsgi_app)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "fallback-secret")


# ✅ Logging: rotate logs at 1MB, keep 5 total
log_dir = "logs"
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, "runtime.log")

handler = RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=5)
handler.setLevel(logging.WARNING)


# ✅ Filter: log risky requests or 4xx/5xx errors
class RiskyRequestFilter(logging.Filter):
    def filter(self, record):
        try:
            ua = request.headers.get("User-Agent", "").lower()
            suspicious = any(
                kw in ua for kw in ["sqlmap", "nikto", "fuzz", "dirbuster"]
            )
            return suspicious or record.levelno >= logging.WARNING
        except RuntimeError:
            # Avoid errors when request context is not available
            return False


handler.addFilter(RiskyRequestFilter())
app.logger.addHandler(handler)
app.logger.setLevel(logging.WARNING)
logging.getLogger().addHandler(handler)
logging.getLogger().setLevel(logging.WARNING)


# ✅ Apply security headers and log risky traffic
@app.after_request
def apply_security_headers(response):
    if response.status_code >= 400:
        app.logger.warning(
            f"{request.remote_addr} - {request.method} {request.path} "
            f"{response.status_code} UA: {request.headers.get('User-Agent')}"
        )

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' https://cdn.jsdelivr.net; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "form-action 'self'; frame-ancestors 'none';"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Strict-Transport-Security"] = (
        "max-age=63072000; includeSubDomains; preload"
    )
    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=()"
    )
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    response.headers["Cache-Control"] = (
        "no-store, no-cache, must-revalidate, private"
    )
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["Server"] = "Secure"

    return response


# ✅ Root route
@app.route('/')
def home():
    return render_template('index.html')


# ✅ Start app
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))  # Fly.io injects PORT
    app.run(debug=False, host='0.0.0.0', port=port)  # nosec
