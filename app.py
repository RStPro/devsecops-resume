from flask import Flask, render_template
import os


app = Flask(__name__)


@app.after_request
def apply_security_headers(response):
    # Anti-XSS and code injection
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' https://cdn.jsdelivr.net; "
        "script-src 'self' https://cdn.jsdelivr.net"
    )

    # Clickjacking protection
    response.headers["X-Frame-Options"] = "DENY"

    # MIME sniffing prevention
    response.headers["X-Content-Type-Options"] = "nosniff"

    # HSTS - enforce HTTPS
    response.headers["Strict-Transport-Security"] = (
        "max-age=63072000; includeSubDomains; preload"
    )

    # Permissions Policy
    response.headers["Permissions-Policy"] = (
        "geolocation=(), camera=(), microphone=()"
    )

    # Spectre protection
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"

    return response


@app.route('/')
def home():
    return render_template('index.html')


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))  # Fly.io injects PORT
