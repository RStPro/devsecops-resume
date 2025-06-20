from flask import Flask, render_template
import os


class RemoveServerHeaderMiddleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        def custom_start_response(status, headers, exc_info=None):
            filtered = [
                (k, v) for (k, v) in headers
                if k.lower() != "server"
            ]
            return start_response(status, filtered, exc_info)
        return self.app(environ, custom_start_response)


app = Flask(__name__)
app.wsgi_app = RemoveServerHeaderMiddleware(app.wsgi_app)


@app.after_request
def apply_security_headers(response):
    # ✅ Security Headers
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

    # ✅ Explicitly override Server header
    response.headers["Server"] = "Secure"

    return response


@app.route('/')
def home():
    return render_template('index.html')


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))  # Fly.io injects PORT
    app.run(debug=False, host='0.0.0.0', port=port)  # nosec
