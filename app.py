from flask import Flask, render_template, request
import os

app = Flask(__name__)

@app.after_request
def apply_security_headers(response):
    # ✅ Content Security Policy - full with no fallback
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' https://cdn.jsdelivr.net; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "form-action 'self'; "
        "frame-ancestors 'none';"
    )

    # ✅ Clickjacking protection
    response.headers["X-Frame-Options"] = "DENY"

    # ✅ MIME sniffing protection
    response.headers["X-Content-Type-Options"] = "nosniff"

    # ✅ Enforce HTTPS
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"

    # ✅ Permissions policy (tight)
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

    # ✅ Cross-Origin protections
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"

    # ✅ Caching controls
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    # ✅ Attempt to hide version info (note: may be overridden by Fly.io infra)
    response.headers["Server"] = "Secure"

    return response


@app.route('/')
def home():
    return render_template('index.html')


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))  # Fly.io injects PORT
    app.run(debug=False, host='0.0.0.0', port=port)  # nosec
