"""
QDrive OAuth Backend — hosted on Railway.
Handles Google OAuth2 flow so the QGIS plugin never sees client secrets.

Endpoints:
  GET /auth/login?port=XXXX  → Redirects to Google consent screen
  GET /auth/callback          → Receives code, exchanges for tokens, redirects to plugin
  GET /health                 → Health check
"""

import os
import json
import secrets

from flask import Flask, redirect, request, session, url_for, jsonify, render_template

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# ── Google OAuth Config (from Railway environment variables) ──
CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
SCOPES = [
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/userinfo.email",
]

# Google OAuth endpoints
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"


def _get_redirect_uri():
    """Build the redirect URI based on the current request host."""
    scheme = request.headers.get("X-Forwarded-Proto", request.scheme)
    host = request.headers.get("X-Forwarded-Host", request.host)
    return f"{scheme}://{host}/auth/callback"


# ──────────────────────────────────────────────────────────────
# Public Pages (for Google OAuth consent screen)
# ──────────────────────────────────────────────────────────────

@app.route("/")
def home():
    return render_template("home.html")


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/terms")
def terms():
    return render_template("terms.html")


# ──────────────────────────────────────────────────────────────
# API Routes
# ──────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "qdrive-backend"})


@app.route("/auth/login")
def auth_login():
    """Start the OAuth flow. Plugin passes ?port=XXXX for the local callback."""
    plugin_port = request.args.get("port", "")
    if not plugin_port:
        return "Error: 'port' parameter is required.", 400

    # Store the plugin's local port in session so we can redirect back after auth
    session["plugin_port"] = plugin_port

    # Build Google OAuth URL
    redirect_uri = _get_redirect_uri()
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "access_type": "offline",
        "prompt": "consent",
        "state": secrets.token_urlsafe(32),
    }
    session["oauth_state"] = params["state"]

    auth_url = GOOGLE_AUTH_URL + "?" + "&".join(
        f"{k}={v}" for k, v in params.items()
    )
    return redirect(auth_url)


@app.route("/auth/callback")
def auth_callback():
    """Handle Google's OAuth callback — exchange code for tokens."""
    import urllib.request
    import urllib.parse

    error = request.args.get("error")
    if error:
        return f"Google OAuth error: {error}", 400

    code = request.args.get("code")
    if not code:
        return "Missing authorization code.", 400

    # Exchange the auth code for tokens
    redirect_uri = _get_redirect_uri()
    token_data = urllib.parse.urlencode({
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            GOOGLE_TOKEN_URL,
            data=token_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urllib.request.urlopen(req) as resp:
            tokens = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return f"Token exchange failed: {e}", 500

    # Redirect tokens back to the plugin's local server
    plugin_port = session.get("plugin_port", "")
    if not plugin_port:
        return "Session expired. Please try logging in again.", 400

    # URL-encode the token JSON and send to plugin's local callback
    token_json = urllib.parse.quote(json.dumps(tokens))
    return redirect(f"http://localhost:{plugin_port}/callback?tokens={token_json}")


# ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
