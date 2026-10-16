
import os
import hmac
import hashlib
import logging

from flask import Flask, request, Response, jsonify
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

VERIFY_TOKEN = os.getenv("META_VERIFY_TOKEN", "").strip()
META_APP_SECRET = os.getenv("META_APP_SECRET", "").strip()
INSTAGRAM_APP_SECRET = os.getenv("INSTAGRAM_APP_SECRET", "").strip()


@app.get("/")
def health_check():
    return jsonify({
        "app": "ChatCart",
        "status": "running"
    }), 200


@app.get("/webhooks/instagram")
def verify_webhook():
    mode = request.args.get("hub.mode", "")
    token = request.args.get("hub.verify_token", "")
    challenge = request.args.get("hub.challenge")

    if (
        mode == "subscribe"
        and VERIFY_TOKEN
        and hmac.compare_digest(token, VERIFY_TOKEN)
        and challenge is not None
    ):
        app.logger.info("Instagram webhook verified")
        return Response(challenge, status=200, mimetype="text/plain")

    app.logger.warning("Instagram webhook verification failed")
    return Response("Verification failed", status=403)


def signature_matches(secret, signature, raw_body):
    """Validate Meta's X-Hub-Signature-256 header."""
    if not secret or not signature.startswith("sha256="):
        return False

    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"),
        raw_body,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(signature, expected)


@app.post("/webhooks/instagram")
def receive_webhook():
    # Read the original bytes before parsing JSON.
    raw_body = request.get_data(cache=True)
    signature = request.headers.get("X-Hub-Signature-256", "")

    app.logger.info(
        "Webhook diagnostic: header_present=%s, "
        "sha256_format=%s, meta_secret_configured=%s, "
        "instagram_secret_configured=%s",
        bool(signature),
        signature.startswith("sha256="),
        bool(META_APP_SECRET),
        bool(INSTAGRAM_APP_SECRET)
    )

    if not signature.startswith("sha256="):
        app.logger.warning("Webhook rejected: missing signature")
        return jsonify({"error": "Invalid signature"}), 401

    meta_match = signature_matches(
        META_APP_SECRET, signature, raw_body
    )
    instagram_match = signature_matches(
        INSTAGRAM_APP_SECRET, signature, raw_body
    )

    # Diagnostic only: do not log either secret or the signature.
    app.logger.info(
        "Signature diagnostic: meta_secret_match=%s, "
        "instagram_secret_match=%s",
        meta_match,
        instagram_match
    )

    if not (meta_match or instagram_match):
        app.logger.warning("Webhook rejected: signature mismatch")
        return jsonify({"error": "Invalid signature"}), 401

    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        app.logger.warning("Webhook rejected: invalid JSON")
        return jsonify({"error": "Invalid JSON"}), 400

    app.logger.info(
        "Verified Instagram webhook received; object=%s",
        payload.get("object", "unknown")
    )

    return jsonify({"status": "received"}), 200


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
    