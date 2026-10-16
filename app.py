
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

VERIFY_TOKEN = os.getenv("META_VERIFY_TOKEN", "")
APP_SECRET = os.getenv("INSTAGRAM_APP_SECRET", "").strip()


@app.get("/")
def health_check():
    return jsonify({
        "app": "ChatCart",
        "status": "running"
    }), 200


@app.get("/webhooks/instagram")
def verify_webhook():
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    if (
        mode == "subscribe"
        and VERIFY_TOKEN
        and hmac.compare_digest(token or "", VERIFY_TOKEN)
        and challenge is not None
    ):
        app.logger.info("Instagram webhook verified")
        return Response(
            challenge,
            status=200,
            mimetype="text/plain"
        )

    app.logger.warning("Instagram webhook verification failed")
    return Response("Verification failed", status=403)


@app.post("/webhooks/instagram")
def receive_webhook():
    # Read the exact raw request body before parsing JSON.
    raw_body = request.get_data(cache=True)

    signature = request.headers.get(
        "X-Hub-Signature-256", ""
    )

    # Safe diagnostic logs: never log the secret or full signature.
    app.logger.info(
        "Webhook signature diagnostic: header_present=%s, "
        "sha256_format=%s, app_secret_configured=%s",
        bool(signature),
        signature.startswith("sha256="),
        bool(APP_SECRET),
    )

    if not APP_SECRET:
        app.logger.error(
            "META_APP_SECRET is missing from the environment"
        )
        return jsonify({"error": "Webhook configuration error"}), 500

    if not signature.startswith("sha256="):
        app.logger.warning(
            "Webhook rejected: missing or invalid signature header"
        )
        return jsonify({"error": "Invalid signature"}), 401

    expected_signature = "sha256=" + hmac.new(
        APP_SECRET.encode("utf-8"),
        raw_body,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature, expected_signature):
        app.logger.warning(
            "Webhook rejected: signature mismatch"
        )
        return jsonify({"error": "Invalid signature"}), 401

    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        app.logger.warning(
            "Webhook signature valid, but JSON payload is invalid"
        )
        return jsonify({"error": "Invalid JSON"}), 400

    # Log only basic metadata; do not log message content or customer data.
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
