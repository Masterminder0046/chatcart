
import os
import hmac
import hashlib
import logging

from flask import Flask, request, Response, jsonify
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

VERIFY_TOKEN = os.getenv("META_VERIFY_TOKEN", "")
APP_SECRET = os.getenv("META_APP_SECRET", "")


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
        return Response(challenge, status=200, mimetype="text/plain")

    return Response("Verification failed", status=403)


@app.post("/webhooks/instagram")
def receive_webhook():
    raw_body = request.get_data()

    # Validate Meta's request signature before trusting the payload.
    signature = request.headers.get("X-Hub-Signature-256", "")

    if not APP_SECRET or not signature.startswith("sha256="):
        return jsonify({"error": "Invalid signature"}), 401

    expected = "sha256=" + hmac.new(
        APP_SECRET.encode("utf-8"),
        raw_body,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature, expected):
        return jsonify({"error": "Invalid signature"}), 401

    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return jsonify({"error": "Invalid JSON"}), 400

    # Module 1 only: validate and log the event type.
    # We will process comment and messaging events in Module 2.
    app.logger.info(
        "Verified Instagram webhook received; object=%s",
        payload.get("object", "unknown")
    )

    return jsonify({"status": "received"}), 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
