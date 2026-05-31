import logging
import json
import time
from typing import Tuple
from flask import Flask, Response, render_template, request, jsonify  # type: ignore[reportMissingImports]
from werkzeug.exceptions import HTTPException  # type: ignore[reportMissingImports]

from core import CascadeDecoder, ArtifactHarvester, DecoderError, PayloadOverflowError

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","lvl":"%(levelname)s","mod":"%(name)s","msg":"%(message)s"}',
)
logger = logging.getLogger("midins.app")

REQUEST_HARD_LIMIT = 3_000_000

app = Flask(__name__, template_folder="templates")
app.config["MAX_CONTENT_LENGTH"] = REQUEST_HARD_LIMIT

_decoder = CascadeDecoder()
_harvester = ArtifactHarvester()


@app.after_request
def _harden_headers(response: Response) -> Response:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'"
    )
    return response


@app.route("/", methods=["GET"])
def render_dashboard() -> str:
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze_payload() -> Tuple[Response, int]:
    started = time.perf_counter()
    body = request.get_json(silent=True) or {}
    raw_data = body.get("payload", "")

    if not isinstance(raw_data, str) or not raw_data.strip():
        return jsonify({"ok": False, "error": "empty_payload"}), 400

    try:
        decoding_report = CascadeDecoder().run(raw_data)
    except PayloadOverflowError as exc:
        logger.warning("overflow rejected: %s", exc)
        return jsonify({"ok": False, "error": "payload_overflow", "detail": str(exc)}), 413
    except DecoderError as exc:
        logger.error("decoder error: %s", exc)
        return jsonify({"ok": False, "error": "decoder_failure", "detail": str(exc)}), 422

    artifacts = _harvester.harvest(decoding_report["final_payload"])
    total_ms = round((time.perf_counter() - started) * 1000, 4)

    return jsonify({
        "ok": True,
        "elapsed_ms": total_ms,
        "decoding": decoding_report,
        "artifacts": artifacts,
    }), 200


@app.errorhandler(HTTPException)
def _http_handler(exc: HTTPException):
    logger.warning("http %s: %s", exc.code, exc.description)
    return jsonify({"ok": False, "error": exc.name, "detail": exc.description}), exc.code


@app.errorhandler(Exception)
def _global_handler(exc: Exception):
    logger.exception("unhandled exception: %s", exc)
    return jsonify({"ok": False, "error": "internal_error"}), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
