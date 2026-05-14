"""
DevSecOps Lab — Main Application

A simple Flask API demonstrating secure coding practices
including input validation, structured logging, and health checks.
"""

import logging
import os
from flask import Flask, jsonify, request

# Configure structured logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(__name__)


@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint for container orchestration."""
    return jsonify({"status": "healthy", "version": "1.0.0"}), 200


@app.route("/", methods=["GET"])
def index():
    """Root endpoint."""
    return jsonify({
        "application": "DevSecOps Lab",
        "version": "1.0.0",
        "endpoints": ["/", "/health", "/api/scan"],
    }), 200


@app.route("/api/scan", methods=["POST"])
def scan_endpoint():
    """
    Simulated security scan endpoint.
    Accepts a target URL and returns a mock scan result.
    """
    data = request.get_json(silent=True)

    if not data or "target" not in data:
        logger.warning("Invalid scan request: missing target field")
        return jsonify({"error": "Missing 'target' field in request body"}), 400

    target = data["target"]

    # Input validation — reject obviously malicious input
    if not isinstance(target, str) or len(target) > 2048:
        logger.warning("Invalid scan target: %s", type(target))
        return jsonify({"error": "Invalid target format"}), 400

    logger.info("Scan requested for target: %s", target)

    # Mock scan result
    result = {
        "target": target,
        "status": "completed",
        "findings": {
            "critical": 0,
            "high": 1,
            "medium": 3,
            "low": 5,
            "info": 12,
        },
        "recommendation": "Review high-severity findings before deployment.",
    }

    return jsonify(result), 200


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    debug = os.getenv("APP_ENV", "production") == "development"

    logger.info("Starting DevSecOps Lab on port %d (debug=%s)", port, debug)
    app.run(host="0.0.0.0", port=port, debug=debug)
