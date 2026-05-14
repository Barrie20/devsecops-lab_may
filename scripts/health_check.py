"""
Health Check Script

Monitors application health by polling the /health endpoint.
Useful for container orchestration and deployment validation.
"""

import logging
import sys
import time

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

DEFAULT_URL = "http://localhost:8080/health"
MAX_RETRIES = 5
RETRY_DELAY = 3


def check_health(url: str = DEFAULT_URL, retries: int = MAX_RETRIES) -> bool:
    """
    Poll the health endpoint with retries.
    Returns True if the service is healthy.
    """
    for attempt in range(1, retries + 1):
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "healthy":
                    logger.info(
                        "Health check passed (attempt %d/%d): %s",
                        attempt,
                        retries,
                        data,
                    )
                    return True
            logger.warning(
                "Unhealthy response (attempt %d/%d): status=%d",
                attempt,
                retries,
                response.status_code,
            )
        except requests.exceptions.ConnectionError:
            logger.warning(
                "Connection failed (attempt %d/%d): service not reachable",
                attempt,
                retries,
            )
        except requests.exceptions.Timeout:
            logger.warning(
                "Timeout (attempt %d/%d): service too slow",
                attempt,
                retries,
            )

        if attempt < retries:
            time.sleep(RETRY_DELAY)

    logger.error("Health check failed after %d attempts", retries)
    return False


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL
    healthy = check_health(url)
    sys.exit(0 if healthy else 1)
