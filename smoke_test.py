import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import NoReturn

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

API_BASE_URL = os.environ.get("API_BASE_URL", "http://localhost:8080")
PUBLIC_KEY_PATH = os.environ.get("PUBLIC_KEY_PATH", "./keys/ed25519.public")
PAYLOAD = "smoke test legal document"
PASSPHRASE = "correct horse battery staple"


def canonical_timestamp(dt: datetime) -> str:
    # Must match securedocs_worker.processor.canonical_timestamp exactly:
    # the Ed25519 signature is over hash || this string.
    utc = dt.astimezone(timezone.utc)
    millis = utc.microsecond // 1000
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{millis:03d}Z"


def fail(message: str) -> NoReturn:
    print(f"SMOKE TEST FAILED: {message}", file=sys.stderr)
    sys.exit(1)


def _get(url: str) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def _post_json(url: str, body: dict[str, str]) -> tuple[int, bytes]:
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def wait_for_api_ready(timeout: float = 90.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status, _ = _get(f"{API_BASE_URL}/health/ready")
        if status == 200:
            print("API is ready")
            return
        time.sleep(2)
    fail("API did not become ready in time")


def submit_document() -> str:
    status, body = _post_json(
        f"{API_BASE_URL}/Documents",
        {"payload": PAYLOAD, "passphrase": PASSPHRASE},
    )
    if status != 201:
        fail(f"submit failed: HTTP {status} {body!r}")
    document_id = json.loads(body)["documentId"]
    print(f"submitted documentId={document_id}")
    return document_id


def wait_for_proof(document_id: str, timeout: float = 60.0) -> dict[str, str]:
    url = f"{API_BASE_URL}/Documents/{document_id}/integrity"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status, body = _get(url)
        if status == 200:
            print("integrity proof available")
            return json.loads(body)
        if status != 404:
            fail(f"unexpected integrity status: HTTP {status} {body!r}")
        time.sleep(1)
    fail("document was not processed in time")


def verify_signature(proof: dict[str, str]) -> None:
    try:
        with open(PUBLIC_KEY_PATH, "rb") as handle:
            public_key = load_pem_public_key(handle.read())
    except OSError as error:
        fail(f"could not read public key at {PUBLIC_KEY_PATH}: {error}")

    if not isinstance(public_key, Ed25519PublicKey):
        fail("public key file is not an Ed25519 key")

    digest = base64.b64decode(proof["hash"])
    signature = base64.b64decode(proof["signature"])
    processed_at = datetime.fromisoformat(proof["processedAt"])
    signed_message = digest + canonical_timestamp(processed_at).encode("utf-8")

    try:
        public_key.verify(signature, signed_message)
    except InvalidSignature:
        fail("SIGNATURE VERIFICATION FAILED — proof is not independently verifiable")
    print("signature verified")


def main() -> None:
    wait_for_api_ready()
    document_id = submit_document()
    proof = wait_for_proof(document_id)
    verify_signature(proof)
    print("\nSMOKE TEST PASSED — end-to-end proof verified independently")


if __name__ == "__main__":
    main()
