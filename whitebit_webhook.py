import base64
import hashlib
import hmac
import json
import os
from decimal import Decimal
from typing import Any, Dict, Optional, Type

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from dotenv import load_dotenv


from models import *


load_dotenv()


# -----------------------------------------------------------------------------
# Helpers to parse payloads into the appropriate dataclass
# -----------------------------------------------------------------------------

METHOD_TO_PARAMS: Dict[str, Type] = {
    "code.apply": CodeApplyParams,
    # deposit events
    "deposit.accepted": DepositParams,
    "deposit.updated": DepositParams,
    "deposit.processed": DepositParams,
    "deposit.canceled": DepositParams,
    # withdraw events
    "withdraw.unconfirmed": WithdrawParams,
    "withdraw.pending": WithdrawParams,
    "withdraw.canceled": WithdrawParams,
    "withdraw.successful": WithdrawParams,
}


def _as_decimal(val: Any) -> Decimal:
    # amounts/fees come as strings; use Decimal for precision
    return Decimal(str(val)) if val is not None else Decimal("0")


def _parse_confirmations(obj: Optional[Dict[str, Any]]) -> Optional[Confirmations]:
    if not obj:
        return None
    return Confirmations(actual=int(obj["actual"]), required=int(obj["required"]))


def parse_envelope(body: Dict[str, Any]) -> WebhookEnvelope:
    method = body.get("method")
    params_raw = body.get("params", {}) or {}
    uid = body.get("id")

    params_cls = METHOD_TO_PARAMS.get(method)
    if params_cls is None:
        # Unknown method: keep raw dict in params so you can still handle it
        return WebhookEnvelope(method=method, params=params_raw, id=uid)

    if params_cls is CodeApplyParams:
        params = CodeApplyParams(
            code=str(params_raw["code"]),
            nonce=int(params_raw["nonce"]),
        )
    elif params_cls is DepositParams:
        params = DepositParams(
            address=str(params_raw["address"]),
            amount=_as_decimal(params_raw["amount"]),
            createdAt=int(params_raw["createdAt"]),
            currency=str(params_raw["currency"]),
            description=params_raw.get("description"),
            fee=_as_decimal(params_raw["fee"]),
            memo=params_raw.get("memo"),
            method=int(params_raw["method"]),
            network=params_raw.get("network"),
            status=int(params_raw["status"]),
            ticker=str(params_raw["ticker"]),
            transactionHash=params_raw.get("transactionHash"),
            uniqueId=params_raw.get("uniqueId"),
            confirmations=_parse_confirmations(params_raw.get("confirmations")),
        )
    elif params_cls is WithdrawParams:
        params = WithdrawParams(
            address=str(params_raw["address"]),
            amount=_as_decimal(params_raw["amount"]),
            createdAt=int(params_raw["createdAt"]),
            currency=str(params_raw["currency"]),
            ticker=str(params_raw["ticker"]),
            description=params_raw.get("description"),
            fee=_as_decimal(params_raw["fee"]),
            memo=params_raw.get("memo"),
            method=int(params_raw["method"]),
            network=params_raw.get("network"),
            status=int(params_raw["status"]),
            transactionHash=params_raw.get("transactionHash"),
            uniqueId=params_raw.get("uniqueId"),
        )
    else:
        params = params_raw  # fallback

    return WebhookEnvelope(method=method, params=params, id=uid)


# -----------------------------------------------------------------------------
# Security: verify headers
# - X-TXC-APIKEY must match your key
# - X-TXC-PAYLOAD is base64(body)
# - X-TXC-SIGNATURE is hex(HMAC_SHA512(payload), key=api_secret))
# Docs: Request headers + verification. Retries: 5x every ~10 minutes.
# -----------------------------------------------------------------------------

API_KEY = os.environ.get("WHITEBIT_WEBHOOK_API_KEY", "")
API_SECRET = os.environ.get("WHITEBIT_WEBHOOK_API_SECRET", "")
PUBLIC_KEY = os.environ.get("WHITEBIT_WEBHOOK_PUBLIC_KEY", "")

if not (API_KEY and API_SECRET and PUBLIC_KEY):
    # Fail fast in dev if env is missing
    print("[WARN] WHITEBIT env vars not fully set; set them via .env")

def verify_signature(raw_body: bytes, x_payload: str, x_signature: str, api_secret: str) -> None:
    # 1) Recreate base64(body) to ensure header payload matches body
    expected_payload = base64.b64encode(raw_body).decode()
    if not hmac.compare_digest(expected_payload, x_payload):
        raise HTTPException(status_code=400, detail="Invalid payload header")

    # 2) Compute HMAC-SHA512 over the *payload header* bytes with api_secret
    mac = hmac.new(api_secret.encode("utf-8"), x_payload.encode("utf-8"), hashlib.sha512)
    expected_sig = mac.hexdigest()
    if not hmac.compare_digest(expected_sig, x_signature.lower()):
        raise HTTPException(status_code=401, detail="Bad signature")


# -----------------------------------------------------------------------------
# Nonce (replay protection)
# WhiteBIT includes an ever-increasing params.nonce. Keep the last seen per key.
# In production, store in Redis/DB (here: simple in-memory dict).
# -----------------------------------------------------------------------------

LAST_NONCE_BY_KEY: Dict[str, int] = {}


def enforce_nonce(api_key: str, nonce: Optional[int]) -> None:
    if nonce is None:
        return
    last = LAST_NONCE_BY_KEY.get(api_key)
    if last is not None and nonce <= last:
        raise HTTPException(status_code=409, detail="Nonce out of order (possible replay)")
    LAST_NONCE_BY_KEY[api_key] = nonce


# -----------------------------------------------------------------------------
# FastAPI app
# -----------------------------------------------------------------------------

app = FastAPI(title="WhiteBIT Webhook Handler", version="1.0.0")


@app.get("/whiteBIT-verification")
def whitebit_verification():
    """
    Domain verification option (returns JSON array with your public webhook key).
    Docs specify three ways: DNS TXT, text file, or this endpoint.
    """
    return JSONResponse([PUBLIC_KEY])


@app.post("/webhook")
async def whitebit_webhook(
    request: Request,
    x_txc_apikey: str = Header(..., convert_underscores=False),
    x_txc_payload: str = Header(..., convert_underscores=False),
    x_txc_signature: str = Header(..., convert_underscores=False),
):
    print(f"Received webhook: \n{x_txc_apikey},\n {x_txc_payload},\n {x_txc_signature}")
    # 1) Verify API key
    if not hmac.compare_digest(x_txc_apikey, API_KEY):
        print(f"Invalid API key: {x_txc_apikey}")
        raise HTTPException(status_code=401, detail="Bad API key")

    # 2) Read body and verify signature against payload header
    raw = await request.body()
    verify_signature(raw, x_txc_payload, x_txc_signature, API_SECRET)

    # 3) Parse envelope and params into dataclasses
    try:
        body = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError:
        print(f"Invalid JSON body\n {raw.decode('utf-8')}")
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    envelope = parse_envelope(body)

    # 4) Nonce replay protection (when present)
    # "params" type varies; get nonce if available
    nonce: Optional[int] = None
    params_obj = envelope.params
    if isinstance(params_obj, (CodeApplyParams, DepositParams, WithdrawParams)):
        nonce = getattr(params_obj, "nonce", None)
    else:
        # raw dict fallback
        if isinstance(params_obj, dict):
            nonce = params_obj.get("nonce")
    enforce_nonce(x_txc_apikey, nonce)

    # 5) Dispatch by method (business logic placeholders)
    # Return 200 quickly—WhiteBIT retries up to 5 times every ~10 minutes otherwise.
    method = envelope.method
    print(f"Handling method: {method}, params: {envelope.params}")
    try:
        if method == "code.apply":
            # handle code application
            # e.g., grant bonus, mark referral, etc.
            pass

        elif method.startswith("deposit."):
            # handle deposit.* events
            # accepted/updated/processed/canceled
            pass

        elif method.startswith("withdraw."):
            # handle withdraw.* events
            # unconfirmed/pending/canceled/successful
            pass

        else:
            # Unknown method: log and accept
            pass

    except Exception as exc:
        # If you cannot handle it, returning non-2xx lets WhiteBIT retry
        # Consider logging the 'id' and method for tracing
        raise HTTPException(status_code=500, detail=f"Handler error: {exc}")

    return {"ok": True, "id": envelope.id, "method": envelope.method}
