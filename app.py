"""
Secure Royal Mail Click & Drop integration service.

Core responsibilities:
- Receive orders from multiple ecommerce platforms via webhooks.
- Apply your business rules:
    * Weight-first: > 750g => parcel; <= 750g MAY be Large Letter.
    * Large Letter only if SKU profile allows and dims fit.
    * Split heavy parcels: 20kg chunks + final remainder, never >30kg.
    * Optional: RM24 for orders created on Sunday (ship Monday), RM48 other days, in BUSINESS_TZ (configurable).
- Create orders via Click & Drop API.
- Fetch tracking numbers and sync back to platforms (Shopify + Woo note).
- Maintain:
    * Idempotency (avoid duplicate orders).
    * Dead-letter log for failed orders.
    * Metrics for rule paths + failures.
- Provide:
    * Health check.
    * Metrics and dead-letter CSV (protected by internal API key).
- Security:
    * All secrets in .env, not in code.
    * Internal endpoints protected by INTERNAL_API_KEY header.
    * Webhooks protected by HMAC/shared secrets.
"""

import os, hmac, base64, hashlib, json, sqlite3
from datetime import datetime
from typing import List, Optional, Tuple, Dict

import pytz
import requests
from fastapi import FastAPI, Request, HTTPException, Header, Depends
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv

# ---------------------------------------------------
# 1) Load environment variables / secrets
# ---------------------------------------------------

load_dotenv()

RM_TOKEN = os.getenv("RM_CLICKDROP_TOKEN", "").strip()
if not RM_TOKEN:
    raise RuntimeError("Missing RM_CLICKDROP_TOKEN in .env")
	
# New explicit codes (LL vs Parcel, Sunday vs other days)
SERVICE_LL_SUN       = os.getenv("SERVICE_LL_SUN", "TRN24")
SERVICE_PARCEL_SUN   = os.getenv("SERVICE_PARCEL_SUN", "TPN24")
SERVICE_LL_OTHER     = os.getenv("SERVICE_LL_OTHER", "TRS48")
SERVICE_PARCEL_OTHER = os.getenv("SERVICE_PARCEL_OTHER", "TPS48")

# Toggle: if false, ignore weekday completely and always use *_OTHER codes.
# When true, orders created on Sunday (in BUSINESS_TZ) use *_SUN codes.
USE_SUNDAY_ROUTING = os.getenv("USE_SUNDAY_ROUTING", "false").lower() == "true"

PACKAGING_CSV = os.getenv("PACKAGING_CSV", "data/sku_packaging_profiles.csv")
ALLOW_MULTI_LL = os.getenv("ALLOW_MULTI_LL", "false").lower() == "true"
BUSINESS_TZ = os.getenv("BUSINESS_TZ", "Europe/London")

# Webhook secrets – must be set in production
SHOPIFY_SECRET = (os.getenv("SHOPIFY_WEBHOOK_SECRET") or "").strip()
WOO_SECRET     = (os.getenv("WOO_WEBHOOK_SECRET") or "").strip()
TIKTOK_SECRET  = (os.getenv("TIKTOK_WEBHOOK_SECRET") or "").strip()
TEMU_SECRET    = (os.getenv("TEMU_WEBHOOK_SECRET") or "").strip()

# Platform API tokens
SHOPIFY_ADMIN_TOKEN = (os.getenv("SHOPIFY_ADMIN_TOKEN") or "").strip()
SHOPIFY_SHOP = (os.getenv("SHOPIFY_SHOP") or "").strip()
WOO_BASE_URL = (os.getenv("WOO_BASE_URL") or "").rstrip("/")
WOO_KEY = (os.getenv("WOO_KEY") or "").strip()
WOO_SECRET_API = (os.getenv("WOO_SECRET") or "").strip()

# Internal API key to protect internal-only endpoints
INTERNAL_API_KEY = (os.getenv("INTERNAL_API_KEY") or "").strip()
if not INTERNAL_API_KEY:
    raise RuntimeError("Missing INTERNAL_API_KEY in .env")

# Alerts
ALERT_WEBHOOK_URL = (os.getenv("ALERT_WEBHOOK_URL") or "").strip()
FAILURE_ALERT_THRESHOLD = float(os.getenv("FAILURE_ALERT_THRESHOLD", "0.05"))

# Amazon poller config (not implemented yet)
AMAZON_POLL_ENABLED = (os.getenv("AMAZON_POLL_ENABLED","false").lower()=="true")
AMAZON_POLL_INTERVAL_SECONDS = int(os.getenv("AMAZON_POLL_INTERVAL_SECONDS", "60"))

# ---------------------------------------------------
# 2) SQLite: idempotency, cursors, metrics, dead letters
# ---------------------------------------------------

DB_PATH = "state.db"

def db_init():
    """Create SQLite tables if they do not exist yet."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # idempotency: (source, raw_id) -> Click & Drop order identifier
    c.execute("""CREATE TABLE IF NOT EXISTS events(
        source TEXT NOT NULL,
        raw_id TEXT NOT NULL,
        cd_order_identifier INTEGER,
        created_at TEXT NOT NULL,
        PRIMARY KEY (source, raw_id)
    )""")

    # generic key->value storage (e.g., cursors)
    c.execute("""CREATE TABLE IF NOT EXISTS cursors(
        name TEXT PRIMARY KEY,
        value TEXT
    )""")

    # dead letters: failed orders with reasons + payload
    c.execute("""CREATE TABLE IF NOT EXISTS dead_letters(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT NOT NULL,
        raw_id TEXT NOT NULL,
        reason TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    )""")

    # metrics: per-minute counts by source, rule and outcome
    c.execute("""CREATE TABLE IF NOT EXISTS metrics(
        ts_min TEXT NOT NULL,    -- UTC minute such as 2025-11-18T17:20Z
        source TEXT NOT NULL,    -- shopify/woocommerce/tiktok/temu/internal
        rule TEXT NOT NULL,      -- LL_pass/LL_fail/Parcel_single/Heavy_split/Created/Failed/Duplicate/TrackingSync
        outcome TEXT NOT NULL,   -- ok/fail
        count INTEGER NOT NULL,
        PRIMARY KEY (ts_min, source, rule, outcome)
    )""")

    conn.commit()
    conn.close()

db_init()

def seen(source: str, raw_id: str) -> Optional[int]:
    """Check if we already created a C&D order for this (source, raw_id)."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT cd_order_identifier FROM events WHERE source=? AND raw_id=?",
              (source, raw_id))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

def record_creation(source: str, raw_id: str, cd_order_identifier: int):
    """Record that we successfully created a C&D order for this event."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""INSERT OR REPLACE INTO events(source,raw_id,cd_order_identifier,created_at)
                 VALUES(?,?,?,?)""",
              (source, raw_id, cd_order_identifier,
               datetime.utcnow().isoformat()+"Z"))
    conn.commit()
    conn.close()

def get_cursor(name: str) -> Optional[str]:
    """Get a stored cursor value (for pollers)."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT value FROM cursors WHERE name=?", (name,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

def set_cursor(name: str, value: str):
    """Store or update a cursor value."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""INSERT OR REPLACE INTO cursors(name,value)
                 VALUES(?,?)""", (name, value))
    conn.commit()
    conn.close()

def _now_minute_utc():
    """Return current UTC time truncated to minutes as ISO string, e.g. 2025-11-18T17:03Z."""
    return datetime.utcnow().replace(second=0, microsecond=0)\
                            .isoformat(timespec="minutes") + "Z"

def record_metric(source: str, rule: str, outcome: str):
    """
    Increment a metric counter:
    - source: origin of the order (shopify/woocommerce/...)
    - rule:   which decision path or stage (LL_pass, LL_fail, Created, Failed, etc.)
    - outcome: 'ok' or 'fail'
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    ts = _now_minute_utc()
    c.execute("""INSERT INTO metrics(ts_min,source,rule,outcome,count)
                 VALUES(?,?,?,?,1)
                 ON CONFLICT(ts_min,source,rule,outcome)
                 DO UPDATE SET count = count+1""",
              (ts, source, rule, outcome))
    conn.commit()
    conn.close()

def record_dead_letter(source: str, raw_id: str, reason: str, payload: dict):
    """
    Store a failed order with a reason and a trimmed payload
    (do NOT dump all PII here).
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""INSERT INTO dead_letters(source,raw_id,reason,payload_json,created_at)
                 VALUES(?,?,?,?,?)""",
              (source, raw_id, reason,
               json.dumps(payload, ensure_ascii=False),
               datetime.utcnow().isoformat()+"Z"))
    conn.commit()
    conn.close()

# ---------------------------------------------------
# 3) Models: internal representation of orders
# ---------------------------------------------------

class OrderLine(BaseModel):
    sku: str
    name: Optional[str] = ""
    quantity: int = 1
    unitWeightInGrams: Optional[int] = None  # may be missing; CSV wins

class Address(BaseModel):
    fullName: str
    addressLine1: str
    city: str
    postcode: str
    countryCode: str = "GB"
    addressLine2: Optional[str] = None
    phoneNumber: Optional[str] = None
    emailAddress: Optional[str] = None
    companyName: Optional[str] = None

class InternalOrder(BaseModel):
    """
    Normalised order object our pipeline expects, regardless of source platform.
    """
    source: str          # shopify / woocommerce / tiktok / temu / amazon / internal
    raw_id: str          # native platform order ID
    orderReference: str  # what we send to C&D (prefix + raw_id)
    recipient: Address

    currencyCode: str = "GBP"
    subtotal: float = 0.0
    shippingCostCharged: float = 0.0
    total: float = 0.0
    orderDate: Optional[str] = None
    lines: List[OrderLine] = []
    serviceCode: Optional[str] = None  # override RM24/RM48 rule if needed

# ---------------------------------------------------
# 4) Packaging DB: CSV with SKU weight and dims
# ---------------------------------------------------

from dataclasses import dataclass

@dataclass
class Profile:
    allow_ll: bool
    weight_g: Optional[int]
    h_mm: Optional[float]
    w_mm: Optional[float]
    d_mm: Optional[float]

SKU_CACHE: Dict[str, Profile] = {}

def _to_float(x):
    try:
        if x is None:
            return None
        xs = str(x).strip()
        if xs == "" or xs.lower() == "nan":
            return None
        return float(xs)
    except:
        return None

def load_profiles():
    """Load SKU profiles (weight/dims/LL flag) from CSV into memory."""
    global SKU_CACHE
    SKU_CACHE = {}
    if not os.path.exists(PACKAGING_CSV):
        return
    import csv
    with open(PACKAGING_CSV, newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            sku = (row.get("sku") or "").strip()
            if not sku:
                continue
            allow = str(row.get("allow_large_letter","")).strip().lower() in ("1","true","yes")
            wg = _to_float(row.get("packed_weight_g"))
            wg = int(wg) if wg is not None else None
            h = _to_float(row.get("dim_h_mm"))
            w = _to_float(row.get("dim_w_mm"))
            d = _to_float(row.get("dim_d_mm"))
            SKU_CACHE[sku] = Profile(allow, wg, h, w, d)

load_profiles()

# ---------------------------------------------------
# 5) Decision rules: LL vs parcel, splitting heavy orders
# ---------------------------------------------------

LL_WG = 750                    # max weight for Large Letter in grams
LL_LIMITS = (25, 250, 353)     # (height, width, depth) in mm for LL slot

def dims_fit(h, w, d) -> bool:
    """
    Check whether the given dims can fit the LL limits in ANY orientation.
    Returns False if any dimension is missing.
    """
    if None in (h, w, d):
        return False
    for H, W, D in ((h,w,d),(h,d,w),(w,h,d),(w,d,h),(d,h,w),(d,w,h)):
        if H <= LL_LIMITS[0] and W <= LL_LIMITS[1] and D <= LL_LIMITS[2]:
            return True
    return False

def choose_service_code(is_large_letter: bool,
                        now_utc: Optional[datetime] = None) -> str:
    """
    Pick the correct Royal Mail service code based on:
    - Business timezone (BUSINESS_TZ).
    - Monday vs other days.
    - Large Letter vs Parcel.

    Uses the four env vars:
      SERVICE_LL_SUN, SERVICE_PARCEL_SUN,
      SERVICE_LL_OTHER, SERVICE_PARCEL_OTHER.

    Behaviour:
    - If USE_SUNDAY_ROUTING is false:
        always use the *_OTHER (48h) codes, regardless of weekday.
    - If USE_SUNDAY_ROUTING is true:
        * local Sunday (weekday == 6): use *_SUN (24h) codes
        * all other days: use *_OTHER (48h) codes

    If you later want “only part of Sunday”, add a time window check
    where we decide is_sunday in BUSINESS_TZ.
    """
    # If routing is disabled, always use *_OTHER codes
    if not USE_SUNDAY_ROUTING:
        return SERVICE_LL_OTHER if is_large_letter else SERVICE_PARCEL_OTHER

    # Convert current UTC time into business local time
    tz = pytz.timezone(BUSINESS_TZ)
    local_dt = (now_utc or datetime.utcnow()).replace(tzinfo=pytz.UTC).astimezone(tz)
    weekday = local_dt.weekday()    # Monday = 0, Sunday = 6

    is_sunday = (weekday == 6)

    # Sunday => use 24h services, Other days => use 48h services
    if is_sunday:
        return SERVICE_LL_SUN if is_large_letter else SERVICE_PARCEL_SUN
    else:
        return SERVICE_LL_OTHER if is_large_letter else SERVICE_PARCEL_OTHER
def split_parcel_weights(total_g: int) -> List[int]:
    """
    Split total_g into multiple parcels:
    - Keep taking 20kg chunks (20000g).
    - Final parcel is the remainder.
    - No parcel may exceed 30kg (30000g).
    """
    parts = []
    r = total_g
    while r > 20000:
        parts.append(20000)
        r -= 20000
    if r > 0:
        parts.append(r)
    if any(p > 30000 for p in parts):
        raise ValueError("Computed a package > 30kg")
    return parts

def compute_weight_and_dims(
    lines: List[OrderLine],
) -> Tuple[int, bool, Optional[Tuple[float, float, float]]]:
    """
    Compute:
    - total weight in grams,
    - whether we are allowed to consider Large Letter,
    - (dims are no longer used; always None).

    Logic now:
    - Weight is from CSV (if present), else from platform line item.
    - If total > LL_WG: cannot be LL.
    - LL eligibility:
        * all SKUs must have allow_ll = True in SKU_CACHE
        * default: require single SKU and qty = 1 (unless ALLOW_MULTI_LL=true)
    - Dimensions from CSV are ignored. LL vs parcel is purely:
        * total weight <= LL_WG
        * allow_large_letter flags
    """
    total_g = 0
    all_allow = True
    sku_set = set()
    qty_sum = 0

    for ln in lines:
        sku = (ln.sku or "").strip()
        qty = int(ln.quantity or 1)
        prof = SKU_CACHE.get(sku)

        # Weight: prefer CSV packed_weight_g, else unitWeightInGrams from platform
        unit_g = (prof.weight_g if (prof and prof.weight_g is not None)
                  else (ln.unitWeightInGrams or 0))
        total_g += unit_g * qty
        sku_set.add(sku)
        qty_sum += qty

        # LL permission flag from CSV
        allow_this = bool(prof.allow_ll) if prof is not None else False
        if not allow_this:
            all_allow = False

    # Too heavy for LL
    if total_g > LL_WG:
        return total_g, False, None

    single = (len(sku_set) == 1 and qty_sum == 1)
    can_ll = all_allow and (single or ALLOW_MULTI_LL)

    # We no longer depend on dims; always None
    return total_g, can_ll, None

# ---------------------------------------------------
# 6) Click & Drop API client
# ---------------------------------------------------

CD_BASE = "https://api.parcel.royalmail.com/api/v1"

def cd_headers():
    """HTTP headers for C&D API requests."""
    return {
        "Authorization": f"Bearer {RM_TOKEN}",
        "Content-Type": "application/json"
    }

def cd_create_order(io: InternalOrder, packages: List[dict], service_code: str) -> dict:
    """
    Create an order in Click & Drop with one or more packages.
    NOTE: We don't log the full response here; callers decide what to do.
    """
    body = {
        "items": [{
            "orderReference": io.orderReference[:40],
            "recipient": {
                "address": {
                    "fullName": io.recipient.fullName,
                    "companyName": io.recipient.companyName or "",
                    "addressLine1": io.recipient.addressLine1,
                    "addressLine2": io.recipient.addressLine2 or "",
                    "city": io.recipient.city,
                    "postcode": io.recipient.postcode,
                    "countryCode": io.recipient.countryCode
                },
                "phoneNumber": io.recipient.phoneNumber or "",
                "emailAddress": io.recipient.emailAddress or ""
            },
            "orderDate": io.orderDate or datetime.utcnow().isoformat() + "Z",
            "subtotal": round(io.subtotal, 2),
            "shippingCostCharged": round(io.shippingCostCharged, 2),
            "total": round(io.total, 2),
            "currencyCode": io.currencyCode,
            "packages": packages,

			"billing": {
   				 "address": {
				    "fullName": io.recipient.fullName,
				    "companyName": io.recipient.companyName or "",
				    "addressLine1": io.recipient.addressLine1,
				    "addressLine2": io.recipient.addressLine2 or "",
				    "city": io.recipient.city,
				    "postcode": io.recipient.postcode,
				    "countryCode": io.recipient.countryCode
				 }
			},
            "postageDetails": {
                "serviceCode": io.serviceCode or service_code,
                "sendNotificationsTo": "recipient",
                "requestSignatureUponDelivery": False
            }
        }]
    }
    r = requests.post(f"{CD_BASE}/orders", headers=cd_headers(),
                      json=body, timeout=30)
    if r.status_code != 200:
        # We re-wrap as HTTPException for FastAPI but do not leak token
        raise HTTPException(status_code=502,
                            detail=f"Click & Drop error {r.status_code}")
    return r.json()

def cd_get_order(order_id: int) -> dict:
    """Fetch a single order from Click & Drop (used to get tracking numbers)."""
    r = requests.get(f"{CD_BASE}/orders/{order_id}",
                     headers=cd_headers(), timeout=30)
    if r.status_code != 200:
        return {}
    return r.json()

# ---------------------------------------------------
# 7) Tracking sync back to platforms (basic)
# ---------------------------------------------------

def _extract_tracking_numbers(cd_order_json: dict) -> List[str]:
    """Pull tracking numbers from a C&D order JSON."""
    trks = set()
    if not isinstance(cd_order_json, dict):
        return []
    for p in cd_order_json.get("packages", []):
        tn = p.get("trackingNumber") or p.get("trackingId")
        if tn:
            trks.add(str(tn))
    sd = cd_order_json.get("shippingDetails", {})
    tn = sd.get("trackingNumber") or sd.get("trackingId")
    if tn:
        trks.add(str(tn))
    return sorted(trks)

def _shopify_fulfill(order_raw_id: str, tracking_numbers: List[str], io: InternalOrder):
    """
    Basic Shopify fulfillment creation using REST API.
    If you want a more advanced, Fulfillment Orders-based flow, this can be replaced later.
    """
    if not (SHOPIFY_ADMIN_TOKEN and SHOPIFY_SHOP):
        return {"skipped": "no_shopify_creds"}
    url = f"https://{SHOPIFY_SHOP}/admin/api/2023-10/orders/{order_raw_id}/fulfillments.json"
    headers = {
        "X-Shopify-Access-Token": SHOPIFY_ADMIN_TOKEN,
        "Content-Type": "application/json"
    }
    tracking_info = {
        "number": tracking_numbers[0] if tracking_numbers else "",
        "company": "Royal Mail"
    }
    payload = {
        "fulfillment": {
            "notify_customer": True,
            "tracking_info": tracking_info
        }
    }
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=30)
        return {"status": resp.status_code, "text": resp.text[:300]}
    except Exception as e:
        return {"error": str(e)}

def _woo_note(order_raw_id: str, tracking_numbers: List[str]):
    """
    Add a simple WooCommerce order note with tracking info.
    If you use a dedicated tracking plugin, you can call its endpoint instead.
    """
    if not (WOO_BASE_URL and WOO_KEY and WOO_SECRET_API):
        return {"skipped": "no_woo_creds"}
    note = f"Royal Mail tracking: {', '.join(tracking_numbers) if tracking_numbers else 'created'}"
    try:
        url = f"{WOO_BASE_URL}/wp-json/wc/v3/orders/{order_raw_id}/notes"
        resp = requests.post(url, auth=(WOO_KEY, WOO_SECRET_API),
                             json={"note": note}, timeout=30)
        return {"status": resp.status_code, "text": resp.text[:300]}
    except Exception as e:
        return {"error": str(e)}

def sync_tracking_back(source: str, raw_id: str,
                       order_identifier: int, io: InternalOrder):
    """
    Get tracking number(s) from C&D and push to source platform.
    Currently:
    - Shopify: creates a fulfillment with tracking.
    - Woo: adds order note with tracking.
    - Others: just record tracking.
    """
    cd_json = cd_get_order(order_identifier)
    trks = _extract_tracking_numbers(cd_json)
    out = {"source": source, "raw_id": raw_id, "tracking": trks}
    if source == "shopify":
        out["shopify"] = _shopify_fulfill(raw_id, trks, io)
    elif source == "woocommerce":
        out["woocommerce"] = _woo_note(raw_id, trks)
    elif source in ("tiktok", "temu", "amazon"):
        out["info"] = "tracking captured; platform push not implemented yet"
    return out

# ---------------------------------------------------
# 8) Alerts: high failure rate detection
# ---------------------------------------------------

def _send_alert(message: str):
    """Send a text payload to ALERT_WEBHOOK_URL (Slack, Teams, etc.)."""
    if not ALERT_WEBHOOK_URL:
        return
    try:
        requests.post(ALERT_WEBHOOK_URL, json={"text": message}, timeout=10)
    except Exception:
        # Do not raise; alerts are best-effort
        pass

def check_failure_rates_and_alert():
    """
    Every 2 minutes, look at last 10 minutes of metrics and send an alert
    if failure rate > FAILURE_ALERT_THRESHOLD (e.g. 5%) with at least 20 events.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT source, rule, outcome, SUM(count) AS cnt
        FROM metrics
        WHERE ts_min >= datetime('now','-10 minutes')
        GROUP BY source, rule, outcome
    """)
    rows = c.fetchall()
    conn.close()

    by_source = {}
    for source, rule, outcome, cnt in rows:
        by_source.setdefault(source, {"ok": 0, "fail": 0})
        if outcome == "fail":
            by_source[source]["fail"] += cnt
        else:
            by_source[source]["ok"] += cnt

    alerts = []
    for src, agg in by_source.items():
        total = agg["ok"] + agg["fail"]
        if total >= 20:
            rate = (agg["fail"] / total) if total else 0.0
            if rate >= FAILURE_ALERT_THRESHOLD:
                alerts.append(
                    f"{src}: failure rate {rate:.1%} over last 10 min "
                    f"(fail={agg['fail']}, total={total})"
                )

    if alerts:
        _send_alert("\n".join(alerts))

# ---------------------------------------------------
# 9) Core pipeline: idempotency, rules, C&D call, tracking sync
# ---------------------------------------------------

def process_internal_order(io: InternalOrder) -> dict:
    """
    Main pipeline:
    - Check idempotency.
    - Compute weight & LL eligibility.
    - Decide LL vs parcel; split heavy parcels.
    - Create order in C&D.
    - Record metrics and dead letters.
    - Fetch tracking and sync back.
    """
    already = seen(io.source, io.raw_id)
    if already is not None:
        record_metric(io.source, "Duplicate", "ok")
        return {"status": "duplicate_ignored", "orderIdentifier": already}

    try:
        total_g, can_ll, _ = compute_weight_and_dims(io.lines)

        # Decide once whether this order is being treated as Large Letter.
        # Now purely based on:
        #  - LL weight threshold (<= LL_WG)
        #  - allow_large_letter flags in CSV
        is_large_letter = bool(can_ll and total_g <= LL_WG)

        # Metric: which rule path was taken
        if total_g > LL_WG:
            rule = "Parcel_single" if total_g <= 20000 else "Heavy_split"
        else:
            rule = "LL_pass" if is_large_letter else "LL_fail"
        record_metric(io.source, rule, "ok")

        # Choose service code based on Monday vs other days and LL vs Parcel
        service = choose_service_code(is_large_letter)

        # Build contents list from order lines for RM
        contents = []
        for ln in io.lines:
            sku = (ln.sku or "").strip()
            qty = int(ln.quantity or 1)
            prof = SKU_CACHE.get(sku)

            # Prefer CSV packed_weight_g if present, else unitWeightInGrams, else 0
            unit_g = None
            if prof and prof.weight_g is not None:
                unit_g = prof.weight_g
            elif ln.unitWeightInGrams is not None:
                unit_g = ln.unitWeightInGrams
            else:
                unit_g = 0

            contents.append({
                "sku": sku or "UNKNOWN",
                "description": (ln.name or sku or "Item"),
                "quantity": qty,
                "weightInGrams": int(unit_g) if unit_g is not None else 0
                # value / origin / HS code left out for now (domestic not needed)
            })

        # Build packages for C&D
        packages = []
        if is_large_letter:
            # Single Large Letter package, no dims needed
            packages = [{
                "weightInGrams": int(total_g),
                "packageFormatIdentifier": "largeLetter"
                "contents": contents
            }]
        else:
            # Parcel(s) – use 20kg + remainder rule
            split_weights = split_parcel_weights(total_g)
            for idx, w in enumerate(split_weights):
                pkg = {
                    "weightInGrams": int(w),
                    "packageFormatIdentifier": "parcel"
                }
                # For now: attach full contents to the first parcel only.
                # If you ever care about per-parcel contents you can
                # get smarter here and actually split.
                if idx == 0:
                    pkg["contents"] = contents
                packages.append(pkg)
                
        # Call Click & Drop
        res = cd_create_order(io, packages, service)
        created = res.get("createdOrders", [])
        if created:
            oid = created[0]["orderIdentifier"]
            record_creation(io.source, io.raw_id, oid)
            record_metric(io.source, "Created", "ok")

            # Attempt tracking sync back to source platform
            try:
                sync_res = sync_tracking_back(io.source, io.raw_id, oid, io)
            except Exception as e:
                sync_res = {"sync_error": str(e)}
                record_metric(io.source, "TrackingSync", "fail")

            return {
                "status": "created",
                "orderIdentifier": oid,
                "packages": packages,
                "trackingSync": sync_res
            }

        # No createdOrders returned -> treat as failure
        record_metric(io.source, "Failed", "fail")
        record_dead_letter(io.source, io.raw_id,
                           "Click&Drop create failed", {"response": res})
        return {"status": "failed", "packages": packages}

    except HTTPException as e:
        # C&D HTTP error (502 etc.)
        record_metric(io.source, "Failed", "fail")
        record_dead_letter(io.source, io.raw_id,
                           f"HTTP {e.status_code}",
                           {"detail": str(e.detail)})
        raise

    except Exception as e:
        # Any other unexpected error
        record_metric(io.source, "Failed", "fail")
        safe_payload = {
            "orderReference": io.orderReference,
            "source": io.source,
            "raw_id": io.raw_id,
            "lines": [ln.dict() for ln in io.lines],
            "recipient_city": io.recipient.city,
            "recipient_postcode": io.recipient.postcode
        }
        record_dead_letter(io.source, io.raw_id,
                           f"Exception: {type(e).__name__}: {str(e)}",
                           safe_payload)
        raise

# ---------------------------------------------------
# 10) Helpers: HMAC verification and mappers
# ---------------------------------------------------

def make_order_ref(prefix: str, raw_id: str) -> str:
    """Combine platform prefix and raw ID into one orderReference string."""
    return f"{prefix}-{raw_id}"

def shopify_hmac_ok(body: bytes, header_hmac: str) -> bool:
    """
    Verify Shopify webhook HMAC.
    In production, SHOPIFY_SECRET must be set.
    """
    if not SHOPIFY_SECRET:
        # Security-first approach: reject if secret missing
        return False
    calc = base64.b64encode(
        hmac.new(SHOPIFY_SECRET.encode("utf-8"), body, hashlib.sha256).digest()
    ).decode()
    return hmac.compare_digest(calc, header_hmac or "")

def woo_hmac_ok(body: bytes, header_sig: str) -> bool:
    """Verify WooCommerce webhook signature using shared secret."""
    if not WOO_SECRET:
        return False
    calc = base64.b64encode(
        hmac.new(WOO_SECRET.encode("utf-8"), body, hashlib.sha256).digest()
    ).decode()
    return hmac.compare_digest(calc, header_sig or "")

def shared_secret_ok(header_value: str, secret: str) -> bool:
    """Simple shared-secret header check for TikTok/Temu."""
    if not secret:
        return False
    return hmac.compare_digest((header_value or ""), secret)

def to_internal_from_shopify(payload: dict) -> InternalOrder:
    """Map raw Shopify order JSON to InternalOrder."""
    raw_id = str(payload["id"])
    addr = payload.get("shipping_address") or {}
    email = payload.get("email") or (addr.get("email") if isinstance(addr, dict) else None)

    lines = []
    for li in payload.get("line_items", []):
        sku = li.get("sku") or li.get("variant_id") or li.get("title") or "UNKNOWN"
        qty = int(li.get("quantity") or 1)
        unit_g = li.get("grams") or None
        lines.append(OrderLine(
            sku=str(sku),
            name=li.get("name") or "",
            quantity=qty,
            unitWeightInGrams=unit_g
        ))

    recipient = Address(
        fullName=(addr.get("name") or f"{addr.get('first_name','')} {addr.get('last_name','')}".strip()),
        companyName=addr.get("company"),
        addressLine1=addr.get("address1") or "",
        addressLine2=addr.get("address2"),
        city=addr.get("city") or "",
        postcode=addr.get("zip") or "",
        countryCode=(addr.get("country_code") or "GB"),
        phoneNumber=addr.get("phone"),
        emailAddress=email
    )

    return InternalOrder(
        source="shopify",
        raw_id=raw_id,
        orderReference=make_order_ref("SH", raw_id),
        recipient=recipient,
        currencyCode=payload.get("currency", "GBP"),
        subtotal=float(payload.get("subtotal_price") or 0),
        shippingCostCharged=float(
            (payload.get("total_shipping_price_set") or {})
            .get("shop_money", {}).get("amount") or 0
        ),
        total=float(payload.get("total_price") or 0),
        lines=lines,
        orderDate=payload.get("created_at")
    )

def to_internal_from_woo(payload: dict) -> InternalOrder:
    """Map WooCommerce order JSON to InternalOrder."""
    raw_id = str(payload.get("id") or payload.get("number") or payload.get("order_key"))
    ship = payload.get("shipping", {})
    email = payload.get("billing", {}).get("email")

    lines = []
    for li in payload.get("line_items", []):
        sku = li.get("sku") or li.get("product_id") or li.get("name") or "UNKNOWN"
        qty = int(li.get("quantity") or 1)
        lines.append(OrderLine(
            sku=str(sku),
            name=li.get("name") or "",
            quantity=qty,
            unitWeightInGrams=None  # from CSV
        ))

    full_name = (ship.get("first_name", "") + " " + ship.get("last_name", "")).strip()
    if not full_name:
        full_name = (payload.get("billing", {}).get("first_name", "") + " " +
                     payload.get("billing", {}).get("last_name", "")).strip()

    recipient = Address(
        fullName=full_name,
        companyName=ship.get("company") or None,
        addressLine1=ship.get("address_1") or "",
        addressLine2=ship.get("address_2") or None,
        city=ship.get("city") or "",
        postcode=ship.get("postcode") or "",
        countryCode=(ship.get("country") or "GB"),
        phoneNumber=payload.get("billing", {}).get("phone"),
        emailAddress=email
    )

    return InternalOrder(
        source="woocommerce",
        raw_id=raw_id,
        orderReference=make_order_ref("WO", raw_id),
        recipient=recipient,
        currencyCode=payload.get("currency", "GBP"),
        subtotal=float(payload.get("subtotal") or 0),
        shippingCostCharged=float(payload.get("shipping_total") or 0),
        total=float(payload.get("total") or 0),
        lines=lines,
        orderDate=payload.get("date_created")
    )

def to_internal_from_generic(payload: dict, source: str, prefix: str) -> InternalOrder:
    """
    Generic mapper for platforms where you shape the webhook yourself (TikTok/Temu/etc).
    Expects "shipping"/"address" and "items"/"line_items".
    """
    raw_id = str(payload.get("id") or payload.get("order_id") or payload.get("number"))
    ship = payload.get("shipping") or payload.get("address") or {}

    recip = Address(
        fullName=ship.get("fullName") or (ship.get("name") or ""),
        companyName=ship.get("companyName") or None,
        addressLine1=ship.get("addressLine1") or ship.get("address1") or "",
        addressLine2=ship.get("addressLine2") or ship.get("address2"),
        city=ship.get("city") or "",
        postcode=ship.get("postcode") or ship.get("zip") or "",
        countryCode=ship.get("countryCode") or ship.get("country") or "GB",
        phoneNumber=ship.get("phoneNumber") or ship.get("phone"),
        emailAddress=ship.get("emailAddress") or payload.get("email")
    )

    lines = []
    for li in payload.get("items", payload.get("line_items", [])):
        sku = li.get("sku") or li.get("id") or li.get("name") or "UNKNOWN"
        qty = int(li.get("quantity") or 1)
        unit_g = li.get("unitWeightInGrams") or None
        lines.append(OrderLine(
            sku=str(sku),
            name=li.get("name") or "",
            quantity=qty,
            unitWeightInGrams=unit_g
        ))

    return InternalOrder(
        source=source,
        raw_id=raw_id,
        orderReference=make_order_ref(prefix, raw_id),
        recipient=recip,
        currencyCode=payload.get("currency", "GBP"),
        subtotal=float(payload.get("subtotal") or 0),
        shippingCostCharged=float(payload.get("shipping") or 0),
        total=float(payload.get("total") or 0),
        lines=lines,
        orderDate=payload.get("created_at") or payload.get("createdAt")
    )

# ---------------------------------------------------
# 11) FastAPI app + security for internal endpoints
# ---------------------------------------------------

# Disable automatic docs in production for less attack surface
app = FastAPI(docs_url=None, redoc_url=None)

async def check_internal_auth(x_internal_key: Optional[str] = Header(None)):
    """
    Dependency that enforces INTERNAL_API_KEY header on sensitive routes.
    Any request without the correct key gets HTTP 401.
    """
    if not INTERNAL_API_KEY or x_internal_key != INTERNAL_API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return True

@app.get("/health")
def health():
    """Simple health endpoint (can be left public for uptime checks)."""
    return {"ok": True, "profiles_loaded": len(SKU_CACHE)}

@app.post("/ingest/internal")
async def ingest_internal(io: InternalOrder,
                          _=Depends(check_internal_auth)):
    """Internal-only ingestion endpoint (protected by INTERNAL_API_KEY)."""
    return process_internal_order(io)

@app.post("/webhooks/shopify")
async def wh_shopify(request: Request,
                     x_shopify_hmac_sha256: Optional[str] = Header(None)):
    """
    Shopify Orders webhook.
    - Verifies HMAC.
    - Maps to InternalOrder.
    - Sends to pipeline.
    """
    body = await request.body()
    if not shopify_hmac_ok(body, x_shopify_hmac_sha256 or ""):
        raise HTTPException(status_code=401, detail="Shopify signature failed")
    payload = await request.json()
    io = to_internal_from_shopify(payload)
    return process_internal_order(io)

@app.post("/webhooks/woo")
async def wh_woo(request: Request,
                 x_wc_webhook_signature: Optional[str] = Header(None)):
    """
    WooCommerce Orders webhook.
    - Verifies signature.
    - Maps to InternalOrder.
    - Sends to pipeline.
    """
    body = await request.body()
    if not woo_hmac_ok(body, x_wc_webhook_signature or ""):
        raise HTTPException(status_code=401, detail="Woo signature failed")
    payload = await request.json()
    io = to_internal_from_woo(payload)
    return process_internal_order(io)

@app.post("/webhooks/tiktok")
async def wh_tiktok(request: Request,
                    x_tiktok_signature: Optional[str] = Header(None)):
    """
    TikTok Shop webhook.
    - Uses simple shared-secret header.
    - Expects a normalised JSON payload.
    """
    if not shared_secret_ok(x_tiktok_signature or "", TIKTOK_SECRET):
        raise HTTPException(status_code=401, detail="TikTok signature failed")
    payload = await request.json()
    io = to_internal_from_generic(payload, "tiktok", "TT")
    return process_internal_order(io)

@app.post("/webhooks/temu")
async def wh_temu(request: Request,
                  x_temu_signature: Optional[str] = Header(None)):
    """
    Temu webhook.
    - Uses simple shared-secret header.
    - Expects a normalised JSON payload.
    """
    if not shared_secret_ok(x_temu_signature or "", TEMU_SECRET):
        raise HTTPException(status_code=401, detail="Temu signature failed")
    payload = await request.json()
    io = to_internal_from_generic(payload, "temu", "TE")
    return process_internal_order(io)

# ---- Metrics, CSV exports and dashboard (all internal-only) ----

@app.get("/metrics")
def get_metrics(_=Depends(check_internal_auth)):
    """Return last 24h metrics as JSON."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""SELECT ts_min, source, rule, outcome, count
                 FROM metrics
                 WHERE ts_min >= datetime('now','-1 day')
                 ORDER BY ts_min DESC, source, rule, outcome""")
    rows = [
        {"ts_min": r[0], "source": r[1],
         "rule": r[2], "outcome": r[3], "count": r[4]}
        for r in c.fetchall()
    ]
    conn.close()
    return {"metrics": rows}

@app.get("/metrics.csv", response_class=PlainTextResponse)
def get_metrics_csv(_=Depends(check_internal_auth)):
    """Download up to last 30 days of metrics as CSV."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""SELECT ts_min, source, rule, outcome, count
                 FROM metrics
                 WHERE ts_min >= datetime('now','-30 day')
                 ORDER BY ts_min DESC, source, rule, outcome""")
    out = ["ts_min,source,rule,outcome,count"]
    for r in c.fetchall():
        out.append(",".join([str(r[0]), str(r[1]),
                             str(r[2]), str(r[3]), str(r[4])]))
    conn.close()
    return "\n".join(out)

@app.get("/deadletters.csv", response_class=PlainTextResponse)
def get_deadletters_csv(_=Depends(check_internal_auth)):
    """Download recent dead letters as CSV for investigation."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""SELECT created_at, source, raw_id, reason, payload_json
                 FROM dead_letters
                 ORDER BY id DESC LIMIT 5000""")
    out = ["created_at,source,raw_id,reason,payload_json"]
    for r in c.fetchall():
        pj = str(r[4]).replace('"', '""')
        out.append(f'{r[0]},{r[1]},{r[2]},"{r[3]}","{pj}"')
    conn.close()
    return "\n".join(out)

@app.get("/dashboard")
def dashboard(_=Depends(check_internal_auth)):
    """Quick JSON snapshot: dead-letter count and failure rates per source."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""SELECT COUNT(*)
                 FROM dead_letters
                 WHERE created_at >= datetime('now','-1 day')""")
    dl_24h = c.fetchone()[0]

    c.execute("""SELECT source,
                        SUM(CASE WHEN outcome='fail' THEN count ELSE 0 END) as fails,
                        SUM(count) as total
                 FROM metrics
                 WHERE ts_min >= datetime('now','-1 day')
                 GROUP BY source""")
    per_src = []
    for src, fails, total in c.fetchall():
        rate = (fails / total) if total else 0.0
        per_src.append({
            "source": src,
            "fail_rate_24h": round(rate, 4),
            "fails": fails,
            "total": total
        })
    conn.close()
    return {"dead_letters_24h": dl_24h, "per_source": per_src}

# ---------------------------------------------------
# 12) Amazon poller stub + scheduler startup
# ---------------------------------------------------

def amazon_poll_once():
    """
    Placeholder for Amazon SP-API polling.
    When you implement:
      - Use SP-API getOrders with created/updated since last cursor.
      - Map to InternalOrder.
      - Call process_internal_order().
      - Store new cursor with set_cursor().
    """
    pass

sched = BackgroundScheduler()
# Check failure rates every 2 minutes
sched.add_job(check_failure_rates_and_alert,
              "interval", minutes=2,
              max_instances=1, coalesce=True)
if AMAZON_POLL_ENABLED:
    sched.add_job(amazon_poll_once,
                  "interval",
                  seconds=AMAZON_POLL_INTERVAL_SECONDS,
                  max_instances=1,
                  coalesce=True)
sched.start()
