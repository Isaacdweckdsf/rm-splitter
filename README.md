# RM-Splitter

A FastAPI service that takes orders from several sales channels, works out how each one should be packed and shipped, books it with Royal Mail Click & Drop, and writes the tracking number back to the channel it came from.

I built it at Diablo Sugar Free (a UK confectionery brand) to replace a manual process. It handled 350–400 orders a day, automated about 95% of the workflow and raised booking accuracy from roughly 65% to 98%.

## What it does

**Ingests orders from every channel into one model**

- Shopify and WooCommerce webhooks, verified with HMAC signatures
- TikTok Shop and Temu webhooks, verified with shared-secret headers
- Amazon, polled through the Selling Partner API (SP-API)
- An internal endpoint for manual or bulk orders

Each order is normalised into a single `InternalOrder` model before any rules run.

**Applies the packing and shipping rules**

- Weight first: over 750 g ships as a parcel; 750 g or under can go as a Large Letter, but only if every SKU's packaging profile allows it and the dimensions fit
- Heavy orders are split into 25 kg parcels plus a remainder, and no parcel ever exceeds 30 kg
- Picks the Royal Mail service code (24 or 48, optional Sunday routing, separate codes for Jersey and Guernsey)
- Per-SKU weights and dimensions come from `data/sku_packaging_profiles.csv`

**Books, labels and syncs back**

- Creates the order (or split orders) in Click & Drop
- Fetches tracking numbers and pushes them back: Shopify fulfilment orders, WooCommerce order notes
- Amazon Buy Shipping: buys the label through SP-API and merges it with a generated packing slip into one printable PDF
- Internal labels page with single and batch PDF printing

**Built to run unattended**

- Idempotency, so a repeated webhook never creates a duplicate order
- Dead-letter log for orders that fail, with personal data redacted
- Per-rule metrics, a failure-rate alert every 2 minutes, and a weekly dead-letter summary
- Background jobs on APScheduler; state in SQLite

## Stack

Python · FastAPI · Uvicorn · Pydantic · Requests · APScheduler · SQLite · ReportLab · pypdf · Pillow

## Running it locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# create a .env file with the variables below
uvicorn app:app --reload
```

### Configuration

All secrets are read from `.env`; nothing sensitive lives in the code.

| Variable | Required | Purpose |
| --- | --- | --- |
| `RM_CLICKDROP_TOKEN` | Yes | Royal Mail Click & Drop API token |
| `INTERNAL_API_KEY` | Yes | Protects internal endpoints (`X-Internal-Key` header) |
| `SHOPIFY_WEBHOOK_SECRET`, `SHOPIFY_ADMIN_TOKEN`, `SHOPIFY_SHOP` | For Shopify | Webhook verification and tracking sync |
| `WOO_WEBHOOK_SECRET`, `WOO_BASE_URL`, `WOO_KEY`, `WOO_SECRET` | For WooCommerce | Webhook verification and order notes |
| `TIKTOK_WEBHOOK_SECRET`, `TEMU_WEBHOOK_SECRET` | For TikTok / Temu | Shared-secret webhook checks |
| `SPAPI_*`, `AMAZON_POLL_ENABLED`, `AMAZON_BUY_SHIPPING_ENABLED` | For Amazon | SP-API credentials and feature flags |
| `ALERT_WEBHOOK_URL` | Optional | Where failure alerts are sent |
| `SERVICE_*`, `MAX_PARCEL_WEIGHT_G`, `HARD_PARCEL_LIMIT_G`, `USE_SUNDAY_ROUTING`, `BUSINESS_TZ` | Optional | Tune service codes and packing limits |

## Endpoints

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| GET | `/health` | None | Health check |
| POST | `/webhooks/shopify` | HMAC | Shopify orders |
| POST | `/webhooks/woo` | HMAC | WooCommerce orders |
| POST | `/webhooks/tiktok` | Shared secret | TikTok Shop orders |
| POST | `/webhooks/temu` | Shared secret | Temu orders |
| POST | `/ingest/internal` | Internal key | Manual / bulk orders |
| GET | `/internal/poll` | Internal key | Trigger a tracking sync |
| GET | `/metrics`, `/metrics.csv` | Internal key | Rule-path and failure metrics |
| GET | `/deadletters.csv` | Internal key | Failed orders |
| GET | `/dashboard` | Internal key | Operations dashboard |
| GET | `/internal/labels` | Internal key | Label printing page |
| GET/POST | `/internal/labels/...` | Internal key | Label PDFs, single and batch |

## Notes

This service was written for one business's workflow, so some defaults (service codes, ship-from details, packaging profiles) reflect that setup and would need changing for another shop.
