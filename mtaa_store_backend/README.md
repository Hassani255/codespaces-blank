# Mtaa Store Backend

Node.js + Express + SQLite backend for the Mtaa Store demo.

## Quick start

1. `npm install`
2. Copy `.env.example` to `.env` and fill credentials
3. `npm run dev` or `npm start`

The server will create `mtaa.sqlite` and initialize tables on first run.

## Notes
- Configure MPESA keys and callback URL before using STK push in production.
- For Airtel Money and TigoPesa, contact provider or use aggregator (ClickPesa, DPO, Tola).
