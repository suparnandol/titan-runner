import argparse
import datetime
import hashlib
import json
import logging
import random
import sys
import time
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from curl_cffi import requests
from eth_account import Account
from eth_account.messages import encode_defunct

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("gh-runner")

API_BASE = "https://testnet-api.titanx.cc"
ORIGIN = "https://testnet.titanx.cc"
DEFAULT_PROXY = "socks5h://127.0.0.1:9050"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
]

def d_pad(key: str, val: any) -> str:
    return f"{key}:".ljust(14) + str(val)

def format_decimal(val: any) -> str:
    t = str(val).strip()
    parts = t.split(".")
    whole = parts[0]
    dec = parts[1] if len(parts) > 1 else ""
    return f"{whole}.{dec.ljust(10, '0')}"

def format_iso(dt: datetime.datetime) -> str:
    s = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    return s.replace(".000Z", "Z")

def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()

def format_auth_message(credential: str, session_pubkey_hex: str, expiry: datetime.datetime, user_nonce: int) -> str:
    return "\n".join([
        "Daml-Perp-Session-Auth v=2",
        d_pad("scheme", "evm"),
        d_pad("credential", credential.lower()),
        d_pad("sessionPubKey", session_pubkey_hex),
        d_pad("expiry", format_iso(expiry)),
        d_pad("maxNotional", format_decimal("1000000")),
        d_pad("userNonce", user_nonce),
        d_pad("label", "")
    ])

def format_request_canonical(api_base: str, session_id: str, method: str, path: str, body_str: Optional[str], nonce: str, ts_str: str) -> str:
    query_str = path.split("?")[1] if "?" in path else ""
    clean_path = path.split("?")[0]
    body_sha = sha256_hex(body_str) if body_str is not None else "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    return "\n".join([
        "Daml-Perp-Request v=2",
        "aud: rest",
        f"origin: {api_base}",
        f"session: {session_id}",
        "conn: ",
        f"method: {method}",
        f"path: {clean_path}",
        f"query: {query_str}",
        f"body: {body_sha}",
        f"ts: {ts_str}",
        f"nonce: {nonce}",
        "expires: "
    ])

def format_order_canonical(session_id: str, market: str, side: str, order_type: str, size: str, price: str, tif: str, reduce_only: bool, nonce: str, ts_str: str) -> str:
    return "\n".join([
        "Daml-Perp-Order v=1",
        d_pad("sessionId", session_id),
        d_pad("market", market),
        d_pad("side", side),
        d_pad("type", order_type),
        d_pad("size", format_decimal(size)),
        d_pad("price", format_decimal(price)),
        d_pad("tif", tif),
        d_pad("reduceOnly", "true" if reduce_only else "false"),
        d_pad("nonce", nonce),
        d_pad("ts", ts_str),
        d_pad("expires", "")
    ])

def process_wallet(wallet_dict: dict, proxy: str = DEFAULT_PROXY) -> dict:
    wid = wallet_dict["id"]
    addr = wallet_dict["address"]
    privkey = wallet_dict["private_key"]
    username = wallet_dict.get("username", "")
    tier = wallet_dict.get("tier", "leaf")

    log.info(f"[{wid}] Processing {username} ({tier}) - {addr[:10]}...")

    acc = Account.from_key(privkey)
    private_key_ed = ed25519.Ed25519PrivateKey.generate()
    session_pubkey_hex = private_key_ed.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ).hex()

    ua = random.choice(USER_AGENTS)
    headers = {
        "Origin": ORIGIN,
        "Referer": f"{ORIGIN}/",
        "User-Agent": ua,
        "Content-Type": "application/json"
    }

    session = requests.Session(impersonate="chrome124", proxies={"http": proxy, "https": proxy})

    # Step 1: Auth Session
    expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=12)
    user_nonce = int(time.time() * 1000) * 1000000
    auth_msg = format_auth_message(addr, session_pubkey_hex, expiry, user_nonce)
    sig_hex = acc.sign_message(encode_defunct(text=auth_msg)).signature.hex()
    if sig_hex.startswith("0x"):
        sig_hex = sig_hex[2:]

    r_auth = None
    for attempt in range(1, 4):
        try:
            r_auth = session.post(
                f"{API_BASE}/v1/auth/session",
                headers=headers,
                json={"scheme": "evm", "message": auth_msg, "signature": sig_hex},
                timeout=20
            )
            if r_auth.status_code == 200:
                break
        except Exception as e:
            time.sleep(attempt * 1.5)

    if not r_auth or r_auth.status_code != 200:
        log.warning(f"[{wid}] Auth failed HTTP {r_auth.status_code if r_auth else 0}")
        return {"id": wid, "ok": False, "error": "auth_failed"}

    session_id = r_auth.json().get("sessionId")
    nonce_counter = int(datetime.datetime.now().timestamp() * 1000)

    def signed_req(method, path, body=None, custom_headers=None):
        nonlocal nonce_counter
        nonce_counter += 1
        ts_now = datetime.datetime.now(datetime.timezone.utc)
        ts_str = format_iso(ts_now)
        nonce_str = str(nonce_counter)
        body_str = json.dumps(body) if body is not None else None

        can = format_request_canonical(API_BASE, session_id, method, path, body_str, nonce_str, ts_str)
        req_sig = private_key_ed.sign(can.encode("utf-8")).hex()

        h = {
            "Accept": "application/json",
            "Origin": ORIGIN,
            "Referer": f"{ORIGIN}/",
            "User-Agent": ua,
            "X-Session-Id": session_id,
            "X-Request-Ts": ts_str,
            "X-Request-Nonce": nonce_str,
            "X-Request-Sig": req_sig
        }
        if custom_headers:
            h.update(custom_headers)
        if body_str is not None:
            h["Content-Type"] = "application/json"

        if method == "GET":
            return session.get(f"{API_BASE}{path}", headers=h, timeout=15)
        elif method == "POST":
            return session.post(f"{API_BASE}{path}", headers=h, data=body_str, timeout=15)

    time.sleep(1.0)

    # Step 2 & 3: Check balance & Claim Faucet with Dynamic Circuit Rotation
    ra = signed_req("GET", "/v1/me/account")
    avail = float(ra.json().get("available", 0.0)) if ra and ra.status_code == 200 else 0.0
    if avail < 10.0:
        for f_try in range(6):
            f_rnd = random.randint(100000, 999999)
            f_proxy = f"socks5h://faucet_{f_rnd}:pass@127.0.0.1:9050"
            f_sess = requests.Session(impersonate="chrome124", proxies={"http": f_proxy, "https": f_proxy})
            f_ts_now = datetime.datetime.now(datetime.timezone.utc)
            f_ts_str = format_iso(f_ts_now)
            nonce_counter += 1
            f_nonce = str(nonce_counter)
            f_can = format_request_canonical(API_BASE, session_id, "POST", "/v1/me/faucet", "{}", f_nonce, f_ts_str)
            f_sig = private_key_ed.sign(f_can.encode("utf-8")).hex()
            f_h = {
                "Accept": "application/json", "Origin": ORIGIN, "Referer": f"{ORIGIN}/",
                "User-Agent": ua, "Content-Type": "application/json",
                "X-Session-Id": session_id, "X-Request-Ts": f_ts_str, "X-Request-Nonce": f_nonce, "X-Request-Sig": f_sig
            }
            try:
                rf = f_sess.post(f"{API_BASE}/v1/me/faucet", headers=f_h, data="{}", timeout=15)
                if rf and rf.status_code in (200, 202):
                    break
                elif rf and "faucet_cooldown" in rf.text:
                    break
                elif rf and "faucet_ip_quota" in rf.text:
                    time.sleep(0.5)
                    continue
            except Exception:
                time.sleep(0.5)

        for _ in range(10):
            time.sleep(3.0)
            ra = signed_req("GET", "/v1/me/account")
            avail = float(ra.json().get("available", 0.0)) if ra and ra.status_code == 200 else 0.0
            if avail >= 10.0:
                break
        if avail < 10.0:
            log.warning(f"[{wid}] Insufficient balance ({avail:.2f})")
            return {"id": wid, "ok": False, "error": "insufficient_balance"}
            
    log.info(f"[{wid}] Balance OK ({avail:.2f} USDCx)")

    # Step 4: First Trade (Onboarding Bonus)
    market = "BTC-USDCX"
    notional = round(random.uniform(55.0, 115.0), 2)
    side = random.choice(["buy", "sell"])
    close_side = "sell" if side == "buy" else "buy"

    ro = None
    order_id = ""
    size_str = "0"
    actual_notional = 0.0

    for o_try in range(1, 4):
        ob = session.get(f"{API_BASE}/v1/markets/{market}/orderbook", headers=headers, timeout=10).json()
        if not ob.get("asks") or not ob.get("bids"):
            time.sleep(1.5)
            continue

        best_ask = float(ob["asks"][0]["price"])
        best_bid = float(ob["bids"][0]["price"])

        calc_size = notional / best_ask
        size_str = f"{calc_size:.5f}"
        actual_notional = float(size_str) * best_ask

        order_price = str(round(best_ask + 15.0, 1)) if side == "buy" else str(round(best_bid - 15.0, 1))

        nonce_counter += 1
        ts_order = format_iso(datetime.datetime.now(datetime.timezone.utc))
        order_can = format_order_canonical(session_id, market, side, "limit", size_str, order_price, "ioc", False, str(nonce_counter), ts_order)
        sig_order = private_key_ed.sign(order_can.encode("utf-8")).hex()

        try:
            ro = signed_req("POST", "/v1/orders", {
                "market": market,
                "side": side,
                "type": "limit",
                "size": size_str,
                "price": order_price,
                "tif": "ioc",
                "reduceOnly": False,
                "nonce": nonce_counter,
                "ts": ts_order
            }, custom_headers={"X-Session-Sig": sig_order})
            if ro and ro.status_code == 200 and ro.json().get("fills", 0) > 0:
                order_id = ro.json().get("orderId", "")
                log.info(f"[{wid}] Filled! Order ID: {order_id}")
                break
        except Exception:
            pass
        time.sleep(1.5)

    if not ro or ro.status_code != 200:
        log.warning(f"[{wid}] Order open failed HTTP {ro.status_code if ro else 0}")
        return {"id": wid, "ok": False, "error": "order_failed"}

    # Humanized hold
    hold_sec = random.uniform(6.0, 12.0)
    time.sleep(hold_sec)

    # Step 5: Read open position and close cleanly
    pos_items = []
    for _ in range(3):
        pos_res = signed_req("GET", "/v1/me/positions")
        if pos_res and pos_res.status_code == 200:
            pos_items = pos_res.json().get("items", [])
            if pos_items:
                break
        time.sleep(2.0)

    if pos_items:
        exact_size = str(abs(float(pos_items[0]["size"])))
        for c_try in range(1, 4):
            ob_c = session.get(f"{API_BASE}/v1/markets/{market}/orderbook", headers=headers, timeout=10).json()
            if not ob_c.get("asks") or not ob_c.get("bids"):
                time.sleep(1.5)
                continue
            b_ask_c = float(ob_c["asks"][0]["price"])
            b_bid_c = float(ob_c["bids"][0]["price"])
            c_price = str(round(b_ask_c + 15.0, 1)) if close_side == "buy" else str(round(b_bid_c - 15.0, 1))

            nonce_counter += 1
            ts_close = format_iso(datetime.datetime.now(datetime.timezone.utc))
            close_can = format_order_canonical(session_id, market, close_side, "limit", exact_size, c_price, "ioc", True, str(nonce_counter), ts_close)
            sig_close = private_key_ed.sign(close_can.encode("utf-8")).hex()

            rc = signed_req("POST", "/v1/orders", {
                "market": market,
                "side": close_side,
                "type": "limit",
                "size": exact_size,
                "price": c_price,
                "tif": "ioc",
                "reduceOnly": True,
                "nonce": nonce_counter,
                "ts": ts_close
            }, custom_headers={"X-Session-Sig": sig_close})
            if rc and rc.status_code == 200 and rc.json().get("fills", 0) > 0:
                log.info(f"[{wid}] Closed position cleanly!")
                break
            time.sleep(2.0)

    return {
        "id": wid,
        "address": addr,
        "username": username,
        "tier": tier,
        "ok": True,
        "order_id": order_id,
        "volume": actual_notional,
        "points": 250.0
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--batch-id", type=int, required=True, help="Matrix Batch ID (0-19)")
    parser.add_argument("--file", type=str, default="vip_wallets.json")
    args = parser.parse_args()

    with open(args.file) as f:
        wallets = json.load(f)

    start = args.batch_id * 10
    end = start + 10
    slice_wallets = wallets[start:end]

    log.info(f"Runner Batch {args.batch_id} processing {len(slice_wallets)} wallets (index {start} to {end-1})...")

    results = []
    for w in slice_wallets:
        r = process_wallet(w)
        results.append(r)
        time.sleep(random.uniform(4.5, 7.5))

    out_file = f"result_batch_{args.batch_id}.json"
    with open(out_file, "w") as f:
        json.dump({"batch_id": args.batch_id, "results": results}, f, indent=2)

    log.info(f"Batch {args.batch_id} complete. Saved to {out_file}")

if __name__ == "__main__":
    main()
