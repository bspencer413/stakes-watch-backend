from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
import bcrypt
import psycopg2
import os
import urllib.request
import urllib.parse
import json as json_lib
from contextlib import contextmanager
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

# ── Config ─────────────────────────────────────────────────────────────────────

SECRET_KEY = os.environ.get("SECRET_KEY", "stakes-watch-secret-2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 10080

# Reuses the MW Postgres but with sw_ prefixed tables for full data isolation.
# Set DATABASE_URL in Render env vars to override.
DB_HOST = os.environ.get("DB_HOST", "dpg-d6qhp3ngi27c73a3ivag-a.oregon-postgres.render.com")
DB_USER = os.environ.get("DB_USER", "memorial_watch_db_user")
DB_PASS = os.environ.get("DB_PASS", "9IkXRdY8NcZSKy0yw5b7viPdtIrVIITR")
DB_NAME = os.environ.get("DB_NAME", "memorial_watch_db")
DATABASE_URL = os.environ.get("DATABASE_URL",
    "postgresql://" + DB_USER + ":" + DB_PASS + "@" + DB_HOST + "/" + DB_NAME)

KALSHI_API_BASE = "https://api.elections.kalshi.com/trade-api/v2"

# ── Database ───────────────────────────────────────────────────────────────────

def init_db():
    conn = psycopg2.connect(DATABASE_URL)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS sw_users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS sw_watchlist (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        location TEXT,
        status TEXT DEFAULT 'active',
        is_resolved BOOLEAN DEFAULT FALSE,
        resolution_outcome TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES sw_users (id)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS sw_notifications (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        watchlist_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES sw_users (id),
        FOREIGN KEY (watchlist_id) REFERENCES sw_watchlist (id)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS sw_snapshots (
        watchlist_id INTEGER PRIMARY KEY,
        snapshot_json TEXT NOT NULL,
        captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (watchlist_id) REFERENCES sw_watchlist (id)
    )""")
    conn.commit()
    conn.close()

@contextmanager
def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    try:
        yield conn
    finally:
        conn.close()

# ── Models ─────────────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class WatchlistItem(BaseModel):
    name: str
    location: Optional[str] = None
    is_resolved: Optional[bool] = False
    resolution_outcome: Optional[str] = None

# ── App ────────────────────────────────────────────────────────────────────────

app = FastAPI(title="Stakes Watch API", version="0.2.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# ── Auth helpers ───────────────────────────────────────────────────────────────

def hash_password(p: str) -> str:
    return bcrypt.hashpw(p.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(p: str, h: str) -> bool:
    return bcrypt.checkpw(p.encode("utf-8"), h.encode("utf-8"))

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    to_encode.update({"exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid authentication")
        return int(user_id)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ── Health ─────────────────────────────────────────────────────────────────────

@app.api_route("/health", methods=["GET", "HEAD"])
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat(),
            "version": "0.2.1", "app": "Stakes Watch"}

# ── Auth ───────────────────────────────────────────────────────────────────────

@app.post("/auth/register", response_model=Token)
async def register(user: UserCreate):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM sw_users WHERE email = %s", (user.email,))
        if c.fetchone():
            raise HTTPException(status_code=400, detail="Email already registered")
        c.execute("INSERT INTO sw_users (email, password_hash) VALUES (%s, %s) RETURNING id",
                  (user.email, hash_password(user.password)))
        user_id = c.fetchone()[0]
        conn.commit()
        return {"access_token": create_access_token({"sub": str(user_id)}), "token_type": "bearer"}

@app.post("/auth/login", response_model=Token)
async def login(user: UserLogin):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT id, password_hash FROM sw_users WHERE email = %s", (user.email,))
        result = c.fetchone()
        if not result or not verify_password(user.password, result[1]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        return {"access_token": create_access_token({"sub": str(result[0])}), "token_type": "bearer"}

@app.delete("/account")
async def delete_account(user_id: int = Depends(get_current_user)):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""DELETE FROM sw_snapshots WHERE watchlist_id IN
                     (SELECT id FROM sw_watchlist WHERE user_id = %s)""", (user_id,))
        c.execute("DELETE FROM sw_notifications WHERE user_id = %s", (user_id,))
        c.execute("DELETE FROM sw_watchlist WHERE user_id = %s", (user_id,))
        c.execute("DELETE FROM sw_users WHERE id = %s", (user_id,))
        conn.commit()
        return {"message": "Account permanently deleted"}

# ── Watchlist ──────────────────────────────────────────────────────────────────

@app.get("/watchlist")
async def get_watchlist(user_id: int = Depends(get_current_user)):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""SELECT id, name, location, status, created_at, is_resolved, resolution_outcome
                     FROM sw_watchlist WHERE user_id = %s AND status = 'active'
                     ORDER BY created_at DESC""", (user_id,))
        return [{"id": r[0], "name": r[1], "location": r[2],
                 "status": r[3], "created_at": str(r[4]),
                 "is_resolved": r[5] or False, "resolution_outcome": r[6]}
                for r in c.fetchall()]

@app.post("/watchlist")
async def add_to_watchlist(item: WatchlistItem, user_id: int = Depends(get_current_user)):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""INSERT INTO sw_watchlist (user_id, name, location, is_resolved, resolution_outcome)
                     VALUES (%s, %s, %s, %s, %s) RETURNING id""",
                  (user_id, item.name, item.location,
                   item.is_resolved or False, item.resolution_outcome))
        new_id = c.fetchone()[0]
        conn.commit()
        return {"id": new_id, "name": item.name, "location": item.location}

@app.delete("/watchlist/{item_id}")
async def remove_from_watchlist(item_id: int, user_id: int = Depends(get_current_user)):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("UPDATE sw_watchlist SET status = 'deleted' WHERE id = %s AND user_id = %s",
                  (item_id, user_id))
        if c.rowcount == 0:
            conn.rollback()
            raise HTTPException(status_code=404, detail="Item not found")
        c.execute("DELETE FROM sw_snapshots WHERE watchlist_id = %s", (item_id,))
        conn.commit()
        return {"message": "Removed"}

# ── Notifications ──────────────────────────────────────────────────────────────

@app.get("/notifications")
async def get_notifications(user_id: int = Depends(get_current_user)):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""SELECT n.id, n.message, n.created_at, w.name, n.watchlist_id
                     FROM sw_notifications n
                     JOIN sw_watchlist w ON n.watchlist_id = w.id
                     WHERE n.user_id = %s
                     ORDER BY n.created_at DESC LIMIT 50""", (user_id,))
        return [{"id": r[0], "name": r[3], "message": r[1],
                 "created_at": str(r[2]), "watchlist_id": r[4]}
                for r in c.fetchall()]

@app.delete("/notifications/{notif_id}")
async def delete_notification(notif_id: int, user_id: int = Depends(get_current_user)):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM sw_notifications WHERE id = %s AND user_id = %s",
                  (notif_id, user_id))
        conn.commit()
        return {"deleted": True}

# ── Kalshi proxy (bypasses browser CORS) ───────────────────────────────────────

def fetch_url(url: str, timeout: int = 15):
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json, text/plain, */*",
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json_lib.loads(resp.read().decode())
    except Exception as e:
        print("[kalshi] fetch error " + url + ": " + str(e))
        return None


def parse_price_cents(val):
    """Convert Kalshi's new dollar-string field (e.g. '0.6500') to int cents 0-100.
    Returns None for empty/null/non-numeric input."""
    if val is None or val == "":
        return None
    try:
        return int(round(float(val) * 100))
    except (ValueError, TypeError):
        return None


def parse_volume(val):
    """Convert Kalshi's volume_fp string (e.g. '12345.00') to int. Returns None
    for empty/null/non-numeric input."""
    if val is None or val == "":
        return None
    try:
        return int(float(val))
    except (ValueError, TypeError):
        return None


def market_last_price_cents(m):
    """Read last price as int cents 0-100 from whichever field Kalshi uses.
    They added *_dollars (float string) alongside the old *_price (int cents)."""
    val = m.get("last_price_dollars")
    if val not in (None, "", "0", "0.0", "0.00", "0.0000"):
        out = parse_price_cents(val)
        if out is not None and out > 0:
            return out
    val = m.get("last_price")
    if isinstance(val, (int, float)) and val > 0:
        return int(val)
    return None


def market_volume_24h(m):
    """Read 24h volume as int from whichever field Kalshi uses."""
    val = m.get("volume_24h_fp")
    if val not in (None, "", "0", "0.0", "0.00"):
        out = parse_volume(val)
        if out:
            return out
    val = m.get("volume_24h")
    if isinstance(val, (int, float)) and val > 0:
        return int(val)
    return None


def is_parlay(m):
    """Detect Kalshi's auto-generated multi-leg parlay markets. These show up as
    'multi-game extended' and 'cross-category' bundles, displayed with payout
    multipliers like '1.3X .92' on Kalshi. They flood the /markets endpoint and
    don't fit our binary YES/NO watchlist model."""
    if not isinstance(m, dict):
        return False
    if m.get("is_provisional"):
        return True
    if m.get("strike_type") == "custom":
        return True
    if m.get("mve_selected_legs"):
        return True
    ticker = m.get("ticker") or ""
    if ticker.startswith("KXMVE"):  # Multi-Variate Event prefix
        return True
    return False


def clean_title(m):
    """Pick the cleanest human-readable title for a Kalshi market.
    Prefers subtitle (per-market question form), falls back to title (event-level),
    then yes_sub_title. Detects and rejects the comma-joined yes-prefixed
    concatenations that some multi-option Kalshi markets emit as their primary
    text (e.g. 'yes New York,yes Donovan Mitchell: 25+,yes Jalen Brunson: 25+').
    Truncates anything over 120 chars.
    Returns None when no clean title is available."""
    subtitle = (m.get("subtitle") or "").strip()
    title = (m.get("title") or "").strip()
    yes_sub = (m.get("yes_sub_title") or "").strip()

    def is_ugly_yes_join(s):
        if not s:
            return False
        low = s.lower()
        return low.count(",yes ") >= 2 or low.count(", yes ") >= 2

    for candidate in (subtitle, title, yes_sub):
        if candidate and not is_ugly_yes_join(candidate):
            if len(candidate) > 120:
                return candidate[:117] + "..."
            return candidate
    return None


def slim_market(m):
    """Reduce a Kalshi market object to the fields the frontend needs.
    Returns None for parlays, for markets without a clean displayable title,
    and normalizes Kalshi's *_dollars / *_fp string fields to int cents / int
    volume so the frontend can treat all markets uniformly."""
    if not isinstance(m, dict):
        return None
    if is_parlay(m):
        return None
    title = clean_title(m)
    if not title:
        return None
    return {
        "ticker": m.get("ticker"),
        "event_ticker": m.get("event_ticker"),
        "title": title,
        "subtitle": m.get("subtitle", ""),
        "yes_sub_title": m.get("yes_sub_title", ""),
        "no_sub_title": m.get("no_sub_title", ""),
        "last_price": market_last_price_cents(m),
        "yes_bid": parse_price_cents(m.get("yes_bid_dollars")) if m.get("yes_bid_dollars") else m.get("yes_bid"),
        "yes_ask": parse_price_cents(m.get("yes_ask_dollars")) if m.get("yes_ask_dollars") else m.get("yes_ask"),
        "no_bid": parse_price_cents(m.get("no_bid_dollars")) if m.get("no_bid_dollars") else m.get("no_bid"),
        "no_ask": parse_price_cents(m.get("no_ask_dollars")) if m.get("no_ask_dollars") else m.get("no_ask"),
        "volume": parse_volume(m.get("volume_fp")) if m.get("volume_fp") else m.get("volume"),
        "volume_24h": market_volume_24h(m),
        "open_time": m.get("open_time"),
        "close_time": m.get("close_time"),
        "expiration_time": m.get("expiration_time"),
        "status": m.get("status"),
        "result": m.get("result", ""),
        "category": market_category(m),
    }


# Kalshi's canonical user-facing category list (matches their site navigation).
# Used by /kalshi/categories and /kalshi/markets-by-category.
KALSHI_CATEGORIES = [
    "Trending", "Elections", "Politics", "Sports", "Culture",
    "Crypto", "Commodities", "Climate", "Economics",
    "Companies", "Financials", "Tech & Science",
]


# Fallback ticker-prefix → category mapping for markets that don't populate the
# `category` field cleanly. Order matters: most specific prefix first.
TICKER_PREFIX_CATEGORY = [
    ("KXFED",        "Economics"),
    ("KXCPI",        "Economics"),
    ("KXGDP",        "Economics"),
    ("KXUNEMP",      "Economics"),
    ("KXINFL",       "Economics"),
    ("KXJOBS",       "Economics"),
    ("KXBTC",        "Crypto"),
    ("KXETH",        "Crypto"),
    ("KXSOL",        "Crypto"),
    ("KXCRYPTO",     "Crypto"),
    ("KXNBA",        "Sports"),
    ("KXMLB",        "Sports"),
    ("KXNFL",        "Sports"),
    ("KXNHL",        "Sports"),
    ("KXEPL",        "Sports"),
    ("KXLALIGA",     "Sports"),
    ("KXSERIE",      "Sports"),
    ("KXATP",        "Sports"),
    ("KXWTA",        "Sports"),
    ("KXMLS",        "Sports"),
    ("KXPGA",        "Sports"),
    ("KXUFC",        "Sports"),
    ("KXPRES",       "Politics"),
    ("KXSENATE",     "Politics"),
    ("KXHOUSE",      "Politics"),
    ("KXAPPROVAL",   "Politics"),
    ("KXELECTION",   "Elections"),
    ("KXVOTE",       "Elections"),
    ("KXHURRICANE",  "Climate"),
    ("KXTEMP",       "Climate"),
    ("KXSNOW",       "Climate"),
    ("KXRAIN",       "Climate"),
    ("KXOSCAR",      "Culture"),
    ("KXGRAMMY",     "Culture"),
    ("KXEMMY",       "Culture"),
    ("KXBOX",        "Culture"),
    ("KXAI",         "Tech & Science"),
    ("KXSPACE",      "Tech & Science"),
    ("KXSPACEX",     "Tech & Science"),
    ("KXSCIENCE",    "Tech & Science"),
    ("KXIPO",        "Companies"),
    ("KXACQ",        "Companies"),
    ("KXSTOCK",      "Financials"),
    ("KXBOND",       "Financials"),
    ("KXVIX",        "Financials"),
    ("KXOIL",        "Commodities"),
    ("KXGAS",        "Commodities"),
    ("KXGOLD",       "Commodities"),
    ("KXSILVER",     "Commodities"),
    ("KXCORN",       "Commodities"),
    ("KXWHEAT",      "Commodities"),
]


def market_category(m):
    """Best-effort category resolution: Kalshi's own field first, then ticker
    prefix inference if that's empty."""
    cat = (m.get("category") or "").strip()
    if cat:
        return cat
    ticker = (m.get("ticker") or "").upper()
    for prefix, label in TICKER_PREFIX_CATEGORY:
        if ticker.startswith(prefix):
            return label
    return ""


# Alias map: user-friendly term -> list of substrings to match against Kalshi market fields.
# Lets users search "bitcoin" and find markets that Kalshi titles "BTC". Keep entries lowercase.
SEARCH_ALIASES = {
    "bitcoin": ["bitcoin", "btc"],
    "btc": ["bitcoin", "btc"],
    "ethereum": ["ethereum", "eth"],
    "eth": ["ethereum", "eth"],
    "crypto": ["bitcoin", "btc", "ethereum", "eth", "crypto"],
    "fed": ["fed", "federal reserve", "fomc", "rate decision"],
    "rates": ["fed", "fomc", "rate", "interest rate"],
    "inflation": ["inflation", "cpi", "consumer price"],
    "gdp": ["gdp", "gross domestic"],
    "election": ["election", "vote", "ballot", "primary"],
    "presidential": ["president", "presidential", "approval", "election"],
    "trump": ["trump", "approval"],
    "hurricane": ["hurricane", "tropical storm", "named storm"],
    "weather": ["weather", "temperature", "hurricane", "storm", "snow"],
    "super bowl": ["super bowl", "nfl championship", "lombardi"],
    "world series": ["world series", "mlb championship"],
    "stanley cup": ["stanley cup", "nhl championship"],
    "nba championship": ["nba championship", "finals mvp"],
    "world cup": ["world cup", "fifa"],
    "oscar": ["oscar", "academy award", "best picture", "best actor"],
    "grammy": ["grammy", "best album", "record of the year"],
    "ai": ["ai", "artificial intelligence", "openai", "anthropic", "llm"],
    "space": ["space", "spacex", "rocket launch", "starlink"],
}


def expand_query(q):
    """Expand a user query through the alias map. Returns a list of lowercase
    substrings to match against Kalshi market fields. Falls back to the raw
    query (and its individual words) when no alias matches."""
    if not q or not q.strip():
        return []
    q_lower = q.strip().lower()
    terms = [q_lower]
    if q_lower in SEARCH_ALIASES:
        terms = list(SEARCH_ALIASES[q_lower])
    else:
        for word in q_lower.split():
            if word in SEARCH_ALIASES:
                terms.extend(SEARCH_ALIASES[word])
    # Dedupe while preserving order
    seen = set()
    out = []
    for t in terms:
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out


def has_activity(m):
    """A market is included if it's not an auto-generated parlay shell. The earlier
    'require last_price or volume_24h > 0' rule wrongly excluded real binary markets
    that just haven't traded yet (fresh markets, longer-dated, quieter contracts).
    Sorting by volume at the endpoint level already pushes the most-active to the top."""
    if not isinstance(m, dict):
        return False
    if is_parlay(m):
        return False
    return True


def fetch_active_markets(target_count=400, max_pages=5):
    """Fetch open Kalshi markets across multiple pages until we have target_count
    markets with actual trading activity (or hit max_pages). Kalshi's default
    /markets ordering returns newly-created empty multi-option shells first;
    real markets are on later pages. Pagination is via the response's cursor field."""
    active = []
    cursor = ""
    for _ in range(max_pages):
        url = KALSHI_API_BASE + "/markets?status=open&limit=1000"
        if cursor:
            url += "&cursor=" + urllib.parse.quote(cursor)
        data = fetch_url(url)
        if data is None:
            break
        page_markets = data.get("markets", [])
        if not page_markets:
            break
        for m in page_markets:
            if has_activity(m):
                active.append(m)
        if len(active) >= target_count:
            break
        cursor = data.get("cursor", "")
        if not cursor:
            break
    return active


@app.get("/kalshi/search")
async def kalshi_search(q: str = "", limit: int = 50):
    """Search active Kalshi markets by substring match on content fields.
    Uses paginated fetch (fetch_active_markets) to look past Kalshi's many
    newly-created empty shells. Search only looks at content fields — not
    tickers, which are random hex hashes that produce false matches."""
    markets = fetch_active_markets()
    if not markets:
        raise HTTPException(status_code=502, detail="Kalshi search failed or no active markets")

    if q and q.strip():
        terms = expand_query(q)
        filtered = []
        for m in markets:
            haystack = " ".join([
                str(m.get("title") or ""),
                str(m.get("subtitle") or ""),
                str(m.get("yes_sub_title") or ""),
                str(m.get("no_sub_title") or ""),
                str(m.get("category") or ""),
            ]).lower()
            if any(t in haystack for t in terms):
                filtered.append(m)
        markets = filtered

    slimmed = [slim_market(m) for m in markets[:limit]]
    slimmed = [s for s in slimmed if s is not None]
    return {"results": slimmed, "count": len(slimmed), "query": q,
            "expanded": expand_query(q) if q else [], "pool_size": "paginated"}


@app.get("/kalshi/featured")
async def kalshi_featured(per_category: int = 2, limit: int = 12):
    """Return a diverse set of featured markets — top N per category by 24h volume.
    Avoids the all-sports-dominate problem of sorting flat by volume. Categories
    themselves are ordered by their total 24h volume so the most-active sector
    surfaces first, but with breathing room for politics/Fed/crypto/weather/etc.
    backward-compatible: still accepts &limit= which caps the total returned."""
    markets = fetch_active_markets()
    if not markets:
        raise HTTPException(status_code=502, detail="Kalshi fetch failed or no active markets")

    def vol_key(m):
        v = m.get("volume_24h", 0)
        try:
            return -int(v) if v else 0
        except Exception:
            return 0

    # Group by category
    by_cat = {}
    for m in markets:
        cat = (m.get("category") or "Other").strip() or "Other"
        by_cat.setdefault(cat, []).append(m)

    # Compute total volume per category for ordering
    cat_total = {}
    for cat, cms in by_cat.items():
        total = 0
        for m in cms:
            try:
                total += int(m.get("volume_24h", 0) or 0)
            except Exception:
                pass
        cat_total[cat] = total

    ordered_cats = sorted(by_cat.keys(), key=lambda c: -cat_total.get(c, 0))

    featured = []
    for cat in ordered_cats:
        cms = by_cat[cat]
        cms.sort(key=vol_key)
        # Skip ugly multi-option mess at the top of categories
        clean_cms = [m for m in cms if (m.get("subtitle") or m.get("title"))]
        featured.extend(clean_cms[:per_category])

    featured = featured[:limit]
    slimmed = [slim_market(m) for m in featured]
    slimmed = [s for s in slimmed if s is not None]
    return {"results": slimmed, "count": len(slimmed), "per_category": per_category}


@app.get("/kalshi/categories")
async def kalshi_categories():
    """Return Kalshi's canonical category list for frontend navigation tiles."""
    return {"categories": KALSHI_CATEGORIES}


@app.get("/kalshi/markets-by-category")
async def kalshi_markets_by_category(cat: str, limit: int = 30):
    """Return active binary markets in a given Kalshi category, sorted by 24h
    volume desc. Special-cases 'Trending' to mean all categories combined,
    sorted by volume. Parlay markets are filtered out upstream by has_activity."""
    cat_input = (cat or "").strip()
    if not cat_input:
        raise HTTPException(status_code=400, detail="Missing category")
    markets = fetch_active_markets(target_count=600, max_pages=6)
    if not markets:
        raise HTTPException(status_code=502, detail="Kalshi fetch failed or no active markets")

    def vol_key(m):
        return -(market_volume_24h(m) or 0)

    cat_lower = cat_input.lower()

    if cat_lower == "trending":
        # All active markets, sorted by volume desc
        candidates = sorted(markets, key=vol_key)
    else:
        # Match against resolved category (Kalshi's category field, with ticker-prefix fallback)
        candidates = []
        for m in markets:
            m_cat = (market_category(m) or "").strip().lower()
            if m_cat == cat_lower:
                candidates.append(m)
        candidates.sort(key=vol_key)

    slimmed = []
    for m in candidates:
        s = slim_market(m)
        if s is not None:
            slimmed.append(s)
        if len(slimmed) >= limit:
            break
    return {"results": slimmed, "count": len(slimmed), "category": cat_input}


@app.get("/kalshi/market/{ticker}")
async def kalshi_market(ticker: str):
    """Fetch a single Kalshi market's current state by ticker."""
    url = KALSHI_API_BASE + "/markets/" + urllib.parse.quote(ticker, safe="")
    data = fetch_url(url)
    if data is None or "market" not in data:
        raise HTTPException(status_code=404, detail="Market not found on Kalshi")
    slimmed = slim_market(data["market"])
    if slimmed is None:
        raise HTTPException(status_code=404, detail="Market not found on Kalshi")
    return slimmed


@app.get("/kalshi/event/{event_ticker}")
async def kalshi_event(event_ticker: str):
    """Fetch a Kalshi event and its markets by event ticker."""
    url = KALSHI_API_BASE + "/events/" + urllib.parse.quote(event_ticker, safe="")
    data = fetch_url(url)
    if data is None:
        raise HTTPException(status_code=404, detail="Event not found on Kalshi")
    event = data.get("event", {})
    markets = data.get("markets", [])
    slimmed_markets = [slim_market(m) for m in markets]
    slimmed_markets = [s for s in slimmed_markets if s is not None]
    return {"event": event, "markets": slimmed_markets}


@app.get("/kalshi/debug")
async def kalshi_debug(q: str = ""):
    """Returns raw Kalshi search response so we can inspect field shapes."""
    url = KALSHI_API_BASE + "/markets?status=open&limit=10"
    data = fetch_url(url)
    if data is None:
        raise HTTPException(status_code=502, detail="Kalshi fetch failed")
    return data

# ── Snapshot + diff (hourly cron) ──────────────────────────────────────────────

def build_alert_snapshot(meta_json):
    """Fetch current Kalshi state for a watched market and return a
    snapshot dict for diffing. Returns None if meta is bad or fetch fails."""
    if not meta_json:
        return None
    try:
        meta = json_lib.loads(meta_json)
    except Exception:
        return None

    platform = meta.get("platform", "kalshi")
    ticker = meta.get("ticker") or meta.get("kalshiTicker")
    if not ticker or platform != "kalshi":
        return None

    url = KALSHI_API_BASE + "/markets/" + urllib.parse.quote(str(ticker), safe="")
    data = fetch_url(url)
    if data is None or "market" not in data:
        return None
    m = data["market"]

    return {
        "platform": "kalshi",
        "ticker": ticker,
        "last_price": m.get("last_price"),
        "yes_bid": m.get("yes_bid"),
        "yes_ask": m.get("yes_ask"),
        "volume_24h": m.get("volume_24h"),
        "status": (m.get("status") or "").lower(),
        "result": (m.get("result") or "").lower(),
        "close_time": m.get("close_time"),
        # Time-to-resolution alert dedupe flags — carried forward each run
        "alerted_24h": False,
        "alerted_1h": False,
    }


def parse_close_time(close_time_str):
    """Parse Kalshi close_time string to a timezone-aware datetime."""
    if not close_time_str:
        return None
    try:
        s = close_time_str
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except Exception:
        return None


def diff_snapshots(old, new, threshold_pct):
    """Compare two Kalshi snapshots. Returns list of short alert messages.
    First-run (old is None) returns [] — never alert on the first capture.
    Price-move alert fires when |delta| / old_price * 100 >= threshold_pct."""
    if old is None or new is None:
        return []
    alerts = []

    # Resolution — terminal event, supersedes other alerts
    new_result = new.get("result", "")
    old_result = (old.get("result") or "")
    if new_result in ("yes", "no") and new_result != old_result:
        return ["Resolved " + new_result.upper()]

    # Status transition (open → closed/settled/finalized)
    old_status = old.get("status", "")
    new_status = new.get("status", "")
    closed_states = ("closed", "settled", "finalized", "determined")
    if old_status == "open" and new_status in closed_states:
        alerts.append("Market closed (pending resolution)")

    # Price move (Kalshi prices in cents, 1-99)
    old_price = old.get("last_price")
    new_price = new.get("last_price")
    if (isinstance(old_price, (int, float)) and isinstance(new_price, (int, float))
            and old_price > 0 and old_price != new_price):
        delta = new_price - old_price
        pct = (delta / old_price) * 100.0
        if abs(pct) >= float(threshold_pct):
            arrow = "↑" if delta > 0 else "↓"
            sign = "+" if delta > 0 else ""
            alerts.append("Price " + arrow + " " + str(old_price) + "¢ → "
                          + str(new_price) + "¢ (" + sign + str(round(pct, 1)) + "%)")

    return alerts


def time_to_resolution_alerts(old, new):
    """Return 24h / 1h time-to-resolution alerts based on close_time.
    Mutates `new` to set alerted_24h/alerted_1h flags so we don't repeat."""
    alerts = []
    close_dt = parse_close_time(new.get("close_time"))
    if close_dt is None:
        return alerts

    now = datetime.now(close_dt.tzinfo or timezone.utc)
    hours_left = (close_dt - now).total_seconds() / 3600.0

    old_24h = bool((old or {}).get("alerted_24h"))
    old_1h = bool((old or {}).get("alerted_1h"))

    # 24-hour warning
    if 0 < hours_left <= 24 and not old_24h:
        alerts.append("Resolves in less than 24 hours")
        new["alerted_24h"] = True
    else:
        new["alerted_24h"] = old_24h

    # 1-hour warning
    if 0 < hours_left <= 1 and not old_1h:
        alerts.append("Resolves in less than 1 hour")
        new["alerted_1h"] = True
    else:
        new["alerted_1h"] = old_1h

    return alerts


def check_all_watched_markets():
    """Hourly job: iterate active watchlist, fetch Kalshi, diff, write notifications."""
    print("[cron] Starting hourly watchlist check at " + datetime.now().isoformat())
    checked = 0
    alerted = 0
    skipped = 0
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("""SELECT id, user_id, name, location FROM sw_watchlist
                         WHERE status = 'active'
                           AND is_resolved = FALSE
                           AND location IS NOT NULL
                           AND location != ''""")
            rows = c.fetchall()

        for row in rows:
            watchlist_id, user_id, name, location = row

            # Per-market threshold from meta, default 10%
            threshold_pct = 10
            try:
                meta = json_lib.loads(location)
                t = meta.get("threshold")
                if isinstance(t, (int, float)) and t > 0:
                    threshold_pct = float(t)
            except Exception:
                pass

            new_snap = build_alert_snapshot(location)
            if new_snap is None:
                skipped += 1
                continue
            checked += 1

            # Read prior snapshot
            with get_db() as conn:
                c = conn.cursor()
                c.execute("SELECT snapshot_json FROM sw_snapshots WHERE watchlist_id = %s",
                          (watchlist_id,))
                prior = c.fetchone()
            old_snap = None
            if prior and prior[0]:
                try:
                    old_snap = json_lib.loads(prior[0])
                except Exception:
                    old_snap = None

            # Build alert list
            alerts = diff_snapshots(old_snap, new_snap, threshold_pct)
            alerts.extend(time_to_resolution_alerts(old_snap, new_snap))

            # Write alerts + mark resolved if applicable
            if alerts:
                resolved_outcome = None
                first = alerts[0]
                if first.startswith("Resolved YES"):
                    resolved_outcome = "YES"
                elif first.startswith("Resolved NO"):
                    resolved_outcome = "NO"

                with get_db() as conn:
                    c = conn.cursor()
                    for msg in alerts:
                        c.execute("""INSERT INTO sw_notifications
                                     (user_id, watchlist_id, message)
                                     VALUES (%s, %s, %s)""",
                                  (user_id, watchlist_id, msg))
                    if resolved_outcome:
                        c.execute("""UPDATE sw_watchlist
                                     SET is_resolved = TRUE, resolution_outcome = %s
                                     WHERE id = %s""",
                                  (resolved_outcome, watchlist_id))
                    conn.commit()
                alerted += 1

            # Always upsert the new snapshot
            with get_db() as conn:
                c = conn.cursor()
                c.execute("""INSERT INTO sw_snapshots (watchlist_id, snapshot_json, captured_at)
                             VALUES (%s, %s, CURRENT_TIMESTAMP)
                             ON CONFLICT (watchlist_id) DO UPDATE
                             SET snapshot_json = EXCLUDED.snapshot_json,
                                 captured_at = CURRENT_TIMESTAMP""",
                          (watchlist_id, json_lib.dumps(new_snap)))
                conn.commit()

        print("[cron] Done. Checked " + str(checked)
              + " markets, " + str(alerted) + " with new alerts, "
              + str(skipped) + " skipped (no ticker or Kalshi fetch failed)")
    except Exception as e:
        print("[cron] Fatal error: " + str(e))


@app.post("/admin/run-cron")
async def run_cron_manually(secret: str):
    """Manually trigger the hourly watchlist check. Useful for testing
    without waiting for :00. Pass ?secret=... matching ADMIN_SECRET."""
    if secret != os.environ.get("ADMIN_SECRET", "stakes-watch-cron-2026"):
        raise HTTPException(status_code=403, detail="Forbidden")
    check_all_watched_markets()
    return {"status": "completed", "ran_at": datetime.now().isoformat()}


@app.get("/admin/signup-stats")
async def admin_signup_stats(x_admin_token: str = Header(None, alias="X-Admin-Token")):
    """Read-only signup metrics for the 3Brains scoreboard.
    Requires X-Admin-Token header matching ADMIN_STATS_TOKEN env var."""
    expected = os.environ.get("ADMIN_STATS_TOKEN")
    if not expected or x_admin_token != expected:
        raise HTTPException(status_code=403, detail="Forbidden")
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM sw_users")
        total_users = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM sw_users WHERE created_at >= NOW() - INTERVAL '24 hours'")
        signups_24h = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM sw_users WHERE created_at >= NOW() - INTERVAL '7 days'")
        signups_7d = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM sw_users WHERE created_at >= NOW() - INTERVAL '30 days'")
        signups_30d = c.fetchone()[0]
        c.execute("SELECT MAX(created_at) FROM sw_users")
        latest_row = c.fetchone()
        latest = latest_row[0].isoformat() if latest_row and latest_row[0] else None
        return {
            "total_users": total_users,
            "signups_24h": signups_24h,
            "signups_7d": signups_7d,
            "signups_30d": signups_30d,
            "latest_signup_at": latest
        }


# Module-level scheduler — kept in scope so it isn't garbage-collected
_sw_scheduler = None

# ── Startup ────────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup_event():
    init_db()
    print("Stakes Watch DB initialized")

    # Hourly watchlist check at minute 0 of every hour, 24/7
    global _sw_scheduler
    _sw_scheduler = BackgroundScheduler(timezone="UTC")
    _sw_scheduler.add_job(
        check_all_watched_markets,
        CronTrigger(minute=0),
        id="sw_hourly_check",
        replace_existing=True,
    )
    _sw_scheduler.start()
    print("Stakes Watch cron scheduled: hourly at :00 UTC")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
