"""ATLAS OSINT PRO v0.2 — passive, source-linked investigation gateway.
Developer: Suat DOĞU. Public data only. No intrusive scanning.
Run: uvicorn main:app --host 0.0.0.0 --port 10000
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import httpx
from fastapi import FastAPI, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

VERSION = "0.2.0"
ROOT = Path(__file__).resolve().parent
APP_TOKEN = os.environ.get("OSINT_APP_TOKEN", "").strip()
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()
LOG = logging.getLogger("atlas-osint")
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="ATLAS OSINT PRO", version=VERSION, docs_url=None, redoc_url=None)

# Short-lived, in-memory cache: no subject data written to disk by backend.
_cache: dict[tuple[str, str], tuple[float, list[dict]]] = {}
_source_health: dict[str, dict] = {}
_rate_windows: dict[str, list[float]] = {}
RATE_LIMIT = 18  # per IP / minute, in addition to APP_TOKEN

CACHE_TTL = 240
MAX_CACHE_ENTRIES = 128
REQUEST_TIMEOUT = httpx.Timeout(14.0, connect=5.0)

KINDS = {
    "domain": "Alan adı / DNS / RDAP / CT",
    "ip": "IP / kayıt bilgileri",
    "github_user": "GitHub açık kullanıcı profili",
    "github_repos": "GitHub açık depolar",
    "bluesky": "Bluesky açık gönderiler",
    "news": "GDELT haber araması",
    "cve": "NVD güvenlik açığı",
    "bitcoin": "Bitcoin açık zincir adresi",
    "wayback": "Wayback Machine / web arşivi",
    "openalex": "OpenAlex / akademik araştırma",
    "kev": "CISA KEV / istismar edildiği bilinen güvenlik açıkları",
}

class SearchRequest(BaseModel):
    kind: str
    query: str = Field(min_length=1, max_length=160)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def require_token(supplied: str | None):
    if not APP_TOKEN:
        raise HTTPException(status_code=503, detail="OSINT_APP_TOKEN tanımlanmamış; sorgular güvenlik amacıyla kapalı.")
    if (supplied or "") != APP_TOKEN:
        raise HTTPException(status_code=401, detail="Uygulama anahtarı hatalı.")


def validate(kind: str, raw: str) -> str:
    q = raw.strip()
    if kind not in KINDS:
        raise ValueError("Bilinmeyen sorgu kategorisi")
    if not q or len(q) > 160 or any(ord(c) < 32 for c in q):
        raise ValueError("Sorgu 1-160 karakter olmalıdır")
    if kind == "domain":
        try:
            q = q.lower().rstrip(".").encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("Alan adı geçersiz") from exc
        if len(q) > 253 or not re.fullmatch(r"(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", q):
            raise ValueError("example.com biçiminde geçerli bir alan adı girin")
        if q.endswith((".local", ".internal", ".test", ".invalid")):
            raise ValueError("Yalnız kamusal alan adlarını araştırın")
    elif kind == "wayback":
        q = validate("domain", q)
    elif kind == "ip":
        try:
            ip = ipaddress.ip_address(q)
        except ValueError as exc:
            raise ValueError("Geçerli IPv4 veya IPv6 adresi girin") from exc
        if not ip.is_global:
            raise ValueError("Yalnız genel internete açık IP adresleri sorgulanabilir")
        q = str(ip)
    elif kind == "github_user":
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", q):
            raise ValueError("Geçerli GitHub kullanıcı adı girin")
    elif kind == "cve":
        q = q.upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", q):
            raise ValueError("CVE-2024-12345 biçiminde girin")
    elif kind == "bitcoin":
        if not re.fullmatch(r"(?:bc1[ac-hj-np-z02-9]{11,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})", q, re.I):
            raise ValueError("Geçerli biçimde bir Bitcoin ana ağ adresi girin")
    elif kind in {"github_repos", "news", "bluesky", "openalex", "kev"} and len(q) < 2:
        raise ValueError("En az iki karakter girin")
    return q


def check_rate_limit(peer: str):
    t = time.monotonic()
    # Old buckets are evicted to avoid unbounded memory usage.
    if len(_rate_windows) > 1024:
        _rate_windows.clear()
    recent = [x for x in _rate_windows.get(peer, []) if t - x < 60]
    if len(recent) >= RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Dakikalık sorgu sınırına ulaşıldı.")
    recent.append(t)
    _rate_windows[peer] = recent


def item(source, title, description, url="", fields=None):
    return {
        "source": source,
        "title": str(title)[:180],
        "description": str(description or "")[:1200],
        "url": url,
        "fields": fields or {},
        "checked_at": now(),
        "status": "ok", "evidence_level": "source_record",
    }


async def get_json(client: httpx.AsyncClient, url: str, params=None, headers=None, max_bytes=3_000_000):
    # Outbound URLs are static provider endpoints; never accept a user-supplied URL.
    resp = await client.get(url, params=params, headers=headers)
    resp.raise_for_status()
    if len(resp.content) > max_bytes:
        raise ValueError("Kaynak yanıtı izin verilen boyutu aşıyor")
    return resp.json()


async def domain_dns(client, domain):
    records = []
    succeeded = 0
    for kind in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            data = await get_json(client, "https://dns.google/resolve", {"name": domain, "type": kind})
            answers = [x.get("data", "") for x in data.get("Answer", [])][:15]
            records.append(item("Google Public DNS", kind + " kayıtları", ", ".join(answers) if answers else "Kayıt bulunamadı", "https://dns.google/", {"record_type": kind, "answers": answers}))
            succeeded += 1
        except Exception as exc:
            failure = item("Google Public DNS", kind + " · kaynak hatası", safe_error(exc))
            failure["status"] = "error"
            failure["evidence_level"] = "error"
            records.append(failure)
    if succeeded == 0:
        raise ValueError("DNS kaynağına erişilemedi (beş kayıt türü de başarısız).")
    return records


async def domain_rdap(client, domain):
    data = await get_json(client, "https://rdap.org/domain/" + domain)
    events = [{"event": x.get("eventAction"), "date": x.get("eventDate")} for x in data.get("events", [])][:10]
    return [item("RDAP", "Alan adı kayıt özeti", data.get("ldhName", domain), "https://client.rdap.org/?object=" + quote(domain) + "&type=domain", {
        "status": data.get("status", []), "nameservers": [x.get("ldhName") for x in data.get("nameservers", [])][:20], "events": events,
        "handle": data.get("handle", ""),
    })]


async def domain_ct(client, domain):
    data = await get_json(client, "https://crt.sh/", {"q": "%." + domain, "output": "json"}, max_bytes=8_000_000)
    if not isinstance(data, list):
        raise ValueError("Sertifika kaynağı beklenmeyen veri döndürdü")
    names = set()
    for cert in data[:1500]:
        for name in cert.get("name_value", "").splitlines():
            name = name.strip().lower().removeprefix("*.")
            if name == domain or name.endswith("." + domain):
                names.add(name)
    values = sorted(names)[:100]
    return [item("crt.sh / Certificate Transparency", f"Sertifikada görünen alan adları · {len(names)}+", ", ".join(values[:25]) or "Kayıt bulunamadı", "https://crt.sh/?q=%25." + quote(domain), {"names": values, "truncated": len(names) > 100})]


async def lookup_ip(client, q):
    data = await get_json(client, "https://rdap.org/ip/" + quote(q))
    names = [e.get("name") for e in data.get("entities", []) if e.get("name")][:8]
    return [item("RDAP IP", "IP tahsis bilgisi", data.get("name", q), "https://client.rdap.org/?object=" + quote(q) + "&type=ip", {
        "handle": data.get("handle"), "startAddress": data.get("startAddress"), "endAddress": data.get("endAddress"),
        "country": data.get("country"), "entities": names, "status": data.get("status", [])
    })]


def gh_headers():
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if GITHUB_TOKEN:
        h["Authorization"] = "Bearer " + GITHUB_TOKEN
    return h


async def lookup_github_user(client, q):
    data = await get_json(client, "https://api.github.com/users/" + quote(q), headers=gh_headers())
    return [item("GitHub API", "Açık geliştirici profili", data.get("bio", "") or data.get("name", "") or q, data.get("html_url", ""), {
        "login": data.get("login"), "name": data.get("name"), "public_repos": data.get("public_repos"),
        "followers": data.get("followers"), "created_at": data.get("created_at"), "updated_at": data.get("updated_at")
    })]


async def lookup_github_repos(client, q):
    data = await get_json(client, "https://api.github.com/search/repositories", {"q": q, "sort": "updated", "per_page": 12}, headers=gh_headers())
    return [item("GitHub API", x.get("full_name", "Depo"), x.get("description") or "Açıklama yok", x.get("html_url", ""), {
        "language": x.get("language"), "stars": x.get("stargazers_count"), "updated_at": x.get("updated_at")
    }) for x in data.get("items", [])[:12]]


async def lookup_bluesky(client, q):
    params = {"q": q, "limit": 15, "sort": "latest"}
    try:
        data = await get_json(client, "https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts", params)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code not in (403, 429):
            raise
        # Second official AppView host; do not bypass sign-in / access controls.
        data = await get_json(client, "https://api.bsky.app/xrpc/app.bsky.feed.searchPosts", params)
    out = []
    for p in data.get("posts", [])[:15]:
        handle = p.get("author", {}).get("handle", "")
        rkey = (p.get("uri") or "").rsplit("/", 1)[-1]
        url = f"https://bsky.app/profile/{quote(handle, safe='.')}/post/{quote(rkey)}" if handle and rkey else ""
        out.append(item("Bluesky AppView", "@" + handle, p.get("record", {}).get("text", ""), url, {
            "created_at": p.get("record", {}).get("createdAt"), "likes": p.get("likeCount"), "reposts": p.get("repostCount")
        }))
    return out


async def lookup_news(client, q):
    data = await get_json(client, "https://api.gdeltproject.org/api/v2/doc/doc", {
        "query": q, "mode": "artlist", "format": "json", "maxrecords": 15, "timespan": "7d", "sort": "datedesc"
    })
    return [item("GDELT DOC 2.0", x.get("title", "Haber"), x.get("domain", "") + " · " + x.get("seendate", ""), x.get("url", ""), {
        "language": x.get("language", ""), "seendate": x.get("seendate", ""), "sourcecountry": x.get("sourcecountry", "")
    }) for x in data.get("articles", [])[:15]]


async def lookup_cve(client, q):
    data = await get_json(client, "https://services.nvd.nist.gov/rest/json/cves/2.0", {"cveId": q})
    result = []
    for v in data.get("vulnerabilities", [])[:1]:
        cve = v.get("cve", {})
        descs = cve.get("descriptions", [])
        desc = next((x.get("value", "") for x in descs if x.get("lang") == "en"), "Açıklama yok")
        result.append(item("NIST NVD", q, desc, "https://nvd.nist.gov/vuln/detail/" + q, {
            "published": cve.get("published"), "lastModified": cve.get("lastModified"), "vulnStatus": cve.get("vulnStatus")
        }))
    return result


async def lookup_bitcoin(client, q):
    data = await get_json(client, "https://mempool.space/api/address/" + quote(q))
    chain = data.get("chain_stats", {})
    pool = data.get("mempool_stats", {})
    return [item("mempool.space", "Bitcoin adres özeti", "Açık Bitcoin zincirindeki istatistikler (özel mülkiyet/kimlik çıkarımı değildir)", "https://mempool.space/address/" + quote(q), {
        "confirmed_txs": chain.get("tx_count", 0), "unconfirmed_txs": pool.get("tx_count", 0),
        "confirmed_balance_sats": chain.get("funded_txo_sum", 0) - chain.get("spent_txo_sum", 0),
        "mempool_delta_sats": pool.get("funded_txo_sum", 0) - pool.get("spent_txo_sum", 0)
    })]




async def lookup_wayback(client, domain):
    data = await get_json(client, "https://archive.org/wayback/available", {"url": "https://" + domain})
    capture = data.get("archived_snapshots", {}).get("closest", {})
    if not capture or not capture.get("available"):
        return []
    url = capture.get("url", "")
    if not isinstance(url, str) or not url.startswith("https://web.archive.org/"):
        url = "https://web.archive.org/web/*/" + quote(domain)
    return [item("Internet Archive Wayback", "Web arşivindeki en yakın görüntü", domain,
                 url, {"timestamp": capture.get("timestamp"), "available": True})]


async def lookup_openalex(client, q):
    data = await get_json(client, "https://api.openalex.org/works", {"search": q, "per-page": 10})
    return [item("OpenAlex", x.get("display_name", "Yayın"),
                 "Açık akademik yayın kaydı", x.get("doi") or x.get("id") or "",
                 {"publication_year": x.get("publication_year"), "cited_by_count": x.get("cited_by_count"),
                  "type": x.get("type"), "open_access": x.get("open_access", {}).get("is_oa")})
            for x in data.get("results", [])[:10]]


async def kev_feed(client):
    sources = [
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
    ]
    last = None
    for url in sources:
        try:
            return await get_json(client, url, max_bytes=5_000_000)
        except (httpx.HTTPError, ValueError) as exc:
            last = exc
    if last:
        raise last
    raise ValueError("CISA KEV erişilemedi")


async def lookup_kev(client, q):
    data = await kev_feed(client)
    findings = []
    for v in data.get("vulnerabilities", []):
        searchable = " ".join(str(v.get(k, "")) for k in ("cveID", "vendorProject", "product", "vulnerabilityName"))
        if q.casefold() in searchable.casefold():
            cve = v.get("cveID", "")
            findings.append(item("CISA KEV", cve + " · " + str(v.get("vendorProject", "")),
                                 v.get("shortDescription", ""),
                                 "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                                 {"cve": cve, "product": v.get("product"), "dateAdded": v.get("dateAdded"),
                                  "dueDate": v.get("dueDate"),
                                  "knownRansomwareCampaignUse": v.get("knownRansomwareCampaignUse")}))
            if len(findings) >= 20:
                break
    return findings


async def lookup_epss(client, cve):
    data = await get_json(client, "https://api.first.org/data/v1/epss", {"cve": cve})
    rows = data.get("data", [])
    if not rows:
        return []
    x = rows[0]
    return [item("FIRST EPSS", cve + " · istismar olasılığı", "Gelecek 30 gün için model tahmini; gerçekleşmiş saldırı kanıtı değildir.",
                 "https://www.first.org/epss/", {"epss_probability": x.get("epss"),
                 "percentile": x.get("percentile"), "model_date": x.get("date")})]


def safe_error(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return f"Kaynak HTTP {status} yanıtı verdi; kota veya erişim kısıtı olabilir."
    if isinstance(exc, (httpx.TimeoutException, asyncio.TimeoutError)):
        return "Kaynak zaman aşımına uğradı."
    if isinstance(exc, httpx.RequestError):
        return "Kaynağa ağ bağlantısı kurulamadı."
    if isinstance(exc, (ValueError, json.JSONDecodeError)):
        return str(exc)[:160]
    LOG.warning("Adapter error: %s", type(exc).__name__)
    return "Veri kaynağında beklenmeyen hata oluştu."


async def source_job(label: str, coroutine):
    start = time.monotonic()
    try:
        results = await coroutine
        status = "ok" if results else "empty"
        _source_health[label] = {"status": status, "last_attempt": now(),
                                 "last_success": now(), "latency_ms": round((time.monotonic()-start)*1000)}
        return results
    except Exception as exc:
        msg = safe_error(exc)
        _source_health[label] = {"status": "error", "last_attempt": now(),
                                 "last_error": msg, "latency_ms": round((time.monotonic()-start)*1000)}
        error_item = item(label, "Kaynak hatası", msg)
        error_item["status"] = "error"
        error_item["evidence_level"] = "error"
        return [error_item]


def get_tasks(client, kind, q):
    if kind == "domain":
        return [("Google Public DNS", domain_dns(client, q)),
                ("RDAP Domain", domain_rdap(client, q)),
                ("crt.sh", domain_ct(client, q))]
    if kind == "cve":
        return [("NIST NVD", lookup_cve(client, q)),
                ("FIRST EPSS", lookup_epss(client, q)),
                ("CISA KEV", lookup_kev(client, q))]
    mapping = {
        "ip": ("RDAP IP", lookup_ip), "github_user": ("GitHub User", lookup_github_user),
        "github_repos": ("GitHub Search", lookup_github_repos),
        "bluesky": ("Bluesky AppView", lookup_bluesky),
        "news": ("GDELT DOC", lookup_news), "bitcoin": ("mempool.space", lookup_bitcoin),
        "wayback": ("Wayback Machine", lookup_wayback),
        "openalex": ("OpenAlex", lookup_openalex), "kev": ("CISA KEV", lookup_kev),
    }
    name, fn = mapping[kind]
    return [(name, fn(client, q))]


def make_client():
    return httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=True,
                             headers={"User-Agent": "AtlasOSINTPro/0.2 (passive research)"},
                             limits=httpx.Limits(max_connections=10))


async def investigate(kind: str, query: str):
    q = validate(kind, query)
    key = (kind, q.casefold())
    hit = _cache.get(key)
    if hit and hit[0] > time.monotonic():
        return hit[1], True
    async with make_client() as client:
        tasks = [source_job(name, task) for name, task in get_tasks(client, kind, q)]
        response = await asyncio.gather(*tasks)
        out = [row for group in response for row in group]
    # Do not cache failures; the next request must be able to retry.
    if not any(x.get("status") == "error" for x in out):
        if len(_cache) >= MAX_CACHE_ENTRIES:
            _cache.clear()
        _cache[key] = (time.monotonic() + CACHE_TTL, out)
    return out, False


@app.get("/")
async def home():
    return FileResponse(ROOT / "index.html")


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": VERSION, "protected": bool(APP_TOKEN),
            "ready": bool(APP_TOKEN), "sources": len(KINDS), "time_utc": now()}


@app.get("/api/sources")
async def sources(x_osint_key: str | None = Header(default=None)):
    require_token(x_osint_key)
    return {"sources": [{"id": k, "name": v, "type": "REST (on-demand)"} for k, v in KINDS.items()],
            "live": ["mempool.space WebSocket (browser direct)"], "source_health": _source_health}


@app.post("/api/investigate")
async def investigate_rest(payload: SearchRequest, x_osint_key: str | None = Header(default=None), request: Request = None):
    require_token(x_osint_key)
    check_rate_limit(request.client.host if request and request.client else "unknown")
    try:
        items, cached = await investigate(payload.kind, payload.query)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"kind": payload.kind, "query": payload.query.strip(), "results": items, "cached": cached, "checked_at": now()}


@app.get("/api/source-health")
async def source_health(x_osint_key: str | None = Header(default=None)):
    require_token(x_osint_key)
    return {"observations": _source_health, "note": "Son istek gözlemleridir; doğrulanmış kesintisiz canlı sağlık testi değildir."}


@app.websocket("/ws/investigate")
async def investigate_ws(ws: WebSocket):
    await ws.accept()
    try:
        request = await asyncio.wait_for(ws.receive_json(), timeout=12)
        if not APP_TOKEN:
            await ws.send_json({"type": "error", "message": "OSINT_APP_TOKEN ayarlanmamış. Güvenlik için sorgu kapalı."})
            await ws.close(code=1008)
            return
        if request.get("token") != APP_TOKEN:
            await ws.send_json({"type": "error", "message": "Uygulama anahtarı hatalı."})
            await ws.close(code=1008)
            return
        try:
            check_rate_limit(ws.client.host if ws.client else "unknown")
        except HTTPException:
            await ws.send_json({"type": "error", "message": "Sorgu limiti: dakikada en fazla 18 istek."})
            await ws.close(code=1008)
            return
        kind, query = request.get("kind", ""), request.get("query", "")
        q = validate(kind, query)
        await ws.send_json({"type": "started", "at": now(), "kind": kind})
        key = (kind, q.casefold())
        hit = _cache.get(key)
        if hit and hit[0] > time.monotonic():
            results, cached = hit[1], True
            for i, x in enumerate(results):
                await ws.send_json({"type": "result", "item": x, "index": i})
        else:
            cached, results = False, []
            async with make_client() as client:
                tasks = [asyncio.create_task(source_job(name, coro)) for name, coro in get_tasks(client, kind, q)]
                for completed in asyncio.as_completed(tasks):
                    batch = await completed
                    for x in batch:
                        results.append(x)
                        await ws.send_json({"type": "result", "item": x, "index": len(results)-1})
            if not any(x.get("status") == "error" for x in results):
                if len(_cache) >= MAX_CACHE_ENTRIES:
                    _cache.clear()
                _cache[key] = (time.monotonic() + CACHE_TTL, results)
        errors = sum(x.get("status") == "error" for x in results)
        await ws.send_json({"type": "done", "count": len(results)-errors,
                            "errors": errors, "cached": cached, "at": now()})
        await ws.close()
    except (ValueError, TypeError) as exc:
        await ws.send_json({"type": "error", "message": str(exc)[:180]})
        await ws.close(code=1003)
    except (WebSocketDisconnect, RuntimeError):
        return
    except Exception:
        LOG.exception("Unhandled WS request error")
        try:
            await ws.send_json({"type": "error", "message": "Beklenmeyen bağlantı hatası."})
            await ws.close(code=1011)
        except Exception:
            pass
