import os, json, time, datetime as dt
from typing import Iterator, List, Dict, Any, Optional

import requests
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from pymongo import MongoClient, UpdateOne
from dotenv import load_dotenv

ISO_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"
ISO_FMT_NVD = "%Y-%m-%dT%H:%M:%S.%f"  # NVD expects format without Z

def utc_now():
    return dt.datetime.utcnow()

def utc_now_str() -> str:
    """Return current UTC time as ISO string for NVD API"""
    now = dt.datetime.utcnow()
    return now.strftime(ISO_FMT_NVD)

def load_checkpoint(path: str) -> Optional[str]:
    if not path or not os.path.exists(path):
        return None
    try:
        return json.load(open(path))["lastModEndDate"]
    except Exception:
        return None

def save_checkpoint(path: str, when_iso: str):
    if path:
        json.dump({"lastModEndDate": when_iso}, open(path, "w"))

class NVDClient:
    def __init__(self, base_url: str, api_key: Optional[str] = None, sleep_seconds: float = 6.0):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.api_key = api_key
        self.sleep_seconds = sleep_seconds  # NVD recommends ~6s between requests

    @retry(
        reraise=True,
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception_type((requests.RequestException,))
    )
    def _get(self, params: Dict[str, Any]) -> Dict[str, Any]:
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key  # per NVD docs
        resp = self.session.get(self.base_url, params=params, headers=headers, timeout=60)
        # Handle server/limit responses
        if resp.status_code == 429:
            # rate limited: honor Retry-After if present, else sleep
            ra = int(resp.headers.get("Retry-After", self.sleep_seconds))
            time.sleep(max(ra, int(self.sleep_seconds)))
            raise requests.RequestException("Rate-limited; retrying")
        resp.raise_for_status()
        return resp.json()

    def iter_cves(
        self,
        last_mod_start: Optional[str] = None,
        last_mod_end: Optional[str] = None,
        results_per_page: int = 2000
    ) -> Iterator[Dict[str, Any]]:
        start_index = 0
        while True:
            params = {
                "resultsPerPage": results_per_page,
                "startIndex": start_index,
                "noRejected": None,  # exclude REJECTed CVEs
            }
            if last_mod_start and last_mod_end:
                params["lastModStartDate"] = last_mod_start
                params["lastModEndDate"] = last_mod_end

            # Clean None flags for requests
            query = {k: v for k, v in params.items() if v is not None}
            if "noRejected" in params and params["noRejected"] is None:
                query["noRejected"] = ""  # flag-style

            data = self._get(query)
            vulns = data.get("vulnerabilities", [])
            for v in vulns:
                yield v.get("cve", {})

            total = data.get("totalResults", 0)
            rpp = data.get("resultsPerPage", results_per_page)
            start_index = data.get("startIndex", start_index) + rpp

            # polite pacing between requests (NVD best practice)
            time.sleep(self.sleep_seconds)

            if start_index >= total or not vulns:
                break

def pick_english(descs: List[Dict[str, Any]]) -> Optional[str]:
    for d in descs or []:
        if d.get("lang") == "en":
            return d.get("value")
    return None

def flatten_cve(cve: Dict[str, Any]) -> Dict[str, Any]:
    cve_id = cve.get("id")
    published = cve.get("published")
    last_modified = cve.get("lastModified")
    descriptions = cve.get("descriptions", [])
    desc_en = pick_english(descriptions)

    # CVSS v3.1 → v3.0 → v2
    base_score = severity = vector = None
    metrics = cve.get("metrics") or {}
    if isinstance(metrics, dict):
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            arr = metrics.get(key, [])
            if arr and isinstance(arr, list) and len(arr) > 0:
                m = arr[0]  # take first vector set
                if isinstance(m, dict):
                    cvss = m.get("cvssData", {})
                    if isinstance(cvss, dict):
                        base_score = cvss.get("baseScore")
                        vector = cvss.get("vectorString")
                        severity = m.get("baseSeverity") or m.get("severity")
                        break

    # CWE(s)
    cwes = []
    for w in cve.get("weaknesses", []):
        if isinstance(w, dict):
            descriptions = w.get("description", [])
            if isinstance(descriptions, list):
                for d in descriptions:
                    if isinstance(d, dict) and d.get("lang") == "en":
                        val = d.get("value")
                        if val:
                            cwes.append(val)

    # CPE match strings (from configurations)
    cpes = []
    configs = cve.get("configurations", [])
    # Handle both list and dict formats
    nodes = []
    if isinstance(configs, dict):
        nodes = configs.get("nodes", [])
    elif isinstance(configs, list):
        # Newer format: configurations is a list
        for cfg in configs:
            if isinstance(cfg, dict) and "nodes" in cfg:
                nodes.extend(cfg.get("nodes", []))
    
    for node in nodes:
        for m in node.get("cpeMatch", []):
            crit = m.get("criteria")
            if crit:
                cpes.append(crit)

    # References
    refs = []
    for r in cve.get("references", []):
        # Handle different reference formats
        if isinstance(r, dict):
            # Check if url is a list
            url_list = r.get("url", [])
            if isinstance(url_list, list):
                refs.extend(url_list)
            else:
                # Single URL string
                if url_list:
                    refs.append(url_list)
        elif isinstance(r, str):
            # Direct URL string
            refs.append(r)

    doc = {
        "cve_id": cve_id,
        "published": published,
        "last_modified": last_modified,
        "description_en": desc_en,
        "cvss_base_score": base_score,
        "cvss_severity": severity,
        "cvss_vector": vector,
        "cwes": list(sorted(set(cwes))),
        "cpe_criteria": list(sorted(set(cpes))),
        "references": refs,
        "ingested_at": utc_now_str(),
        "raw": cve,  # keep original for completeness
    }
    return doc

def bulk_upsert(mongo_coll, docs: List[Dict[str, Any]]):
    ops = []
    for d in docs:
        if not d.get("cve_id"):
            continue
        ops.append(
            UpdateOne({"cve_id": d["cve_id"]}, {"$set": d}, upsert=True)
        )
    if ops:
        mongo_coll.bulk_write(ops, ordered=False)

def main():
    try:
        load_dotenv()
        base = os.getenv("NVD_API_BASE", "https://services.nvd.nist.gov/rest/json/cves/2.0")
        key = os.getenv("NVD_API_KEY", "")
        mongo_uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
        db_name = os.getenv("MONGODB_DB", "security")
        coll_name = os.getenv("MONGODB_COLLECTION", "nvd_cve_raw")
        checkpoint_file = os.getenv("CHECKPOINT_FILE", ".nvd_checkpoint.json")

        # Test MongoDB connection
        print("[INFO] Connecting to MongoDB...")
        try:
            client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
            client.server_info()  # Will raise exception if can't connect
            print("[OK] MongoDB connection successful")
        except Exception as e:
            print(f"[ERROR] Failed to connect to MongoDB at {mongo_uri}")
            print(f"[ERROR] Make sure MongoDB is running or update MONGODB_URI in .env")
            print(f"[ERROR] Details: {e}")
            return

        coll = client[db_name][coll_name]

        nvd = NVDClient(base_url=base, api_key=key, sleep_seconds=6.0)

        # Decide mode: incremental if checkpoint exists, else initial
        last_end = load_checkpoint(checkpoint_file)
        if last_end:
            last_start = last_end
        else:
            # initial backfill: use a conservative 120-day window ending now
            now = utc_now()
            last_start = (now - dt.timedelta(days=120)).strftime(ISO_FMT_NVD)
        last_end = utc_now_str()

        print(f"[INFO] Fetching CVEs lastModified between {last_start} and {last_end}")

        buf: List[Dict[str, Any]] = []
        count = 0
        for cve in nvd.iter_cves(last_mod_start=last_start, last_mod_end=last_end):
            doc = flatten_cve(cve)
            buf.append(doc)
            count += 1
            if len(buf) >= 1000:
                bulk_upsert(coll, buf)
                print(f"[PROGRESS] Processed {count} CVEs...")
                buf.clear()
        if buf:
            bulk_upsert(coll, buf)

        save_checkpoint(checkpoint_file, last_end)
        print(f"[OK] Ingestion complete. Total CVEs processed: {count}")
    except Exception as e:
        print(f"[ERROR] {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()

