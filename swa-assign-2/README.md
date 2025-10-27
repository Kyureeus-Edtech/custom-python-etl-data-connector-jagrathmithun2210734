# NVD CVE ETL Connector

Python ETL pipeline that extracts CVEs from the NVD API 2.0, flattens the JSON data, and upserts into MongoDB.

## Overview

This connector fetches Common Vulnerabilities and Exposures (CVEs) from the National Vulnerability Database (NVD) API, transforms the data into a flattened MongoDB-friendly schema, and performs incremental syncs using date-range filtering.

## API Documentation

- **Base URL**: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **API Key**: Pass the key in the request header as `apiKey: <KEY>` to increase rate limits from 5 to 50 requests per rolling 30 seconds
- **Request Parameters**:
  - `lastModStartDate` and `lastModEndDate`: Date range filters (max 120-day window)
  - `resultsPerPage`: Number of results per page (max 2,000)
  - `startIndex`: Pagination starting point
  - `noRejected`: Exclude REJECTed CVEs

Reference: [NVD Developer Pages](https://nvd.nist.gov/developers)

## Prerequisites

- Python 3.7+
- MongoDB (local or remote)
- NVD API Key (request at https://nvd.nist.gov/developers/request-an-api-key)

## Setup

1. **Create a virtual environment** (Windows):
```bash
python -m venv .venv
.venv\Scripts\activate
```

Or (Linux/Mac):
```bash
python -m venv .venv
source .venv/bin/activate
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

3. **Configure environment variables**:
Create a `.env` file in the project root with the following variables:

```env
NVD_API_BASE=https://services.nvd.nist.gov/rest/json/cves/2.0
NVD_API_KEY=your_key_here
MONGODB_URI=mongodb://localhost:27017
MONGODB_DB=security
MONGODB_COLLECTION=nvd_cve_raw
CHECKPOINT_FILE=.nvd_checkpoint.json
```

**Important**: `.env` is git-ignored. Never commit your API key.

## Usage

Run the ETL connector:

```bash
python etl_connector.py
```

### How It Works

**Initial Run**:
- Queries CVEs modified in the last 120 days
- Paginates through all results in chunks of 2,000
- Flattens and upserts into MongoDB
- Saves checkpoint timestamp

**Subsequent Runs** (Incremental):
- Loads checkpoint timestamp from `.nvd_checkpoint.json`
- Queries only CVEs modified since the checkpoint
- Updates existing documents and adds new ones
- Saves new checkpoint timestamp

## MongoDB Schema

**Collection**: `nvd_cve_raw`  
**Upsert Key**: `cve_id` (unique CVE identifier)

**Sample Document**:
```json
{
  "cve_id": "CVE-2024-12345",
  "published": "2024-01-15T00:00:00.000Z",
  "last_modified": "2024-01-20T12:30:00.000Z",
  "description_en": "A vulnerability in...",
  "cvss_base_score": 7.5,
  "cvss_severity": "HIGH",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H",
  "cwes": ["CWE-79", "CWE-89"],
  "cpe_criteria": ["cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"],
  "references": ["https://example.com/advisory"],
  "ingested_at": "2024-01-20T14:30:00.000000",
  "raw": { /* full original CVE JSON */ }
}
```

## Operational Notes

### Rate Limits

- **Without API key**: 5 requests per rolling 30 seconds
- **With API key**: 50 requests per rolling 30 seconds
- The connector sleeps 6 seconds between requests (NVD best practice)
- Automatic retry with exponential backoff on rate-limit errors (HTTP 429)

### Incremental Sync Pattern

NVD recommends:
- Use date range filters (`lastModStartDate` / `lastModEndDate`) for incremental updates
- Maximum date range: 120 days
- Sleep approximately 6 seconds between API calls
- Run incremental syncs no more than once every 2 hours

### Checkpoint File

The `.nvd_checkpoint.json` file stores the timestamp of the last successful sync:
```json
{
  "lastModEndDate": "2024-01-20T14:30:00.000000"
}
```

To restart from a fresh state, delete this file.

### Re-running Initial Backfill

To change the date window for initial backfill, modify the `main()` function in `etl_connector.py`:
```python
# Change from 120 days to a different number
last_start = (now - dt.timedelta(days=30)).strftime(ISO_FMT)
```

## Extracted Fields

- **ID & Dates**: CVE ID, published date, last modified date
- **Description**: English description text
- **CVSS Scores**: Base score, severity level, vector string (prefers v3.1 → v3.0 → v2)
- **CWEs**: Common Weakness Enumeration identifiers
- **CPEs**: Common Platform Enumeration match criteria
- **References**: External URLs and advisories
- **Metadata**: Ingestion timestamp for audit trails

## Error Handling

- **HTTP 429 (Rate Limit)**: Automatic retry with exponential backoff, honors `Retry-After` header
- **Network Errors**: Tenacity library provides robust retry logic (5 attempts)
- **Missing Data**: Gracefully handles missing CVSS, CWE, or CPE data
- **Invalid Checkpoints**: Falls back to 120-day window if checkpoint is invalid or missing

## Testing Checklist

- ✅ Run without API key (expect slower sync, potential 429 errors)
- ✅ Run with API key (smooth pagination, higher rate limits)
- ✅ Verify pagination stops when `startIndex >= totalResults`
- ✅ Test incremental sync by running twice
- ✅ Verify MongoDB upserts prevent duplicates (re-run same window)
- ✅ Validate schema: check sample CVE document matches NVD JSON
- ✅ Test date window filtering (try 24h window vs 120-day window)
- ✅ Simulate 429 errors and verify retry/backoff behavior

## License

This project is provided for educational purposes.

## References

- [NVD Developer Documentation](https://nvd.nist.gov/developers)
- [NVD API 2.0 Specification](https://nvd.nist.gov/developers/vulnerabilities)

