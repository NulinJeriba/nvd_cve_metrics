# NVD CVE SQLite Database & Flask Web App

## Overview

This project downloads the National Vulnerability Database (NVD) CVE dataset via the official NVD API and stores it locally in a SQLite database. It includes a Flask web application to browse, search, and view detailed vulnerability CVEs with full CVSS V2 metrics and associated CPE information.

## Setup Instructions

### Prerequisites
- Python 3.8+
- Virtual environment recommended
- Internet access to fetch from NVD API

### Database Initialization & Data Fetching

Run the fetch script to create tables and import CVE data into SQLite:

python fetch_all_cves_parallel.py

- The script automatically resumes fetching from the last offset.
- Allows restarting if interrupted without re-fetching all data.
- Fetching the full dataset may take several hours depending on network and machine speed.
- Handles API rate limiting and network interruptions gracefully.

### Running the Flask Web Application

Start the Flask app:

python app.py
Open your browser at [http://localhost:5000/cves/list](http://localhost:5000/cves/list) to browse and search CVEs, and click items for detailed metrics and CPE info.

## Database Schema

- `cves`: Stores CVE details and CVSS V2 metrics including sub-metrics.


## Project API Documentation

### NVD CVE Fetcher Script (`fetch_all_cves_parallel.py`)

- Connects to the official NVD REST API: `https://services.nvd.nist.gov/rest/json/cves/2.0`.
- Supports paginated data fetching with `startIndex` and `resultsPerPage` parameters.
- Uses multithreading (`ThreadPoolExecutor`) to fetch pages concurrently.
- Dedicated writer thread batches inserts into SQLite to prevent DB locking.
- Extracts and stores CVE metadata, CVSS v2 metrics, and CPE matches.

**Usage:**

python fetch_all_cves_parallel.py

### Flask Web Application (`app.py`)

- Serves data from the local SQLite database.
- Key endpoints:
  - `/cves/list`: Paginated list of CVEs.
  - `/cves/<cve_id>`: Detailed view of a CVE’s description, CVSS V2 metrics, and CPE data.

## Notes

- Delete your database file to start fetching fresh data.
- Use the `.gitignore` file to exclude the local database file (`database/nvd_cve.db`) from version control.
- The fetch script is designed to be resilient to API limits and interruptions.

![List page](screenshots/list%20page%20.png)

![CVE ID with metric NA](screenshots/cve%20id%20-%20metric%20NA.png)

![CVE ID with metrics](screenshots/cve%20id%20with%20metrics.png)
