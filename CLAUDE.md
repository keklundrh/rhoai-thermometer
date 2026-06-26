# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

RHOAI Thermometer is a security analytics tool that scans Red Hat OpenShift AI (RHOAI) container images for CVE vulnerabilities. It generates time-series vulnerability data by scanning images from specific RHOAI releases as they existed at release time, enabling trend analysis and security posture tracking.

## Prerequisites

Before first run:
1. Clone the helper repo in project root: `git clone https://github.com/red-hat-data-services/rhoai-disconnected-install-helper.git`
2. Install dependencies: `grype`, `syft`, `jq`, `git`, `podman`, `gh` (GitHub CLI)

## Running Scans

Main script: `./rh-summarize.sh <OCP_VERSION> <RHOAI_VERSION> [today|release] [CVSS_THRESHOLD]`

Examples:
- `./rh-summarize.sh 4.18 2.19.0` — scan RHOAI 2.19.0 on OCP 4.18 using CVEs as of release date, no CVSS filtering (default 0.0)
- `./rh-summarize.sh 4.18 2.19.0 today` — scan same version using today's CVE database, no filtering
- `./rh-summarize.sh 4.18 2.19.0 release 8.0` — scan at release date, only include CVEs with CVSS >= 8.0

**CVSS Filtering:** The optional 4th parameter sets a minimum CVSS threshold. Default is 0.0 (no filtering). The filter applies to base-score OR rel-base-score. Best practice: run scans without filtering to capture all CVEs, then use the frontend filtering UI for dynamic analysis.

The script:
1. Fetches image list from Red Hat operator catalog for the specified OCP version
2. Retrieves the historical RHOAI image manifest from the disconnected-install-helper repo at the release date
3. Generates SBOMs for each container image using Syft
4. Scans SBOMs with Grype for vulnerabilities
5. Enriches CVE data with Red Hat VEX metadata and GitHub Security Advisories
6. Outputs consolidated TSV files in `data/summary/`

## Data Architecture

### Directory Structure

```
data/
  releases/
    <ocp-version>/
      rhoai-<version>.txt          # List of image references for a release
    rhoai-dates.csv                 # Release date mapping (release,GA-date)
  images/
    <image-name>/
      sboms/
        <sha256>.syft.json          # SBOM for specific image digest
      scans/
        <sha256>.grype.<date>.json  # Raw Grype scan output
        <sha256>.grype.<date>.tsv   # Processed CVE summary with metadata
  summary/
    ocp-<ocp>-rhoai-<ver>-RELEASE.tsv    # Release-date CVE snapshot
    ocp-<ocp>-rhoai-<ver>-CVEs-TODAY.tsv # Current CVE snapshot
  vex/
    <year>/
      <cve-id>.json                 # Red Hat VEX data
    GHSA/
      <ghsa-id>.json                # GitHub Security Advisory data
```

### TSV Schema

Summary TSV files contain these columns (tab-separated):
1. `id` — CVE or GHSA identifier
2. `severity` — Low/Medium/High/Critical
3. `base-score` — CVSS base score from Grype
4. `package` — Affected package name
5. `version` — Installed package version
6. `fix-version` — Version with fix (or "None")
8. `rel-base-score` — Related vulnerability CVSS score
9. `container-build-date` — When the container was built
10. `DISCOVERY_DATE` — When CVE was discovered (from RH VEX)
11. `FIX_DATE` — When fix was available (from RH VEX)
12. `RELEASE_DATE` — RHOAI release GA date
13. `REPOSITORY` — Image registry (e.g., quay.io)
14. `IMAGE` — Image name without tag/digest
15. `SHA` — Image SHA256 digest

Only CVEs with CVSS >= 8.0 (either base score or related score) are included in output.

### Key Functions in rh-summarize.sh

- `fn_generate_sbom()` — Creates Syft SBOM for an image if not cached
- `fn_scan_sbom()` — Runs Grype scan on SBOM if not cached  
- `fn_cve_summary()` — Filters scan results to high/critical CVEs and formats as TSV

### Data Enrichment Flow

For each CVE found:
1. If GHSA identifier: fetch GitHub advisory to map to CVE-ID
2. Fetch Red Hat VEX data from `https://security.access.redhat.com/data/csaf/v2/vex/<year>/<cve>.json`
3. Extract discovery date and remediation date from VEX
4. Cache all fetched data locally (30-day freshness check)

### Historical Scanning

The script uses `git show "$(git rev-list -n 1 --before="$SCAN_DATE" main)"` to retrieve the RHOAI image manifest as it existed at the release date. This enables scanning against the CVE database state at release time, not just current state.

## Development Notes

### Caching Strategy

- SBOMs are generated once per image SHA and reused
- Grype scans are dated (`<sha>.grype.<date>.json`) to allow rescanning with newer CVE databases
- VEX data is cached with 30-day TTL
- All data stored under `data/` for reuse across scans

### OCP Version Requirements

RHOAI 3.x requires OCP 4.20 or later. The script validates catalog availability and shows available versions on error.

### Version Normalization

Script strips trailing `.0` from versions (e.g., `2.19.0` → `2.19`) to match file naming in the disconnected-install-helper repo.

### Parallel Execution

The script currently runs sequentially (`while read` loop). Parallel scanning capability exists but is commented out (see TODO at line 37-40). Can be re-enabled with `xargs -n 1 -P $JOBS`.

## Output Naming Convention

- `RELEASE` suffix: CVEs as of the RHOAI GA date (from rhoai-dates.csv)
- `CVEs-TODAY` suffix: CVEs as of script execution date

This enables comparing "how many CVEs existed at launch" vs "how many exist now" for the same RHOAI version.

## Frontend 

This project contains a local web application that displays the following high-level content: 
1. Summary data per release 
2. Summary data over time 
3. Documentation and data catalog

The application has three views accessible via sidebar:
- **Release View** - Detailed metrics for a single RHOAI release
- **Time Series View** - Trends across multiple RHOAI releases
- **Documentation** - Comprehensive guide to scanning process, metrics, and data schema

## User experience 

### Release View

The user selects a RHOAI release and sees:

**Summary Metrics:**
* Total CVEs at Release - CVEs discovered before or on the RHOAI release date (excludes NO-RH-VEX)
* Unique CVEs - Distinct CVE IDs (same CVE may appear in multiple containers)
* Total Containers - Number of unique container images scanned
* Average CVEs per Container - Mean CVE count across containers

**Fix Availability:**
* % CVEs with No Fix at Release
* % CVEs with Fix at Release

**Distribution Analysis:**
* CVE Distribution box plot - Shows CVE count distribution across containers (Y-axis capped at 1.5×IQR for readability)
* Severity chart - Breakdown by Critical/High/Medium/Low
* Container Freshness histogram - Shows age of containers relative to RHOAI release date
  - Positive values = containers built before release (older/stale)
  - Negative values = containers built after release (newer)
  - Calculated as: `RELEASE_DATE - container-build-date`

**Top Containers:**
* Table showing 5 containers with the most CVEs

### Time Series View

The user selects a metric to track across RHOAI releases:
* Numeric metrics (Total CVEs, Unique CVEs, Total Containers, Avg CVEs per Container) - automatic Y-axis
* Percentage metrics (% No Fix, % With Fix) - consistent Y-axis across both

**Container Freshness (when selected from dropdown):**
* Stacked bar chart showing container build dates binned by month
* Each release color-coded, allowing comparison of container age patterns over time
* Vertical dashed lines mark each RHOAI release date

### Documentation View

Displays comprehensive documentation loaded from `app/DOCUMENTATION.md`:
* Scanning process and data collection pipeline
* TSV data schema with all column definitions
* Metric calculations and meanings for both Release and Time Series views
* Data filtering rules
* Glossary of terms

The documentation is stored as Markdown for easy editing without code changes.

In both cases, the `data/summary` folder includes a release specific TSV summary. The file names are structured `ocp-${OPENSHIFT_VER}-rhoai-${RHOAI_VER}.tsv or `ocp-${OPENSHIFT_VER}-rhoai-${RHOAI_VER}-RELEASE.tsv. For the timeseries, you can ignore $OPENSHIFT_VER. Plot $RHOAI_VER in increasing numerical order where 2.22.0 is less than 3.2.0 which is less than 3.4.0. 

## Summary of summarized files

Data files exist in `data/summary` but they include a tsv file where each row is a CVE. The frontend uses a summary of these summaries files and is created using a python script. The python script auto-refreshes when the streamlit app loads to pull in any new data files in the `data/summary` folder and add the summary data to the file. 

Default to \*-RELEASE.tsv files for historical comparison.

If two scans were done on the same RHOAI version, the summary script only uses the $OPENSHIFT_VER that is greater.

## Frontend technical specs 

The frontend is a simple streamlit application.

## The deployment model 

Run locally using a simple command.
