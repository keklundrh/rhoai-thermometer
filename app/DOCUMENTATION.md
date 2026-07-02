## Overview

**RHOAI Thermometer** is a security analytics tool that scans Red Hat OpenShift AI (RHOAI) container images for CVE vulnerabilities. It generates time-series vulnerability data by scanning **supported images only** from specific RHOAI releases as they existed at release time, enabling trend analysis and security posture tracking.

**Important:** Only **officially supported** RHOAI container images are scanned. Images marked as "Unsupported" or deprecated in the disconnected-install-helper repository are automatically excluded from analysis.

**Default CVSS Threshold:** By default, scans include only CVEs with CVSS ≥ 8.0 (High or Critical severity). The frontend allows dynamic filtering to adjust this threshold or filter by severity levels.

---

## 🔍 Scanning Process

### Data Collection Pipeline

The scanning process (`scripts/rh-summarize.sh`) performs the following steps:

1. **Fetch Image List** - Retrieves container image list from Red Hat operator catalog for the specified OCP version
2. **Historical Manifest** - Uses `git` to retrieve the RHOAI image manifest from the [disconnected-install-helper](https://github.com/red-hat-data-services/rhoai-disconnected-install-helper) repo as **it existed at the release date**
3. **Filter Unsupported Images** - Automatically excludes images marked as "Unsupported" in the disconnected-install-helper repository. **Only officially supported RHOAI images are scanned.**
4. **Generate SBOMs** - Creates Software Bill of Materials for each container image using **Syft**
5. **Scan for Vulnerabilities** - Scans SBOMs with **Grype** to identify CVEs
6. **Enrich CVE Data** - Fetches metadata from multiple sources based on vulnerability type:
   - **CVE-\*** identifiers → Red Hat VEX (Vulnerability Exploitability eXchange) API
   - **GHSA-\*** identifiers → GitHub Security Advisories API
   - **GO-\*** identifiers → OSV (Open Source Vulnerabilities) API for Go ecosystem
7. **Cross-Reference Mappings** - When GHSA or GO identifiers map to CVE-\* aliases, fetches Red Hat VEX data for the mapped CVE
8. **Filter by CVSS** - By default, includes only CVEs with CVSS ≥ 8.0 (base-score OR rel-base-score)
9. **Output** - Generates consolidated TSV files in `data/summary/`  

**Key Tools:**
- `syft` - SBOM generation
- `grype` - CVE scanning (detects CVE-\*, GHSA-\*, and GO-\* identifiers)
- `jq` - JSON processing
- `gh` - GitHub API access for GHSA data
- `podman` - Container image inspection
- `curl` - API calls to Red Hat VEX and OSV databases

### Caching Strategy

To improve performance and reduce redundant work:

- **SBOMs** are generated once per image SHA and reused
- **Grype scans** are dated (`<sha>.grype.<date>.json`) to allow rescanning with newer CVE databases
- **VEX data** is cached with 30-day TTL
- All data stored under `data/` for reuse across scans

### Historical Scanning

The script uses `git show` to retrieve the RHOAI image manifest as it existed at a specific date, by default we use the RHOAI release date:

```bash
git show "$(git rev-list -n 1 --before="$SCAN_DATE" main)"
```

Files are named based off the scan date, for example:

**File Naming:**
- `*-RELEASE.tsv` - CVEs as of the RHOAI GA date
- `*-CVEs-TODAY.tsv` - CVEs as of script execution date

---

## 📊 Data Schema

### Vulnerability Identifier Types

The scanner detects three types of vulnerability identifiers:

| Type | Format | Source | Description |
|------|--------|--------|-------------|
| **CVE** | `CVE-YYYY-NNNNN` | NVD/MITRE | Standard Common Vulnerabilities and Exposures identifier |
| **GHSA** | `GHSA-xxxx-xxxx-xxxx` | GitHub | GitHub Security Advisory identifier |
| **GO** | `GO-YYYY-NNNN` | OSV | Go ecosystem vulnerability identifier from OSV database |

**Enrichment Process:**
1. All identifiers are scanned by Grype
2. **CVE-\*** → Fetch Red Hat VEX data directly
3. **GHSA-\*** → Fetch GitHub advisory, check for CVE-\* alias, then fetch RH VEX if alias exists
4. **GO-\*** → Fetch OSV data, check for CVE-\* alias, then fetch RH VEX if alias exists

**Fallback Dates:**
- If GO-\* has no CVE alias: Use `published` date as DISCOVERY_DATE and `modified` date as FIX_DATE
- If GHSA-\* has no CVE alias: Use `published_at` as DISCOVERY_DATE and `updated_at` as FIX_DATE
- If no VEX data available: Marked as `NO-RH-VEX`, `NO-GHSA`, or `NO-GO-VEX`

**Why GO Identifiers Matter:**
- RHOAI containers include Go-compiled binaries (Kubernetes operators, controllers, services)
- Go dependencies have their own vulnerability tracking separate from CVE
- OSV provides comprehensive coverage of Go ecosystem vulnerabilities
- Many GO-\* identifiers map to CVE-\* aliases for cross-referencing

**Example Data Flow for GO Vulnerability:**
```
1. Grype detects: GO-2024-3321 in golang.org/x/crypto v0.21.0
2. Script fetches OSV data: https://api.osv.dev/v1/vulns/GO-2024-3321
3. OSV response includes alias: CVE-2024-45678
4. Script fetches RH VEX for CVE-2024-45678
5. TSV output:
   - id: GO-2024-3321
   - DISCOVERY_DATE: From RH VEX (if CVE alias exists) or OSV published date
   - FIX_DATE: From RH VEX (if CVE alias exists) or OSV modified date
```

### TSV File Columns

Summary TSV files (`data/summary/*.tsv`) contain these tab-separated columns:

| Column | Description |
|--------|-------------|
| `id` | Vulnerability identifier (CVE-\*, GHSA-\*, or GO-\*) |
| `severity` | Low/Medium/High/Critical |
| `base-score` | CVSS base score from Grype |
| `package` | Affected package name |
| `version` | Installed package version |
| `fix-version` | Version with fix (or "None") |
| `location` | File path(s) in container |
| `rel-base-score` | Related vulnerability CVSS score |
| `container-build-date` | When the container was built |
| `DISCOVERY_DATE` | When CVE was discovered (from RH VEX) |
| `FIX_DATE` | When fix was available (from RH VEX) |
| `RELEASE_DATE` | RHOAI release GA date |
| `REPOSITORY` | Image registry (e.g., quay.io) |
| `IMAGE` | Image name without tag/digest |
| `SHA` | Image SHA256 digest |

> **Note:** By default, only CVEs with CVSS ≥ 8.0 (either base-score OR rel-base-score) are included in scan output. The frontend allows dynamic filtering to adjust this threshold.

---

## 📈 Release View Metrics

### Summary Metrics

| Metric | Calculation | Meaning |
|--------|-------------|---------|
| **Total CVEs at Release** | Count of rows where `DISCOVERY_DATE <= RELEASE_DATE` | High/critical CVEs that existed when RHOAI was released. Excludes `NO-RH-VEX` entries. |
| **Unique CVEs** | Count of distinct `id` values (from filtered set) | Number of distinct vulnerabilities. Same CVE may appear in multiple containers. |
| **Number of Containers with CVEs** | Count of distinct `SHA` values with CVEs | Number of unique container images that have at least one CVE. Note: Containers with 0 CVEs are not included in summary files. |
| **Avg CVEs per Container** | Mean of CVEs grouped by `IMAGE` | Average vulnerability count per container (only containers with CVEs). |

### Fix Availability Metrics

**Important Context:** These metrics reflect when fixes became **available**, either in the Red Hat ecosystem or upstream sources, not necessarily when they were **deployed** in RHOAI containers. Actual deployment depends on container rebuild cycles.

| Metric | Calculation | Meaning |
|--------|-------------|---------|
| **CVEs with Fix Available at Release** | Count where `FIX_DATE <= RELEASE_DATE` | CVEs where a fix existed at the RHOAI release date. A fix is available but may or may not be available through Red Hat - it could be upstream or in other ecosystems. This indicates fix **availability**, not necessarily fix **deployment** in RHOAI containers. |
| **% CVEs with No Fix at Release** | `(FIX_DATE > RELEASE_DATE OR FIX_DATE = 'NO-RH-VEX') / total_cves * 100` | Percentage of CVEs where no fix existed when RHOAI was released. |
| **% CVEs with Fix at Release** | `100 - % No Fix` | Percentage of CVEs where a fix already existed at RHOAI release date. A fix is available but may or may not be available through Red Hat - it could be upstream or in other ecosystems. This indicates fix **availability**, not necessarily fix **deployment** in RHOAI containers. |
| **% with RH Fix Version** | `(FIX_DATE <= RELEASE_DATE AND fix-version != 'None') / cves_with_fix * 100` | Of CVEs with fix at release, percentage that have the fix-version field populated in Red Hat VEX data. This indicates Red Hat tracked which package version contains the fix - applicability to specific build needs further investigation. |

### Understanding the Three Fix Metrics

These three metrics work together to provide a complete picture of fix status:

1. **% CVEs with Fix at Release** - Broadest measure: indicates a fix existed *somewhere* (Red Hat, upstream, or other ecosystems)
2. **% with RH Fix Version** - Subset of #1: indicates Red Hat specifically tracked a fix version in their VEX data
3. **CVEs with Fix Available at Release** - Raw count version of #2

**Relationship:**
```
All CVEs at Release (100%)
├─ % CVEs with No Fix at Release
└─ % CVEs with Fix at Release
   ├─ Fixes tracked by Red Hat (% with RH Fix Version)
   └─ Fixes from other sources (upstream, other vendors)
```

**Example Interpretation:**
- 85% CVEs with Fix at Release
- 60% with RH Fix Version
- Means: 85% had *some* fix, but only 60% of those (i.e., 51% of total) are tracked by Red Hat

### Understanding Fix Availability vs. Deployment

**Key Distinction:**
- **Fix Available**: A patched package version exists (in Red Hat products, upstream, or elsewhere)
- **Fix Deployed**: The RHOAI container image was rebuilt with the patched package

**Example Timeline:**
```
2025-03-10: RHEL 9.2 ships libxml2-2.9.13-3.el9_2.6 (CVE-2024-56171 fixed)
            → Fix is now AVAILABLE

2025-03-27: RHOAI 2.16 containers rebuilt, pulling in updated libxml2
            → Fix is now DEPLOYED in RHOAI

Gap: 17 days between availability and deployment
```

**Why the gap exists:**
- Container images are rebuilt on product release schedules, not immediately when upstream fixes ship
- RHOAI containers may be based on different RHEL minor versions (9.2, 9.4) with different update timelines
- Application-level dependencies (Go, Python packages) are updated independently per product

**Implication for metrics:**
- A CVE showing "fix at release" means the fix *could have been* included if containers were rebuilt
- It doesn't guarantee the fix *was actually* in the scanned container images
- Use container build dates (freshness metrics) to assess how current the images are

### Distribution Analysis

**CVE Distribution Box Plot**
- Shows distribution of CVE counts across containers
- Y-axis capped at 1.5×IQR (interquartile range) for readability
- Annotation shows containers extending beyond axis and max CVE count

**Severity Chart**
- Horizontal bar chart showing breakdown by severity level
- Color coded: Critical (red), High (orange), Medium (yellow), Low (blue)

**Container Freshness Score** (Release View)
- Percentage of containers built within 3 months of release date
- **Calculation:** `freshness_score = (containers aged 0-90 days / total containers) × 100`
- **Container age:** `RELEASE_DATE - container-build-date` (positive = built before release)
- **Age buckets:**
  - **Excellent (0-3 months):** 0-90 days old at release
  - **Good (3-6 months):** 91-180 days old at release
  - **Fair (6-12 months):** 181-365 days old at release
  - **Stale (12+ months):** 365+ days old at release
- **Impact:** Freshness reduces CVE accumulation from aging dependencies
  - Example: Stale containers (12+mo) in RHOAI 2.13 had ~280 CVEs vs ~120 in fresh RHOAI 3.x containers
  - **However:** Total CVE count depends on BOTH freshness AND base image security at build time
  - Fresh containers built from vulnerable base images can still have high CVE counts
- **Industry standard:** 3-month threshold aligns with quarterly rebuild cycles
- **Interpretation:** 
  - 90%+ score indicates excellent rebuild cadence
  - Combine with total CVE trends to assess overall security posture

**Container Freshness Histogram** (Release View)
- Histogram of container ages relative to RHOAI release
- **Calculation:** `freshness_days = container-build-date - RELEASE_DATE`
- **Negative values** (left) = containers built BEFORE release (older/stale)
- **Positive values** (right) = containers built AFTER release (newer/fresher)
- Hover shows actual build date ranges per bin
- Red vertical line marks RHOAI release date

### Top Containers Table

Displays the 5 containers with the highest CVE counts (from filtered dataset).

Sorted in descending order by CVE count.

---

## 📉 Time Series View Metrics

Select a metric from the dropdown to visualize trends across RHOAI releases.

### Available Metrics

| Metric | Y-Axis Behavior | Description |
|--------|-----------------|-------------|
| **Total CVEs at Release** | Automatic | Total high/critical CVEs discovered at or before each release |
| **CVEs with Fix Available at Release** | Automatic | Count of CVEs where a fix existed at release date |
| **Unique CVEs** | Automatic | Count of distinct CVE IDs per release |
| **Number of Containers with CVEs** | Automatic | Number of unique container images with at least one CVE |
| **Avg CVEs per Container** | Automatic | Mean CVE count across containers (only containers with CVEs) |
| **% CVEs with No Fix at Release** | Consistent (shared) | Percentage of CVEs without fixes available at release time |
| **% CVEs with Fix at Release** | Consistent (shared) | Percentage of CVEs with fixes available at release time (may or may not be through Red Hat) |
| **% with RH Fix Version** | Consistent (shared) | Percentage of CVEs with fix version tracked in Red Hat VEX data |
| **Container Freshness Score** | Consistent (shared) | Percentage of containers built within 3 months of release (0-90 days old) |

**Y-Axis Consistency:**
- Percentage metrics share the same Y-axis range for easy comparison across metrics
- Numeric metrics use automatic scaling due to magnitude differences

### Container Freshness Score Trends (Time Series)

Shows the percentage of "Excellent" containers (0-3 months old) across RHOAI releases.

**Chart Type:** Line chart

**X-Axis:** RHOAI version (e.g., 2.13, 2.16, 3.0, 3.2, 3.3, 3.4)

**Y-Axis:** Percentage of containers in "Excellent" category (0-90 days old at release)

**What It Reveals:**
- **Upward trend** = Container rebuild practices improving
- **Score ≥90%** = Excellent container hygiene (minimal technical debt)
- **Score 60-89%** = Good, but room for improvement
- **Score <60%** = Many stale containers, high CVE accumulation risk

**Key Findings:**
- RHOAI 2.x releases: 42-63% freshness (moderate)
- RHOAI 3.0: 59% (last release with significant stale containers)
- RHOAI 3.2: 72% (major improvement)
- RHOAI 3.3+: 89-94% (excellent, nearly all fresh containers)

**Why This Matters:**
- Fresh containers (0-3mo) average ~120 CVEs in RHOAI 3.x
- Stale containers (12+mo) average ~280 CVEs in RHOAI 2.x (2.3x more)
- Freshness **reduces CVE accumulation** from aging dependencies
- **Important limitation:** Freshness alone doesn't eliminate CVEs - total count also depends on the security posture of base images at build time
- **Best practice:** Combine frequent rebuilds (high freshness) with patched base images
- The 3-month threshold aligns with industry best practices (quarterly rebuild cycles)

---

## 📊 Interpreting Fix Metrics

### How to Read "% CVEs with Fix at Release"

This metric answers: **"What percentage of CVEs had a fix available when this RHOAI release shipped?"**

**Note:** A fix may be available through Red Hat, upstream sources, or other ecosystems. The "% with RH Fix Version" metric shows which fixes are specifically tracked by Red Hat.

**High percentage (e.g., 80%+):**
- ✅ Good: Most CVEs had fixes available somewhere
- ⚠️ Consideration: Check container freshness - old containers may not have pulled in available fixes
- 💡 Action: Compare with "% with RH Fix Version" and container build dates to assess if fixes were likely deployed

**Low percentage (e.g., 30%):**
- ⚠️ Concern: Many CVEs had no available fixes at release time
- 📊 Cross-reference: Check "% CVEs with No Fix" to see what wasn't fixable
- 💡 Action: Review CVE discovery dates - recently discovered CVEs may not have fixes yet

### Combining Metrics for Better Insight

**Scenario 1: High fix availability + Fresh containers = Good posture**
```
% CVEs with Fix at Release: 85%
Container Freshness: Most containers built 0-30 days before release
→ Interpretation: Fixes were available AND likely deployed
```

**Scenario 2: High fix availability + Stale containers = Missed opportunity**
```
% CVEs with Fix at Release: 85%
Container Freshness: Most containers built 90-180 days before release
→ Interpretation: Fixes were available but likely NOT deployed
→ Recommendation: Consider more frequent container rebuilds
```

**Scenario 3: Low fix availability + Fresh containers = Limited options**
```
% CVEs with Fix at Release: 35%
Container Freshness: Most containers built 0-30 days before release
→ Interpretation: Even fresh builds couldn't fix most CVEs (no fixes existed)
→ Recommendation: Focus on tracking when fixes become available post-release
```

### Using Fix Metrics with Discovery Dates

Cross-reference with `DISCOVERY_DATE` to understand CVE age:

- **CVE discovered months before release, no fix**: Concerning - upstream slow to patch
- **CVE discovered days before release, no fix**: Expected - insufficient time to patch
- **CVE discovered before release, fix at release**: Ideal - responsive patching

## 🔍 Data Filtering Rules

### CVE Filtering (Release View)

Only CVEs meeting ALL criteria are included:

1. ✅ **Valid dates:** Both `DISCOVERY_DATE` and `RELEASE_DATE` must be parseable
2. ✅ **Discovered at/before release:** `DISCOVERY_DATE <= RELEASE_DATE`
3. ❌ **Excludes:** `DISCOVERY_DATE = 'NO-RH-VEX'` (cannot determine discovery date)

### Container Filtering

- Containers with `container-build-date = 'W'` are **excluded** from freshness calculations
- All other containers included in total counts

### CVSS Filtering

**Default Threshold:** Scan output includes only CVEs with **CVSS ≥ 8.0** (High or Critical severity).

**Filter Logic:** A CVE is included if **either** `base-score` OR `rel-base-score` meets the threshold. This OR logic ensures CVEs are captured even when only one score field is populated.

**Frontend Filtering:** The dashboard provides dynamic filtering options:
- **CVSS Score slider** - Adjust minimum threshold (default 8.0, range depends on data)
- **Severity selector** - Filter by Critical, High, Medium, Low (multi-select with OR logic)

**Best Practice:** Run scans without CVSS filtering (threshold 0.0) to capture all CVEs, then use frontend filtering for dynamic analysis.

---

## 📖 Glossary

| Term | Definition |
|------|------------|
| **CVE** | Common Vulnerabilities and Exposures - standardized identifier for security vulnerabilities (format: CVE-YYYY-NNNNN) |
| **GHSA** | GitHub Security Advisory - vulnerability database maintained by GitHub (format: GHSA-xxxx-xxxx-xxxx) |
| **GO** | Go ecosystem vulnerability identifier from OSV database (format: GO-YYYY-NNNN) |
| **OSV** | Open Source Vulnerabilities - distributed vulnerability database for open source projects (api.osv.dev) |
| **CVSS** | Common Vulnerability Scoring System - standard for assessing severity (0-10 scale) |
| **SBOM** | Software Bill of Materials - comprehensive inventory of software components |
| **VEX** | Vulnerability Exploitability eXchange - Red Hat's vulnerability metadata API |
| **Grype** | Open-source vulnerability scanner for container images |
| **Syft** | Open-source SBOM generation tool |
| **NO-RH-VEX** | Marker indicating no Red Hat VEX data available for this CVE identifier |
| **NO-GHSA** | Marker indicating no GitHub Security Advisory data available |
| **NO-GO-VEX** | Marker indicating no OSV data available for this GO identifier |
| **Freshness** | Age of container relative to RHOAI release (container-build-date - RELEASE_DATE) |
| **IQR** | Interquartile Range - statistical measure of data spread (Q3 - Q1) |
| **SHA** | Secure Hash Algorithm digest - unique identifier for container images |
| **base-score** | CVSS base score from Grype vulnerability scanner |
| **rel-base-score** | CVSS score from related vulnerabilities (e.g., when a CVE references other CVEs) |
| **FIX_DATE** | Date when a fix became available (from Red Hat VEX or upstream sources) |
| **DISCOVERY_DATE** | Date when the CVE was first discovered or published |

---

## 📂 Data Location

```bash
data/summary/*.tsv
```

## 🔄 Cache Refresh

Dashboard data auto-refreshes every 5 minutes (300s TTL)

---

## 🚀 Running Scans

To scan a new RHOAI release, **run from the project root directory**:

```bash
# From project root (rhoai-thermometer/)
./scripts/rh-summarize.sh <OCP_VERSION> <RHOAI_VERSION> [CVSS_THRESHOLD]

# Examples:
./scripts/rh-summarize.sh 4.18 2.19.0          # Default: CVSS ≥ 0.0 (no filtering)
./scripts/rh-summarize.sh 4.18 2.19.0 0.0      # Explicit: include all CVEs (recommended)
./scripts/rh-summarize.sh 4.18 2.19.0 8.0      # Only High/Critical CVEs (CVSS ≥ 8.0)
./scripts/rh-summarize.sh 4.18 2.19.0 9.0      # Only Critical CVEs (CVSS ≥ 9.0)
```

**Parameters:**
- `OCP_VERSION` - OpenShift version (e.g., 4.18)
- `RHOAI_VERSION` - RHOAI version to scan (e.g., 2.19.0)
- `CVSS_THRESHOLD` - Optional minimum CVSS score (default: 0.0 = no filtering)

**Important Notes:**
- ⚠️ **Must run from project root** - script uses relative paths to `data/` and `rhoai-disconnected-install-helper/`
- The script always scans using CVEs as they existed at the RHOAI release date (from `data/releases/rhoai-dates.csv`), not today's CVE database
- Default threshold changed to 0.0 (no filtering) to allow frontend dynamic filtering

Results will appear in `data/summary/` and be automatically picked up by the dashboard within 5 minutes.
