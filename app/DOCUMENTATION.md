## Overview

**RHOAI Thermometer** is a security analytics tool that scans Red Hat OpenShift AI (RHOAI) container images for CVE vulnerabilities. It generates time-series vulnerability data by scanning images from specific RHOAI releases as they existed at release time, enabling trend analysis and security posture tracking.

---

## 🔍 Scanning Process

### Data Collection Pipeline

The scanning process (`scripts/rh-summarize.sh`) performs the following steps:

1. **Fetch Image List** - Retrieves container image list from Red Hat operator catalog for the specified OCP version
2. **Historical Manifest** - Uses `git` to retrieve the RHOAI image manifest from the [disconnected-install-helper](https://github.com/red-hat-data-services/rhoai-disconnected-install-helper) repo as **it existed at the release date**
3. **Generate SBOMs** - Creates Software Bill of Materials for each container image using **Syft**
4. **Scan for Vulnerabilities** - Scans SBOMs with **Grype** to identify CVEs
5. **Enrich CVE Data** - Fetches metadata from:
   - Red Hat VEX (Vulnerability Exploitability eXchange) API
   - GitHub Security Advisories
6. **Output** - Generates consolidated TSV files in `data/summary/`
7. **Removes CVES < 8.0** - Including only CVEs with CVSS or related score greater than or equal to 8.0 (following process from two large Red Hat customers)  

**Key Tools:**
- `syft` - SBOM generation
- `grype` - CVE scanning
- `jq` - JSON processing
- `gh` - GitHub API access
- `podman` - Container image inspection

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

### TSV File Columns

Summary TSV files (`data/summary/*.tsv`) contain these tab-separated columns:

| Column | Description |
|--------|-------------|
| `id` | CVE or GHSA identifier |
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

> **Note:** Only CVEs with CVSS ≥ 8.0 (either base score or related score) are included in output.

---

## 📈 Release View Metrics

### Summary Metrics

| Metric | Calculation | Meaning |
|--------|-------------|---------|
| **Total CVEs at Release** | Count of rows where `DISCOVERY_DATE <= RELEASE_DATE` | High/critical CVEs that existed when RHOAI was released. Excludes `NO-RH-VEX` entries. |
| **Unique CVEs** | Count of distinct `id` values (from filtered set) | Number of distinct vulnerabilities. Same CVE may appear in multiple containers. |
| **Total Containers** | Count of distinct `SHA` values | Number of unique container images scanned in this release. |
| **Avg CVEs per Container** | Mean of CVEs grouped by `IMAGE` | Average vulnerability count per container. |

### Fix Availability Metrics

**Important Context:** These metrics reflect when fixes became **available** in the Red Hat ecosystem (RHEL, OCP, RHOAI, or other RH products), not necessarily when they were **deployed** in RHOAI containers. Actual deployment depends on container rebuild cycles.

| Metric | Calculation | Meaning |
|--------|-------------|---------|
| **CVEs with RH Fix Available at Release** | Count where `FIX_DATE <= RELEASE_DATE AND fix-version != 'None'` | CVEs where a fix existed somewhere in Red Hat's product ecosystem at the RHOAI release date. For base system packages (libxml2, openssl, krb5), this typically means the fix was available in RHEL and *could* have been pulled into RHOAI containers during rebuild. For application-level dependencies (Go/Python libraries), each product manages versions independently. |
| **% CVEs with No Fix at Release** | `(FIX_DATE > RELEASE_DATE OR FIX_DATE = 'NO-RH-VEX') / total_cves * 100` | Percentage of CVEs where no fix existed anywhere in the Red Hat ecosystem when RHOAI was released. |
| **% CVEs with Fix at Release** | `100 - % No Fix` | Percentage of CVEs where a fix already existed somewhere in the Red Hat ecosystem at RHOAI release date. This indicates fix **availability**, not necessarily fix **deployment** in RHOAI containers. |
| **% with Fix Version Listed** | `(FIX_DATE <= RELEASE_DATE AND fix-version != 'None') / cves_with_fix * 100` | Of CVEs with fix at release, percentage that have the fix-version field populated in Red Hat VEX data. This indicates Red Hat tracked which package version contains the fix. |

### Understanding Fix Availability vs. Deployment

**Key Distinction:**
- **Fix Available**: A patched package version exists in some Red Hat product (RHEL, OCP, RHOAI, etc.)
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

**Container Freshness**
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
| **Total CVEs** | Automatic | Total high/critical CVEs discovered at or before each release |
| **Unique CVEs** | Automatic | Count of distinct CVE IDs per release |
| **Total Containers** | Automatic | Number of unique container images per release |
| **Average CVEs per Container** | Automatic | Mean CVE count across containers |
| **% CVEs with No Fix** | Consistent (shared) | Percentage of CVEs without fixes available in RH ecosystem at release time |
| **% CVEs with Fix** | Consistent (shared) | Percentage of CVEs with fixes available in RH ecosystem at release time |
| **% with Fix Version Listed** | Consistent (shared) | Percentage of CVEs with fix version tracked in VEX data |
| **Container Freshness (View 1)** | Monthly bins | Container build dates binned by calendar month, stacked by release |
| **Container Freshness (View 2)** | Days histogram | Container freshness in days from release, stacked histogram by release |

**Y-Axis Consistency:**
- Percentage metrics share the same Y-axis range for easy comparison
- Numeric metrics use automatic scaling due to magnitude differences

### Container Freshness Views (Time Series)

Two views are available to analyze container freshness:

#### View 1: Monthly Build Dates

**Chart Type:** Stacked bar chart

**X-Axis:** Calendar months (YYYY-MM format)
- Each bar represents one month
- Bars are stacked by RHOAI release version

**Vertical Lines:** Dashed lines mark each RHOAI release date
- Color-coded to match that release's bars
- Labels rotated -90° to avoid overlap

**Interpretation:**
- Bars to the **left** of a release line = containers built BEFORE that release
- Bars to the **right** of a release line = containers built AFTER that release
- Helps identify if releases are using fresh or stale container builds

#### View 2: Freshness Distribution (Days)

**Chart Type:** Stacked histogram

**X-Axis:** Days from release (container-build-date - RELEASE_DATE)
- Negative values = containers built BEFORE release (left side)
- Positive values = containers built AFTER release (right side)
- Bins show distribution of freshness across all releases

**Red Vertical Line:** Marks the release date (x=0)

**Interpretation:**
- Each colored layer = one RHOAI release
- Shows how many days before/after release containers were built
- Helps identify trends in container age at release time

---

## 📊 Interpreting Fix Metrics

### How to Read "% CVEs with Fix at Release"

This metric answers: **"What percentage of CVEs had a fix available somewhere in the Red Hat ecosystem when this RHOAI release shipped?"**

**High percentage (e.g., 80%+):**
- ✅ Good: Most CVEs had fixes available in Red Hat products
- ⚠️ Consideration: Check container freshness - old containers may not have pulled in available fixes
- 💡 Action: Compare with container build dates to assess if fixes were likely deployed

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

### Severity Threshold

Only CVEs with **CVSS ≥ 8.0** (High or Critical) are included in scan output.

---

## 📖 Glossary

| Term | Definition |
|------|------------|
| **CVE** | Common Vulnerabilities and Exposures - standardized identifier for security vulnerabilities |
| **GHSA** | GitHub Security Advisory - vulnerability database maintained by GitHub |
| **CVSS** | Common Vulnerability Scoring System - standard for assessing severity (0-10 scale) |
| **SBOM** | Software Bill of Materials - comprehensive inventory of software components |
| **VEX** | Vulnerability Exploitability eXchange - Red Hat's vulnerability metadata API |
| **Grype** | Open-source vulnerability scanner for container images |
| **Syft** | Open-source SBOM generation tool |
| **NO-RH-VEX** | Marker indicating no Red Hat VEX data available for this CVE |
| **Freshness** | Age of container relative to RHOAI release (container-build-date - RELEASE_DATE) |
| **IQR** | Interquartile Range - statistical measure of data spread (Q3 - Q1) |
| **SHA** | Secure Hash Algorithm digest - unique identifier for container images |

---

## 📂 Data Location

```bash
data/summary/*.tsv
```

## 🔄 Cache Refresh

Dashboard data auto-refreshes every 5 minutes (300s TTL)

---

## 🚀 Running Scans

To scan a new RHOAI release:

```bash
cd scripts
./rh-summarize.sh <OCP_VERSION> <RHOAI_VERSION>

# Examples:
./rh-summarize.sh 4.18 2.19.0          # Scan with CVEs as of release date
./rh-summarize.sh 4.18 2.19.0 today    # Scan with today's CVE database
```

Results will appear in `data/summary/` and be automatically picked up by the dashboard within 5 minutes.
