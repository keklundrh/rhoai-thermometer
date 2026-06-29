# FRONTEND APP Filtering - IMPLEMENTATION COMPLETE

## Overview

The Streamlit app includes dynamic filtering in the sidebar that allows users to filter CVE data by CVSS score or severity level. Filters are mutually exclusive and apply to both Release View and Time Series View.

---

## IMPLEMENTATION STATUS: ✅ COMPLETE

### Implemented Features

1. ✅ Filter section in sidebar above "Views" toggle
2. ✅ CVSS Score filtering with slider + text input
3. ✅ Severity filtering with multi-select dropdown
4. ✅ Mutually exclusive filter modes (radio button selector)
5. ✅ Dynamic minimum CVSS calculation from actual data
6. ✅ Active filter indicator shown in main views
7. ✅ Updated `rh-summarize.sh` to support configurable CVSS threshold

---

## FILTERING BY CVSS SCORE

### User Interface
- **Slider**: Visual selection of CVSS threshold
- **Text Input**: Allows precise value entry (overrides slider)
- **Min Value**: Dynamically calculated from data (see calculation logic below)
- **Max Value**: 10.0 (CVSS maximum)
- **Default Value**: `max(8.0, min_cvss)` - uses 8.0 or the data minimum, whichever is greater
- **Step**: 0.1

### Filter Logic
- Includes CVEs where **EITHER** `base-score >= threshold` **OR** `rel-base-score >= threshold`
- Applied after date-based filtering (DISCOVERY_DATE <= RELEASE_DATE)
- When CVSS filter is selected, severity filter is disabled

### Minimum CVSS Calculation
The minimum slider value is calculated dynamically from ALL available data files:

1. For each CVE row: `effective_score = max(base-score, rel-base-score)`
   - Reflects the OR logic: a CVE qualifies if either score meets the threshold
   - Example: `base-score=0, rel-base-score=9.8` → effective score is 9.8
2. Find the minimum of all effective scores across all releases
3. Round down to nearest 0.1 for clean slider values
4. Cached for 5 minutes to avoid re-scanning on every interaction

**Rationale**: This matches the scan filter behavior where CVEs are included if EITHER score exceeds the threshold.

---

## FILTERING BY SEVERITY

### User Interface
- **Multi-select dropdown**: Choose one or more severity levels
- **Options**: Critical, High, Medium, Low
- **Default**: Critical + High
- **Logic**: OR operator (selecting High & Critical returns CVEs matching either criteria)

### Filter Logic
- Includes CVEs where `severity` matches ANY selected level
- Applied after date-based filtering (DISCOVERY_DATE <= RELEASE_DATE)
- When severity filter is selected, CVSS filter is disabled

---

## DATA LAYER IMPLEMENTATION

### `data_loader.py` Changes

**`get_min_cvss_score()`**
- Scans all RELEASE.tsv files in `data/summary/`
- Computes effective CVSS score per row: `max(base-score, rel-base-score)`
- Returns the minimum effective score across all data
- Handles "NA" values by converting to NaN and excluding from calculation

**`compute_release_metrics(df, cvss_threshold, severity_filter)`**
- Added two new optional parameters:
  - `cvss_threshold`: float or None
  - `severity_filter`: list of severity strings or None
- Filters applied sequentially:
  1. Date filter (existing): DISCOVERY_DATE <= RELEASE_DATE
  2. CVSS/Severity filter (new): based on user selection
- Converts score columns to numeric, treating "NA" as NaN

**`get_time_series_data(cvss_threshold, severity_filter)`**
- Accepts filter parameters and passes to `compute_release_metrics()`
- Uses tuple for severity_filter (required for Streamlit caching)

---

## UI/UX IMPLEMENTATION

### `app.py` Changes

**Filter Section (Sidebar)**
```
🔍 Filters
├── Filter By: [CVSS Score | Severity]
├── CVSS Mode:
│   ├── Slider (min_cvss to 10.0, default: max(8.0, min_cvss))
│   └── Text Input (override slider)
└── Severity Mode:
    └── Multi-select (Critical, High, Medium, Low)
```

**Active Filter Indicator**
- Info banner displayed at top of Release View and Time Series View
- Shows current filter: "🔍 Active Filter: CVSS Score ≥ 8.0" or "🔍 Active Filter: Severity = Critical, High"

**Caching**
- Filter parameters passed to cached functions
- Severity filter converted to tuple for cache key compatibility

---

## BASH SCRIPT UPDATES (`rh-summarize.sh`)

### Changes Made
- **Old**: Hardcoded `CVE_SCORE=7.9`
- **New**: `CVE_SCORE=${4:-0.0}` - optional 4th parameter, defaults to 0.0

### Usage
```bash
./rh-summarize.sh <OCP_VERSION> <RHOAI_VERSION> [today|release] [CVSS_THRESHOLD]
```

### Examples
```bash
# Scan with no filtering (recommended - let frontend filter)
./rh-summarize.sh 4.18 2.19.0

# Scan with today's CVE data, no filtering
./rh-summarize.sh 4.18 2.19.0 today

# Scan at release date, pre-filter CVSS >= 8.0
./rh-summarize.sh 4.18 2.19.0 release 8.0
```

### Best Practice
- **Run scans with `CVSS_THRESHOLD=0.0`** (default) to capture all CVEs
- **Use frontend filtering** for dynamic, flexible analysis
- Only pre-filter during scans if you specifically want smaller TSV files or never need to see lower-severity CVEs

### Filter Behavior (when CVSS_THRESHOLD > 0)
```bash
awk -v score="$CVE_SCORE" -F\t '($3+0 > score ) || ($7+0 > score)'
```
- Includes CVEs where `base-score > threshold` OR `rel-base-score > threshold`
- Column 3: base-score
- Column 7: rel-base-score

---

## DOCUMENTATION UPDATES

### CLAUDE.md
- Updated "Running Scans" section with new usage pattern
- Added CVSS_THRESHOLD parameter documentation
- Added best practices for filtering

---

## TESTING NOTES

### Test Scenarios
1. ✅ CVSS slider adjusts to actual data minimum
2. ✅ Default CVSS is 8.0 (or higher if data minimum > 8.0)
3. ✅ Text input overrides slider value
4. ✅ Severity multi-select defaults to Critical + High
5. ✅ Switching filter types disables the other
6. ✅ Active filter shown in Release View
7. ✅ Active filter shown in Time Series View
8. ✅ Filters applied to both views consistently
9. ✅ Time series data respects filters across all releases

### Edge Cases Handled
- "NA" values in score columns → converted to NaN, excluded from calculations
- Empty data files → skip gracefully
- No valid scores → fallback to 0.0
- Data minimum > 8.0 → default adjusts upward

---

## FUTURE ENHANCEMENTS (Not Implemented)

- Combine CVSS + Severity filters (currently mutually exclusive)
- Filter persistence across sessions (browser storage)
- Export filtered data to CSV
- Filter by date ranges
- Filter by container/repository 
