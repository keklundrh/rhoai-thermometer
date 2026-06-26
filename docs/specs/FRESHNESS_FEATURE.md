# Container Freshness Feature

## Overview

Added container freshness analysis to both Release View and Time Series View.

**Freshness Definition:** Days between container build date and RHOAI release date
- Formula: `RELEASE_DATE - container-build-date`
- **Positive values** = container built BEFORE release (older/stale)
- **Negative values** = container built AFTER release (newer/fresher)

---

## Changes Made

### 1. Data Processing (`app/data_loader.py`)

**Added to `compute_release_metrics()`:**
```python
# Container Freshness Analysis
df_freshness = df[df['container-build-date'] != 'W'].copy()
df_freshness['freshness_days'] = (RELEASE_DATE - container-build-date).days
freshness_per_container = df_freshness.groupby('SHA')['freshness_days'].first()
freshness_dist = freshness_per_container.values
```

**New function:**
```python
get_freshness_data_by_release() -> Dict[str, np.ndarray]
```
Returns mapping of RHOAI version → freshness array for all releases (used in Time Series View).

### 2. Visualization (`app/utils.py`)

**New chart functions:**

1. **`create_freshness_chart(data)`**
   - Single-release histogram
   - Green color scheme
   - Vertical line at x=0 (release date)
   - Used in Release View

2. **`create_freshness_stacked_chart(freshness_data_by_release)`**
   - Multi-release stacked histogram
   - Color-coded by release
   - Shows all releases on same axis
   - Used in Time Series View

### 3. UI Updates (`app/app.py`)

**Release View:**
- Added freshness histogram in "Distribution Analysis" section
- Placed below CVE distribution and severity charts
- Full width display

**Time Series View:**
- Added new section: "Container Freshness Across Releases"
- Stacked histogram comparing freshness patterns across releases
- Info box explaining positive/negative values

### 4. Documentation

**Updated `CLAUDE.md`:**
- Added freshness to Release View user experience section
- Added freshness to Time Series View section
- Documented freshness calculation formula

---

## Usage

### Release View
1. Select a RHOAI release
2. Scroll to "Distribution Analysis"
3. View freshness histogram below CVE/severity charts

**Interpretation:**
- Peak on positive side = most containers older than release
- Peak on negative side = most containers newer than release
- Spread indicates variation in container ages

### Time Series View
1. Navigate to Time Series View
2. Scroll to "Container Freshness Across Releases"
3. View stacked histogram

**Interpretation:**
- Compare freshness patterns across releases
- Identify trends (are newer releases using fresher containers?)
- Each color = one RHOAI release

---

## Technical Details

**Data Filtering:**
- Excludes containers with `container-build-date = 'W'` (invalid dates)
- Uses only unique containers (one entry per SHA)
- Handles unparseable dates gracefully

**Caching:**
- Both functions use `@st.cache_data(ttl=300)` for 5-minute cache
- Auto-refreshes when new data files added

**Return Values:**
- `compute_release_metrics()` now includes `'freshness_dist': np.ndarray`
- All empty return dicts updated to include `'freshness_dist': []`

---

## Testing Checklist

- [ ] Release View freshness chart displays correctly
- [ ] Time Series View stacked chart displays all releases
- [ ] Vertical red line at x=0 shows release date
- [ ] Hover tooltips show correct values
- [ ] Chart handles releases with no valid build dates
- [ ] Legend shows all RHOAI versions
- [ ] Info box explains positive/negative values

---

## Future Enhancements

Potential additions:
- Add median freshness to summary metrics
- Filter time series chart by date range
- Add freshness trend line over time
- Show freshness percentiles (p50, p90, p95)
