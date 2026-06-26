# Freshness Feature Updates

## Changes Made

### Release View

**1. Inverted Freshness Calculation**
- **Before:** `freshness = RELEASE_DATE - container-build-date`
  - Positive = before release, Negative = after release
- **After:** `freshness = container-build-date - RELEASE_DATE`
  - **Negative = before release (LEFT)**, Positive = after release (RIGHT)
  - Release date on the **right side** of chart

**2. Enhanced Hover Information**
- Now shows actual container build date ranges when hovering
- Format: `Days from release: X | Container count: Y | Build date range: YYYY-MM-DD`

**3. Updated Chart**
- X-axis label: "Days from Release (negative = built before, positive = built after)"
- Red vertical line shows release date with label
- Green color scheme maintained

---

### Time Series View

**1. Freshness as Dropdown Metric**
- Added "Container Freshness" to metric selector dropdown
- Only displays when user selects it (not always visible)
- Removed standalone "Container Freshness Across Releases" section

**2. Monthly Binning (instead of days)**
- Container build dates binned by **month/year**
- X-axis shows actual calendar months (YYYY-MM format)
- Tick marks every 3 months for readability
- Stacked bars show distribution by RHOAI release

**3. Vertical Release Lines**
- Each RHOAI release marked with colored vertical dashed line
- Lines match the color of that release's bars
- Labels rotated -90° to avoid overlap
- Shows release date position relative to container build months

**4. Inverted Timeline**
- Build dates **before** release appear on the **LEFT**
- Release lines appear at their actual date position
- Build dates **after** release appear on the **RIGHT**

---

## Technical Implementation

### data_loader.py

**compute_release_metrics():**
```python
# Inverted calculation
freshness_days = container-build-date - RELEASE_DATE

# Store both days and dates
freshness_per_container = groupby(['freshness_days', 'container-build-date_dt'])
return {
    'freshness_dist': days_array,
    'freshness_dates': dates_array  # NEW
}
```

**get_freshness_data_by_release():**
```python
# Returns Tuple[Dict, Dict]
# - freshness_data: {version: DataFrame[month, count]}
# - release_dates: {version: release_date}

# Bins containers by month using pandas Period
monthly_data = build_dates.dt.to_period('M').value_counts()
```

### utils.py

**create_freshness_chart():**
- Added `dates` and `release_date` parameters
- Custom hover shows build date ranges
- Updated axis labels for inverted logic

**create_freshness_stacked_chart():**
- Changed from histogram to **stacked bar chart**
- X-axis = calendar months (not days delta)
- Vertical lines for each release with labels
- Color-coded by release version

### app.py

**Release View:**
```python
fig_freshness = create_freshness_chart(
    metrics['freshness_dist'],
    metrics['freshness_dates'],  # NEW
    release_date  # NEW
)
```

**Time Series View:**
```python
# Conditional rendering
if metric_col == "freshness":
    freshness_data, release_dates = get_freshness_data_by_release()
    fig = create_freshness_stacked_chart(freshness_data, release_dates)
else:
    fig = create_time_series_chart(...)  # Regular metrics
```

---

## User Experience

### Release View
- Select a release
- Scroll to "Distribution Analysis"
- **Freshness histogram** shows:
  - Negative values (left) = containers built before release
  - 0 (red line) = RHOAI release date
  - Positive values (right) = containers built after release
  - Hover shows actual build date ranges

### Time Series View
- Select "Container Freshness" from dropdown
- **Monthly stacked bar chart** shows:
  - X-axis = calendar months
  - Colored bars = container counts per release
  - Vertical dashed lines = RHOAI release dates
  - Left of line = containers built before that release
  - Right of line = containers built after that release

---

## Testing Checklist

- [ ] Release View: Freshness chart inverted (negative left, positive right)
- [ ] Release View: Hover shows build date ranges
- [ ] Release View: Red line on right for recent releases
- [ ] Time Series: Freshness appears in dropdown
- [ ] Time Series: Freshness chart only shows when selected
- [ ] Time Series: Monthly bins on X-axis
- [ ] Time Series: Vertical lines for each release
- [ ] Time Series: Colors match between bars and release lines
- [ ] Time Series: Labels don't overlap

---

## Key Differences from Previous Version

| Aspect | Before | After |
|--------|--------|-------|
| **Calculation** | RELEASE - BUILD | BUILD - RELEASE |
| **Left side** | After release (+) | Before release (-) |
| **Right side** | Before release (-) | After release (+) |
| **Release position** | Left (x=0) | Right (x=0) |
| **Time Series display** | Always visible | Dropdown selection |
| **Time Series bins** | Days histogram | Monthly bars |
| **Release markers** | None | Vertical lines with labels |
