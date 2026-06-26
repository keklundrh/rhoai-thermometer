# Container Freshness - Two Views

## Summary

Added two separate freshness visualization options to the Time Series View dropdown.

---

## View 1: Monthly Build Dates

**Dropdown Label:** "Container Freshness (View 1)"

**Chart Type:** Stacked bar chart with monthly bins

**X-Axis:** Calendar months (YYYY-MM)

**Features:**
- Bars show container build dates grouped by month
- Each color = one RHOAI release
- Vertical dashed lines mark each RHOAI release date
- Lines color-coded to match their release's bars

**Use Case:**
- See when containers were built on a calendar timeline
- Identify if releases cluster builds before/after release dates
- Compare build patterns across releases

**Info Text:**
> Container build dates are binned by month. Vertical dashed lines show when each RHOAI release was published. Bars to the left = containers built before release, bars to the right = containers built after release.

---

## View 2: Freshness Distribution (Days)

**Dropdown Label:** "Container Freshness (View 2)"

**Chart Type:** Stacked histogram

**X-Axis:** Days from release (negative = before, positive = after)

**Features:**
- Bins show how many days before/after release containers were built
- Each color = one RHOAI release (stacked)
- Single red vertical line at x=0 (release date)
- 50 bins for granular distribution

**Use Case:**
- See distribution of container ages relative to release
- Identify how far before/after release containers were built
- Compare age patterns across releases

**Info Text:**
> Stacked histogram showing container freshness in days. Negative values (left) = containers built BEFORE release. Positive values (right) = containers built AFTER release. Red vertical line marks the release date.

---

## Technical Implementation

### Data Loader Functions

**`get_freshness_data_by_release()`**
- Returns: `Tuple[Dict[str, pd.DataFrame], Dict[str, str]]`
- Data: Monthly bins with counts
- Used by: View 1

**`get_freshness_histogram_data()`**
- Returns: `Dict[str, np.ndarray]`
- Data: Freshness in days (raw values)
- Used by: View 2

### Chart Functions

**`create_freshness_stacked_chart()`**
- Input: Monthly binned data + release dates
- Output: Stacked bar chart
- Features: Multiple vertical lines (one per release)

**`create_freshness_histogram_stacked()`**
- Input: Freshness days by release
- Output: Stacked histogram
- Features: Single vertical line at x=0

### App Logic

```python
if metric_col == "freshness_monthly":
    # View 1: Monthly bins
    freshness_data, release_dates = get_freshness_data_by_release()
    fig = create_freshness_stacked_chart(freshness_data, release_dates)

elif metric_col == "freshness_histogram":
    # View 2: Days histogram
    freshness_data = get_freshness_histogram_data()
    fig = create_freshness_histogram_stacked(freshness_data)
```

---

## Files Modified

1. **`app/data_loader.py`**
   - Added `get_freshness_histogram_data()` function

2. **`app/utils.py`**
   - Added `create_freshness_histogram_stacked()` function

3. **`app/app.py`**
   - Renamed "Container Freshness" → "Container Freshness (View 1)"
   - Added "Container Freshness (View 2)" dropdown option
   - Updated imports to include new functions
   - Added conditional rendering for both views

4. **`app/DOCUMENTATION.md`**
   - Updated metrics table with both views
   - Added "Container Freshness Views" section
   - Documented both View 1 and View 2 separately

---

## User Workflow

1. Navigate to **Time Series View**
2. Select from dropdown:
   - "Container Freshness (View 1)" → See monthly calendar view
   - "Container Freshness (View 2)" → See days distribution histogram
3. Interpret based on info box guidance

---

## Key Differences

| Aspect | View 1 (Monthly) | View 2 (Histogram) |
|--------|------------------|-------------------|
| **X-Axis** | Calendar months | Days from release |
| **Bins** | Month boundaries | 50 equal bins |
| **Vertical Lines** | Multiple (one per release) | Single (at x=0) |
| **Chart Type** | Stacked bars | Stacked histogram |
| **Use Case** | Calendar timeline | Age distribution |
| **Granularity** | Monthly | Daily |

Both views show the same underlying data (container freshness) but from different analytical perspectives.
