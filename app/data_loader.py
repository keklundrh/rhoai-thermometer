"""Data loading and processing functions for RHOAI Thermometer dashboard."""

from pathlib import Path
from typing import List, Tuple, Dict
import pandas as pd
import numpy as np
import streamlit as st
from utils import parse_filename, sort_versions


# Check if running in container (data mounted at /data) or locally
if Path("/data").exists():
    DATA_DIR = Path("/data/summary")
else:
    DATA_DIR = Path(__file__).parent.parent / "data" / "summary"


@st.cache_data(ttl=300)
def get_min_cvss_score() -> float:
    """
    Calculate the minimum CVSS score across all data files.
    For each row, takes the maximum of (base-score, rel-base-score),
    then returns the minimum of those maximums.

    This reflects the OR logic: a CVE qualifies if EITHER score is high enough.

    Returns:
        Minimum qualifying CVSS score found across all releases (excluding "NA" values)
    """
    releases = get_available_releases()
    min_score = 10.0  # Start with max possible

    for rhoai_ver, ocp_ver, filepath in releases:
        try:
            df = load_release_data(filepath)
            if df.empty:
                continue

            # Convert to numeric, treating "NA" as NaN
            base_scores = pd.to_numeric(df['base-score'], errors='coerce')
            rel_scores = pd.to_numeric(df['rel-base-score'], errors='coerce')

            # For each row, take the max of the two scores (OR logic)
            max_per_row = pd.concat([base_scores, rel_scores], axis=1).max(axis=1)

            # Get the minimum of those maximums (excluding NaN)
            if max_per_row.notna().any():
                min_score = min(min_score, max_per_row.min())

        except Exception:
            continue

    # Round down to nearest 0.1 for cleaner slider values
    return round(min_score, 1) if min_score < 10.0 else 0.0


@st.cache_data(ttl=300)
def get_release_dates() -> Dict[str, str]:
    """
    Load release dates from rhoai-dates.csv.

    Returns:
        Dictionary mapping rhoai_version -> release_date (YYYY-MM-DD string)
    """
    # Check if running in container or locally
    if Path("/data").exists():
        dates_file = Path("/data/releases/rhoai-dates.csv")
    else:
        dates_file = Path(__file__).parent.parent / "data" / "releases" / "rhoai-dates.csv"

    if not dates_file.exists():
        return {}

    try:
        df = pd.read_csv(dates_file)
        return dict(zip(df['release'], df['GA-date']))
    except Exception:
        return {}


@st.cache_data(ttl=300)
def get_available_releases() -> List[Tuple[str, str, str]]:
    """
    Scan data/summary directory for RELEASE.tsv files.

    When multiple OCP versions exist for the same RHOAI version,
    only the highest OCP version is retained.

    Returns:
        List of tuples: [(rhoai_version, ocp_version, filepath), ...]
        Sorted chronologically by release date (from rhoai-dates.csv)
    """
    if not DATA_DIR.exists():
        st.error(f"Data directory not found: {DATA_DIR}")
        return []

    releases = {}  # Maps rhoai_version -> (ocp_version, filepath)

    for filepath in DATA_DIR.glob("*-RELEASE.tsv"):
        parsed = parse_filename(filepath.name)
        if parsed is None:
            continue

        ocp_ver, rhoai_ver = parsed

        # Keep only the highest OCP version for each RHOAI version
        if rhoai_ver not in releases or ocp_ver > releases[rhoai_ver][0]:
            releases[rhoai_ver] = (ocp_ver, str(filepath))

    # Convert to list
    result = [(rhoai, ocp, path) for rhoai, (ocp, path) in releases.items()]

    # Load release dates for chronological sorting
    release_dates = get_release_dates()

    # Sort by release date (chronologically)
    # If a version has no date in rhoai-dates.csv, fall back to semantic versioning
    def sort_key(item):
        rhoai_ver = item[0]
        if rhoai_ver in release_dates:
            return (0, release_dates[rhoai_ver])  # Sort by date first
        else:
            # Fallback: put versions without dates at the end, sorted semantically
            from packaging import version
            return (1, str(version.parse(rhoai_ver)))

    result.sort(key=sort_key)

    return result


@st.cache_data(ttl=300)
def load_release_data(filepath: str) -> pd.DataFrame:
    """
    Load a RELEASE.tsv file into a DataFrame.

    Args:
        filepath: Path to the TSV file

    Returns:
        DataFrame with CVE data
    """
    try:
        # TSV files have headers - use them
        df = pd.read_csv(filepath, sep='\t', header=0,
                        keep_default_na=False, na_values=[''])

        if len(df.columns) < 14:
            st.warning(f"File has fewer than 14 columns: {filepath}")

        return df
    except Exception as e:
        st.error(f"Error loading {filepath}: {e}")
        return pd.DataFrame()


def compute_release_metrics(df: pd.DataFrame, cvss_threshold: float = None, severity_filter: List[str] = None) -> Dict:
    """
    Compute summary metrics for a release.

    Args:
        df: DataFrame with CVE data
        cvss_threshold: Minimum CVSS score (applied to base-score OR rel-base-score)
        severity_filter: List of severity levels to include (OR logic)

    Returns:
        Dictionary with metrics (all metrics reflect CVEs discovered at or before release date, matching active filter):
        - total_cves: Total number of CVEs discovered at or before release, matching active filter
        - unique_cves: Number of distinct CVE IDs discovered at or before release, matching active filter
        - total_containers: Number of unique containers with at least one CVE at release, matching active filter
        - avg_cves_per_container: Mean CVEs per container (at release, matching active filter)
        - cves_per_container_dist: Array of CVE counts (for box plot)
        - pct_no_fix: Percentage of CVEs (at release, matching active filter) with no fix at release time
        - pct_with_fix: Percentage of CVEs (at release, matching active filter) with a fix at release time
        - cves_with_fix_at_release: Count of CVEs (at release, matching active filter) with fix at release
        - pct_fix_version_listed: % of CVEs with fix at release that have fix-version populated
        - severity_counts: Dict of severity -> count (unique CVEs at release, matching active filter)
        - freshness_score: Percentage of ALL containers built within 3 months (independent of CVE filters)
        - freshness_buckets: Container age distribution (independent of CVE filters)
        - top_containers: Top containers by CVE count (at release, matching active filter)
    """
    if df.empty:
        return {
            'total_cves': 0,
            'unique_cves': 0,
            'total_containers': 0,
            'avg_cves_per_container': 0,
            'cves_per_container_dist': [],
            'dist_stats': {'count': 0, 'min': 0, 'q1': 0, 'median': 0, 'mean': 0, 'q3': 0, 'max': 0, 'iqr': 0, 'std': 0},
            'top_containers': pd.DataFrame(columns=['Container Image', 'CVE Count']),
            'freshness_dist': [],
            'freshness_dates': [],
            'pct_no_fix': 0,
            'pct_with_fix': 0,
            'cves_with_fix_at_release': 0,
            'cves_with_fix_version_listed': 0,
            'pct_fix_version_listed': 0,
            'severity_counts': {},
            'pct_fix_before_build': 0,
            'pct_fix_after_build': 0,
            'avg_days_to_fix': 0,
            'fix_timeline_dist': [],
            'df_filtered': pd.DataFrame()
        }

    # FILTER 1: Only keep CVEs discovered at or before release date
    # (DISCOVERY_DATE <= RELEASE_DATE)
    # Excludes CVEs with unparseable discovery dates like NO-RH-VEX (we can't confirm they existed at release)
    # This time-based filter is ALWAYS applied - all metrics reflect "CVEs at release"
    df_filtered = df.copy()
    df_filtered['DISCOVERY_DATE_dt'] = pd.to_datetime(df_filtered['DISCOVERY_DATE'], errors='coerce')
    df_filtered['RELEASE_DATE_dt'] = pd.to_datetime(df_filtered['RELEASE_DATE'], errors='coerce')

    # Keep only CVEs with valid dates that were discovered before or on release date
    mask_valid_dates = df_filtered['DISCOVERY_DATE_dt'].notna() & df_filtered['RELEASE_DATE_dt'].notna()
    mask_discovered_at_or_before_release = df_filtered['DISCOVERY_DATE_dt'] <= df_filtered['RELEASE_DATE_dt']

    df_filtered = df_filtered[mask_valid_dates & mask_discovered_at_or_before_release]

    # FILTER 2: Apply active user filter (CVSS or Severity)
    # This filter is OPTIONAL - applied on top of the time-based filter above
    if cvss_threshold is not None:
        # CVSS filter: base-score OR rel-base-score >= threshold
        # Convert score columns to numeric, treating "NA" as NaN
        df_filtered['base-score-num'] = pd.to_numeric(df_filtered['base-score'], errors='coerce')
        df_filtered['rel-base-score-num'] = pd.to_numeric(df_filtered['rel-base-score'], errors='coerce')

        # Include if EITHER score >= threshold
        mask_cvss = (df_filtered['base-score-num'] >= cvss_threshold) | (df_filtered['rel-base-score-num'] >= cvss_threshold)
        df_filtered = df_filtered[mask_cvss]

    elif severity_filter is not None and len(severity_filter) > 0:
        # Severity filter: include CVEs matching any selected severity (OR logic)
        df_filtered = df_filtered[df_filtered['severity'].isin(severity_filter)]

    if df_filtered.empty:
        return {
            'total_cves': 0,
            'unique_cves': 0,
            'total_containers': 0,
            'avg_cves_per_container': 0,
            'cves_per_container_dist': [],
            'dist_stats': {'count': 0, 'min': 0, 'q1': 0, 'median': 0, 'mean': 0, 'q3': 0, 'max': 0, 'iqr': 0, 'std': 0},
            'top_containers': pd.DataFrame(columns=['Container Image', 'CVE Count']),
            'freshness_dist': [],
            'freshness_dates': [],
            'freshness_score': 0,
            'freshness_buckets': {'excellent': 0, 'good': 0, 'fair': 0, 'old': 0, 'stale': 0},
            'pct_no_fix': 0,
            'pct_with_fix': 0,
            'cves_with_fix_at_release': 0,
            'cves_with_fix_version_listed': 0,
            'pct_fix_version_listed': 0,
            'severity_counts': {},
            'pct_fix_before_build': 0,
            'pct_fix_after_build': 0,
            'avg_days_to_fix': 0,
            'fix_timeline_dist': [],
            'df_filtered': pd.DataFrame()
        }

    # Total CVEs (discovered at or before release, matching active filter)
    total_cves = len(df_filtered)

    # Total unique CVEs (distinct CVE IDs discovered at or before release, matching active filter)
    unique_cves = df_filtered['id'].nunique()

    # Total unique containers (containers with at least one CVE discovered at or before release, matching active filter)
    total_containers = df_filtered['SHA'].nunique()

    # CVEs per container (CVEs discovered at or before release, matching active filter, grouped by container)
    cves_per_container = df_filtered.groupby('SHA').size()
    avg_cves_per_container = cves_per_container.mean()
    cves_per_container_dist = cves_per_container.values

    # Calculate distribution statistics (unique containers by SHA that have CVEs)
    if len(cves_per_container_dist) > 0:
        dist_stats = {
            'count': len(cves_per_container_dist),
            'min': np.min(cves_per_container_dist),
            'q1': np.percentile(cves_per_container_dist, 25),
            'median': np.median(cves_per_container_dist),
            'mean': np.mean(cves_per_container_dist),
            'q3': np.percentile(cves_per_container_dist, 75),
            'max': np.max(cves_per_container_dist),
            'iqr': np.percentile(cves_per_container_dist, 75) - np.percentile(cves_per_container_dist, 25),
            'std': np.std(cves_per_container_dist)
        }
    else:
        dist_stats = {
            'count': 0,
            'min': 0,
            'q1': 0,
            'median': 0,
            'mean': 0,
            'q3': 0,
            'max': 0,
            'iqr': 0,
            'std': 0
        }

    # Top 5 containers by CVE count (using SHA, then get the IMAGE name for display)
    top_shas = cves_per_container.sort_values(ascending=False).head(5)

    # Map SHAs to IMAGE names for display
    sha_to_image = df_filtered.groupby('SHA')['IMAGE'].first()
    top_containers = pd.DataFrame({
        'Container Image': top_shas.index.map(sha_to_image),
        'CVE Count': top_shas.values
    })

    # Container Freshness Analysis
    # NOTE: Freshness is calculated from ALL containers in the release, independent of CVE filters
    # This metric reflects the age of containers at release time, regardless of which CVEs they contain
    df_freshness = df[df['container-build-date'] != 'W'].copy()
    df_freshness['container-build-date_dt'] = pd.to_datetime(df_freshness['container-build-date'], errors='coerce')
    df_freshness['RELEASE_DATE_dt'] = pd.to_datetime(df_freshness['RELEASE_DATE'], errors='coerce')

    # Freshness = container-build-date - RELEASE_DATE (negative = before release, positive = after release)
    df_freshness['freshness_days'] = (df_freshness['container-build-date_dt'] - df_freshness['RELEASE_DATE_dt']).dt.days

    # Get unique containers with their freshness (one entry per SHA)
    freshness_per_container = df_freshness.groupby('SHA')[['freshness_days', 'container-build-date_dt']].first().dropna()
    freshness_dist = freshness_per_container['freshness_days'].values
    freshness_dates = freshness_per_container['container-build-date_dt'].values

    # Calculate Container Age (how old containers are AT release date)
    # Age = RELEASE_DATE - container-build-date (positive = built before release)
    df_freshness['container_age_days'] = (df_freshness['RELEASE_DATE_dt'] - df_freshness['container-build-date_dt']).dt.days

    # Get unique containers with their age (one entry per SHA)
    age_per_container = df_freshness.groupby('SHA')['container_age_days'].first().dropna()

    # Calculate freshness score buckets (based on container age at release)
    total_aged_containers = len(age_per_container)
    if total_aged_containers > 0:
        excellent_count = (age_per_container <= 30).sum()   # 0-1 month
        good_count = ((age_per_container > 30) & (age_per_container <= 90)).sum()   # 1-3 months
        fair_count = ((age_per_container > 90) & (age_per_container <= 180)).sum()  # 3-6 months
        old_count = ((age_per_container > 180) & (age_per_container <= 365)).sum()  # 6-12 months
        stale_count = (age_per_container > 365).sum()  # 12+ months

        freshness_score = (excellent_count / total_aged_containers * 100)
        freshness_buckets = {
            'excellent': excellent_count,
            'good': good_count,
            'fair': fair_count,
            'old': old_count,
            'stale': stale_count
        }
    else:
        freshness_score = 0
        freshness_buckets = {'excellent': 0, 'good': 0, 'fair': 0, 'old': 0, 'stale': 0}

    # Fix status AT RELEASE TIME
    # NO fix at release = (FIX_DATE > RELEASE_DATE) OR (FIX_DATE == 'NO-RH-VEX') OR (FIX_DATE == 'NOT-FOUND')
    # HAS fix at release = (FIX_DATE <= RELEASE_DATE AND FIX_DATE is a valid date)

    df_filtered['FIX_DATE_dt'] = pd.to_datetime(df_filtered['FIX_DATE'], errors='coerce')

    # CVEs with NO fix at release time
    mask_no_vex = df_filtered['FIX_DATE'] == 'NO-RH-VEX'
    mask_not_found = df_filtered['FIX_DATE'] == 'NOT-FOUND'
    mask_fix_after_release = (df_filtered['FIX_DATE_dt'].notna() &
                               df_filtered['RELEASE_DATE_dt'].notna() &
                               (df_filtered['FIX_DATE_dt'] > df_filtered['RELEASE_DATE_dt']))

    no_fix_count = (mask_no_vex | mask_not_found | mask_fix_after_release).sum()

    pct_no_fix = (no_fix_count / total_cves * 100) if total_cves > 0 else 0
    pct_with_fix = 100 - pct_no_fix

    # CVEs with fix available at release (FIX_DATE <= RELEASE_DATE AND is a valid date)
    mask_fix_date_at_release = (df_filtered['FIX_DATE_dt'].notna() &
                                 df_filtered['RELEASE_DATE_dt'].notna() &
                                 (df_filtered['FIX_DATE_dt'] <= df_filtered['RELEASE_DATE_dt']))

    mask_has_fix_version = (df_filtered['fix-version'].notna() &
                            (df_filtered['fix-version'] != 'None') &
                            (df_filtered['fix-version'] != 'NA') &
                            (df_filtered['fix-version'] != ''))

    # CVEs with fix date at release (regardless of fix-version field)
    cves_with_fix_at_release = mask_fix_date_at_release.sum()

    # For the breakdown: use the same denominator as "% CVEs with Fix at Release"
    # which is total_cves - no_fix_count (updated to use consistent denominator)
    cves_counted_as_with_fix = total_cves - no_fix_count
    cves_with_fix_version_listed = (mask_fix_date_at_release & mask_has_fix_version).sum()
    pct_fix_version_listed = (cves_with_fix_version_listed / cves_counted_as_with_fix * 100) if cves_counted_as_with_fix > 0 else 0

    # Severity distribution (unique CVEs discovered at or before release, matching active filter)
    # Drop duplicates by CVE ID to count each unique CVE once
    severity_counts = df_filtered.drop_duplicates(subset='id')['severity'].value_counts().to_dict()

    # Fix timeline analysis (relative to RELEASE_DATE, not container build date)
    # Use filtered data
    df_timeline = df_filtered[df_filtered['FIX_DATE'] != 'NO-RH-VEX'].copy()

    if len(df_timeline) > 0:
        # Dates already parsed above, reuse
        df_timeline['days_diff'] = (df_timeline['FIX_DATE_dt'] - df_timeline['RELEASE_DATE_dt']).dt.days

        # Remove any NaT values
        df_timeline = df_timeline.dropna(subset=['days_diff'])

        fix_before = (df_timeline['days_diff'] < 0).sum()
        fix_after = (df_timeline['days_diff'] > 0).sum()

        pct_fix_before_build = (fix_before / len(df_timeline) * 100) if len(df_timeline) > 0 else 0
        pct_fix_after_build = (fix_after / len(df_timeline) * 100) if len(df_timeline) > 0 else 0

        # Average days to fix (only for fixes that came after)
        after_df = df_timeline[df_timeline['days_diff'] > 0]
        avg_days_to_fix = after_df['days_diff'].mean() if len(after_df) > 0 else 0

        fix_timeline_dist = df_timeline['days_diff'].values
    else:
        pct_fix_before_build = 0
        pct_fix_after_build = 0
        avg_days_to_fix = 0
        fix_timeline_dist = []

    return {
        'total_cves': total_cves,
        'unique_cves': unique_cves,
        'total_containers': total_containers,
        'avg_cves_per_container': avg_cves_per_container,
        'cves_per_container_dist': cves_per_container_dist,
        'dist_stats': dist_stats,
        'top_containers': top_containers,
        'freshness_dist': freshness_dist,
        'freshness_dates': freshness_dates,
        'freshness_score': freshness_score,
        'freshness_buckets': freshness_buckets,
        'pct_no_fix': pct_no_fix,
        'pct_with_fix': pct_with_fix,
        'cves_with_fix_at_release': cves_with_fix_at_release,
        'cves_with_fix_version_listed': cves_with_fix_version_listed,
        'pct_fix_version_listed': pct_fix_version_listed,
        'severity_counts': severity_counts,
        'pct_fix_before_build': pct_fix_before_build,
        'pct_fix_after_build': pct_fix_after_build,
        'avg_days_to_fix': avg_days_to_fix,
        'fix_timeline_dist': fix_timeline_dist,
        'df_filtered': df_filtered
    }


@st.cache_data(ttl=300)
def get_time_series_data(cvss_threshold: float = None, severity_filter: tuple = None) -> pd.DataFrame:
    """
    Load all releases and compute metrics for time series visualization.

    Args:
        cvss_threshold: Minimum CVSS score filter
        severity_filter: Tuple of severity levels to include (tuple for caching)

    Returns:
        DataFrame with columns:
        - rhoai_version
        - total_cves
        - unique_cves
        - total_containers
        - avg_cves_per_container
        - pct_no_fix
        - pct_with_fix
        - freshness_score
    """
    releases = get_available_releases()

    # Convert tuple back to list for processing
    severity_list = list(severity_filter) if severity_filter else None

    data = []
    for rhoai_ver, ocp_ver, filepath in releases:
        df = load_release_data(filepath)
        metrics = compute_release_metrics(df, cvss_threshold=cvss_threshold, severity_filter=severity_list)

        data.append({
            'rhoai_version': rhoai_ver,
            'total_cves': metrics['total_cves'],
            'unique_cves': metrics['unique_cves'],
            'total_containers': metrics['total_containers'],
            'avg_cves_per_container': metrics['avg_cves_per_container'],
            'cves_with_fix_at_release': metrics['cves_with_fix_at_release'],
            'pct_no_fix': metrics['pct_no_fix'],
            'pct_with_fix': metrics['pct_with_fix'],
            'pct_fix_version_listed': metrics['pct_fix_version_listed'],
            'freshness_score': metrics['freshness_score']
        })

    return pd.DataFrame(data)


@st.cache_data(ttl=300)
def get_freshness_data_by_release() -> Tuple[Dict[str, pd.DataFrame], Dict[str, str]]:
    """
    Load freshness data for all releases, binned by month.

    Returns:
        Tuple of (freshness_data, release_dates)
        - freshness_data: Dict mapping rhoai_version -> DataFrame with columns [month, count]
        - release_dates: Dict mapping rhoai_version -> release_date string
    """
    import numpy as np

    releases = get_available_releases()
    freshness_data = {}
    release_dates = {}

    for rhoai_ver, ocp_ver, filepath in releases:
        df = load_release_data(filepath)

        # Calculate freshness for this release
        df_freshness = df[df['container-build-date'] != 'W'].copy()
        df_freshness['container-build-date_dt'] = pd.to_datetime(df_freshness['container-build-date'], errors='coerce')
        df_freshness['RELEASE_DATE_dt'] = pd.to_datetime(df_freshness['RELEASE_DATE'], errors='coerce')

        # Store release date (convert Timestamp to datetime for Plotly compatibility)
        if not df_freshness.empty and df_freshness['RELEASE_DATE_dt'].notna().any():
            release_dates[rhoai_ver] = df_freshness['RELEASE_DATE_dt'].iloc[0].to_pydatetime()

        # Get unique containers with their build dates
        unique_containers = df_freshness.groupby('SHA')['container-build-date_dt'].first().dropna()

        if len(unique_containers) > 0:
            # Convert to month/year for binning
            monthly_data = unique_containers.dt.to_period('M').value_counts().sort_index()

            # Convert to DataFrame
            freshness_df = pd.DataFrame({
                'month': monthly_data.index.to_timestamp(),
                'count': monthly_data.values
            })

            freshness_data[rhoai_ver] = freshness_df

    return freshness_data, release_dates


@st.cache_data(ttl=300)
def get_freshness_histogram_data() -> Dict[str, np.ndarray]:
    """
    Load freshness data for all releases as days (for histogram view).

    Returns:
        Dictionary mapping rhoai_version -> array of freshness days
        Freshness = container-build-date - RELEASE_DATE
    """
    import numpy as np

    releases = get_available_releases()
    freshness_data = {}

    for rhoai_ver, ocp_ver, filepath in releases:
        df = load_release_data(filepath)

        # Calculate freshness for this release
        df_freshness = df[df['container-build-date'] != 'W'].copy()
        df_freshness['container-build-date_dt'] = pd.to_datetime(df_freshness['container-build-date'], errors='coerce')
        df_freshness['RELEASE_DATE_dt'] = pd.to_datetime(df_freshness['RELEASE_DATE'], errors='coerce')

        # Calculate freshness in days (negative = before release)
        df_freshness['freshness_days'] = (df_freshness['container-build-date_dt'] - df_freshness['RELEASE_DATE_dt']).dt.days

        # Get unique containers with their freshness
        unique_freshness = df_freshness.groupby('SHA')['freshness_days'].first().dropna()

        if len(unique_freshness) > 0:
            freshness_data[rhoai_ver] = unique_freshness.values

    return freshness_data
