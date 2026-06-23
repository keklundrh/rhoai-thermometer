"""Data loading and processing functions for RHOAI Thermometer dashboard."""

from pathlib import Path
from typing import List, Tuple, Dict
import pandas as pd
import streamlit as st
from utils import parse_filename, sort_versions


# Check if running in container (data mounted at /data) or locally
if Path("/data").exists():
    DATA_DIR = Path("/data/summary")
else:
    DATA_DIR = Path(__file__).parent.parent / "data" / "summary"


@st.cache_data(ttl=300)
def get_available_releases() -> List[Tuple[str, str, str]]:
    """
    Scan data/summary directory for RELEASE.tsv files.

    When multiple OCP versions exist for the same RHOAI version,
    only the highest OCP version is retained.

    Returns:
        List of tuples: [(rhoai_version, ocp_version, filepath), ...]
        Sorted by RHOAI version (semantic ordering)
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

    # Convert to list and sort by RHOAI version
    result = [(rhoai, ocp, path) for rhoai, (ocp, path) in releases.items()]
    result.sort(key=lambda x: x[0], reverse=False)  # Will be sorted by sort_versions later

    # Sort by semantic versioning
    rhoai_versions = [r[0] for r in result]
    sorted_versions = sort_versions(rhoai_versions)

    # Rebuild result in sorted order
    version_to_data = {r[0]: r for r in result}
    sorted_result = [version_to_data[v] for v in sorted_versions]

    return sorted_result


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

        if len(df.columns) < 15:
            st.warning(f"File has fewer than 15 columns: {filepath}")

        return df
    except Exception as e:
        st.error(f"Error loading {filepath}: {e}")
        return pd.DataFrame()


def compute_release_metrics(df: pd.DataFrame) -> Dict:
    """
    Compute summary metrics for a release.

    Args:
        df: DataFrame with CVE data

    Returns:
        Dictionary with metrics:
        - total_cves: Total number of CVEs that existed at release time
        - total_containers: Number of unique containers
        - avg_cves_per_container: Mean CVEs per container
        - cves_per_container_dist: Array of CVE counts (for box plot)
        - pct_no_fix: Percentage of CVEs with no fix at release time
        - pct_with_fix: Percentage of CVEs with a fix at release time
        - severity_counts: Dict of severity -> count
        - pct_fix_before_build: % CVEs where fix existed before container build
        - pct_fix_after_build: % CVEs where fix came after container build
        - avg_days_to_fix: Average days from build to fix (for fixes after build)
        - fix_timeline_dist: Array of days differences (for distribution chart)
    """
    if df.empty:
        return {
            'total_cves': 0,
            'unique_cves': 0,
            'total_containers': 0,
            'avg_cves_per_container': 0,
            'cves_per_container_dist': [],
            'top_containers': pd.DataFrame(columns=['Container Image', 'CVE Count']),
            'pct_no_fix': 0,
            'pct_with_fix': 0,
            'severity_counts': {},
            'pct_fix_before_build': 0,
            'pct_fix_after_build': 0,
            'avg_days_to_fix': 0,
            'fix_timeline_dist': []
        }

    # FILTER: Only keep CVEs that existed at release time
    # (DISCOVERY_DATE <= RELEASE_DATE)
    # Excludes NO-RH-VEX and other unparseable dates (we can't confirm they existed at release)
    df_filtered = df.copy()
    df_filtered['DISCOVERY_DATE_dt'] = pd.to_datetime(df_filtered['DISCOVERY_DATE'], errors='coerce')
    df_filtered['RELEASE_DATE_dt'] = pd.to_datetime(df_filtered['RELEASE_DATE'], errors='coerce')

    # Keep only CVEs with valid dates that were discovered before or on release date
    mask_valid_dates = df_filtered['DISCOVERY_DATE_dt'].notna() & df_filtered['RELEASE_DATE_dt'].notna()
    mask_discovered_at_or_before_release = df_filtered['DISCOVERY_DATE_dt'] <= df_filtered['RELEASE_DATE_dt']

    df_filtered = df_filtered[mask_valid_dates & mask_discovered_at_or_before_release]

    if df_filtered.empty:
        return {
            'total_cves': 0,
            'unique_cves': 0,
            'total_containers': 0,
            'avg_cves_per_container': 0,
            'cves_per_container_dist': [],
            'top_containers': pd.DataFrame(columns=['Container Image', 'CVE Count']),
            'pct_no_fix': 0,
            'pct_with_fix': 0,
            'severity_counts': {},
            'pct_fix_before_build': 0,
            'pct_fix_after_build': 0,
            'avg_days_to_fix': 0,
            'fix_timeline_dist': []
        }

    # Total CVEs (after filtering)
    total_cves = len(df_filtered)

    # Total unique CVEs (count unique CVE IDs from filtered set)
    unique_cves = df_filtered['id'].nunique()

    # Total unique containers (count unique SHAs from original df)
    total_containers = df['SHA'].nunique()

    # CVEs per container (using filtered CVEs)
    cves_per_container = df_filtered.groupby('IMAGE').size()
    avg_cves_per_container = cves_per_container.mean()
    cves_per_container_dist = cves_per_container.values

    # Top 5 containers by CVE count
    top_containers = cves_per_container.sort_values(ascending=False).head(5).reset_index()
    top_containers.columns = ['Container Image', 'CVE Count']

    # Fix status AT RELEASE TIME
    # NO fix at release = (FIX_DATE > RELEASE_DATE) OR (FIX_DATE == 'NO-RH-VEX')
    # HAS fix at release = (FIX_DATE < RELEASE_DATE)

    df_filtered['FIX_DATE_dt'] = pd.to_datetime(df_filtered['FIX_DATE'], errors='coerce')

    # CVEs with NO fix at release time
    mask_no_vex = df_filtered['FIX_DATE'] == 'NO-RH-VEX'
    mask_fix_after_release = (df_filtered['FIX_DATE_dt'].notna() &
                               df_filtered['RELEASE_DATE_dt'].notna() &
                               (df_filtered['FIX_DATE_dt'] > df_filtered['RELEASE_DATE_dt']))

    no_fix_count = (mask_no_vex | mask_fix_after_release).sum()

    pct_no_fix = (no_fix_count / total_cves * 100) if total_cves > 0 else 0
    pct_with_fix = 100 - pct_no_fix

    # Severity distribution (from filtered data)
    severity_counts = df_filtered['severity'].value_counts().to_dict()

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
        'top_containers': top_containers,
        'pct_no_fix': pct_no_fix,
        'pct_with_fix': pct_with_fix,
        'severity_counts': severity_counts,
        'pct_fix_before_build': pct_fix_before_build,
        'pct_fix_after_build': pct_fix_after_build,
        'avg_days_to_fix': avg_days_to_fix,
        'fix_timeline_dist': fix_timeline_dist
    }


@st.cache_data(ttl=300)
def get_time_series_data() -> pd.DataFrame:
    """
    Load all releases and compute metrics for time series visualization.

    Returns:
        DataFrame with columns:
        - rhoai_version
        - total_cves
        - unique_cves
        - total_containers
        - avg_cves_per_container
        - pct_no_fix
        - pct_with_fix
    """
    releases = get_available_releases()

    data = []
    for rhoai_ver, ocp_ver, filepath in releases:
        df = load_release_data(filepath)
        metrics = compute_release_metrics(df)

        data.append({
            'rhoai_version': rhoai_ver,
            'total_cves': metrics['total_cves'],
            'unique_cves': metrics['unique_cves'],
            'total_containers': metrics['total_containers'],
            'avg_cves_per_container': metrics['avg_cves_per_container'],
            'pct_no_fix': metrics['pct_no_fix'],
            'pct_with_fix': metrics['pct_with_fix']
        })

    return pd.DataFrame(data)
