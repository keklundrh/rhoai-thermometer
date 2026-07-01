"""RHOAI Thermometer - CVE Security Dashboard

A Streamlit dashboard for analyzing CVE vulnerabilities in RHOAI container images.
"""

import streamlit as st
import pandas as pd
from data_loader import get_available_releases, load_release_data, compute_release_metrics, get_time_series_data, get_freshness_data_by_release, get_freshness_histogram_data, get_min_cvss_score
from utils import create_severity_chart, create_time_series_chart, create_freshness_chart, create_freshness_stacked_chart, create_freshness_histogram_stacked


# Page configuration
st.set_page_config(
    page_title="Red Hat OpenShift AI - Security Thermometer",
    page_icon="🔴",
    layout="wide"
)

# Red Hat brand colors
RED_HAT_RED = "#EE0000"
RED_HAT_DARK = "#151515"

# Custom CSS for Red Hat branding
st.markdown(f"""
    <style>
    /* Red Hat color accents */
    .stMetric {{
        background-color: #f8f8f8;
        padding: 10px;
        border-radius: 5px;
        border-left: 4px solid {RED_HAT_RED};
    }}
    h1 {{
        color: {RED_HAT_DARK};
        border-bottom: 3px solid {RED_HAT_RED};
        padding-bottom: 10px;
    }}
    h2 {{
        color: {RED_HAT_DARK};
        margin-top: 20px;
    }}
    .stProgress > div > div > div {{
        background-color: {RED_HAT_RED};
    }}
    </style>
    """, unsafe_allow_html=True)

# Title with Red Hat branding
st.title("🔴 Red Hat OpenShift AI - Security Thermometer")
st.markdown("**CVE Vulnerability Analysis Dashboard** | Red Hat OpenShift AI Releases")

# Sidebar - Filtering Section
st.sidebar.header("🔍 Filters")

# Calculate dynamic minimum CVSS across all data files
min_cvss = get_min_cvss_score()
# Default is 8.0 or the minimum value, whichever is greater
default_cvss = max(8.0, min_cvss)

# Filter type selector
filter_type = st.sidebar.radio(
    "Filter By",
    ["CVSS Score", "Severity"],
    help="Choose to filter by CVSS score threshold or severity level"
)

if filter_type == "CVSS Score":
    cvss_threshold = st.sidebar.slider(
        "Minimum CVSS Score",
        min_value=min_cvss,
        max_value=10.0,
        value=default_cvss,
        step=0.1,
        help=f"Include CVEs where base-score OR rel-base-score >= this value (data range: {min_cvss:.1f}-10.0)"
    )
    # Allow text input override
    cvss_text_input = st.sidebar.number_input(
        "Or enter exact value",
        min_value=min_cvss,
        max_value=10.0,
        value=cvss_threshold,
        step=0.1
    )
    cvss_threshold = cvss_text_input
    severity_filter = None
else:  # Severity
    severity_filter = st.sidebar.multiselect(
        "Select Severity Levels",
        options=["Critical", "High", "Medium", "Low"],
        default=["Critical", "High"],
        help="Include CVEs matching any selected severity (OR logic)"
    )
    cvss_threshold = None

st.sidebar.markdown("---")

# Sidebar - View selector
view_options = ["Release View", "Time Series View", "Documentation"]

# Initialize session state from query params on first load
query_params = st.query_params
if 'view' not in st.session_state:
    default_view = query_params.get("view", "Release View")
    if default_view not in view_options:
        default_view = "Release View"
    st.session_state.view = default_view

current_index = view_options.index(st.session_state.view)

def update_view():
    st.session_state.view = st.session_state.view_radio
    st.query_params["view"] = st.session_state.view

view = st.sidebar.radio(
    "Select View",
    view_options,
    index=current_index,
    help="Choose between single release analysis, trends over time, or documentation",
    key="view_radio",
    on_change=update_view
)

# Load available releases
releases = get_available_releases()

if not releases:
    st.error("No RELEASE.tsv files found in data/summary/")
    st.stop()


# ===== RELEASE VIEW =====
if view == "Release View":
    st.markdown(f"<h2 style='color: {RED_HAT_DARK};'>📊 Release Analysis</h2>", unsafe_allow_html=True)

    # Show active filter with Red Hat styling
    if cvss_threshold is not None:
        st.markdown(f"""
            <div style='background-color: #fff5f5; border-left: 4px solid {RED_HAT_RED}; padding: 10px; margin-bottom: 20px; border-radius: 5px;'>
                <strong style='color: {RED_HAT_RED};'>🔍 Active Filter:</strong> CVSS Score ≥ {cvss_threshold}
            </div>
        """, unsafe_allow_html=True)
    elif severity_filter:
        st.markdown(f"""
            <div style='background-color: #fff5f5; border-left: 4px solid {RED_HAT_RED}; padding: 10px; margin-bottom: 20px; border-radius: 5px;'>
                <strong style='color: {RED_HAT_RED};'>🔍 Active Filter:</strong> Severity = {', '.join(severity_filter)}
            </div>
        """, unsafe_allow_html=True)

    # Release selector
    release_options = {f"RHOAI {rhoai} (OCP {ocp})": (rhoai, ocp, path)
                      for rhoai, ocp, path in releases}

    # Initialize session state from query params on first load
    if 'release' not in st.session_state:
        default_release = query_params.get("release", list(release_options.keys())[0])
        if default_release not in release_options:
            default_release = list(release_options.keys())[0]
        st.session_state.release = default_release

    default_index = list(release_options.keys()).index(st.session_state.release)

    def update_release():
        st.session_state.release = st.session_state.release_selector
        st.query_params["release"] = st.session_state.release

    selected = st.selectbox(
        "Select RHOAI Release",
        options=list(release_options.keys()),
        index=default_index,
        help="Choose a RHOAI release to analyze",
        key="release_selector",
        on_change=update_release
    )

    rhoai_ver, ocp_ver, filepath = release_options[selected]

    # Load data
    with st.spinner(f"Loading data for RHOAI {rhoai_ver}..."):
        df = load_release_data(filepath)
        metrics = compute_release_metrics(df, cvss_threshold=cvss_threshold, severity_filter=severity_filter)

    # Display metrics
    st.subheader("Summary Metrics")

    # Row 1: Count metrics
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.metric(
            label="Total CVEs at Release",
            value=f"{metrics['total_cves']:,}",
            help="High/critical CVEs discovered at or before RHOAI release (DISCOVERY_DATE <= RELEASE_DATE). Excludes NO-RH-VEX entries."
        )

    with col2:
        st.metric(
            label="CVEs with RH Fix Available at Release",
            value=f"{metrics['cves_with_fix_at_release']:,}",
            help="CVEs where a fix existed somewhere in the Red Hat ecosystem at release date (FIX_DATE <= RELEASE_DATE) with fix-version listed. Note: Fix availability doesn't guarantee the fix was deployed in RHOAI containers - that depends on container rebuild cycles."
        )

    with col3:
        st.metric(
            label="Unique CVEs",
            value=f"{metrics['unique_cves']:,}",
            help="Number of distinct CVE IDs (same CVE may appear in multiple containers)"
        )

    with col4:
        st.metric(
            label="Number of Containers with CVEs",
            value=f"{metrics['total_containers']:,}",
            help="Number of unique container images with at least one CVE"
        )

    with col5:
        st.metric(
            label="Avg CVEs per Container",
            value=f"{metrics['avg_cves_per_container']:.1f}",
            help="Mean number of CVEs across all containers"
        )

    # Row 2: Fix status metrics AT RELEASE TIME
    st.subheader("Fix Availability at Release")
    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            label="% CVEs with No Fix at Release",
            value=f"{metrics['pct_no_fix']:.1f}%",
            help="CVEs where no fix existed at RHOAI release date (FIX_DATE > RELEASE_DATE or NO-RH-VEX)"
        )
        st.progress(metrics['pct_no_fix'] / 100)

    with col2:
        st.metric(
            label="% CVEs with Fix at Release",
            value=f"{metrics['pct_with_fix']:.1f}%",
            help="CVEs where a fix already existed at RHOAI release date (FIX_DATE <= RELEASE_DATE). A fix is available but may or may not be available through Red Hat - it could be upstream or in other ecosystems."
        )
        st.progress(metrics['pct_with_fix'] / 100)

    with col3:
        st.metric(
            label="% with RH Fix Version",
            value=f"{metrics['pct_fix_version_listed']:.1f}%",
            help=f"Of the {metrics['pct_with_fix']:.1f}% CVEs with fix at release, this percentage has the fix-version field populated in VEX data. This indicates Red Hat tracked a specific package version containing the fix - applicability to specific build needs further investigation."
        )
        st.progress(metrics['pct_fix_version_listed'] / 100)

    # Charts
    st.subheader("Distribution Analysis")

    col1, col2 = st.columns(2)

    with col1:
        # CVE Distribution Statistics Table
        st.markdown("**CVE Distribution Across Containers**")
        if metrics['dist_stats']['count'] > 0:
            stats_df = pd.DataFrame([
                {"Statistic": "Containers with CVEs Count", "Value": f"{metrics['dist_stats']['count']:,}"},
                {"Statistic": "Minimum", "Value": f"{metrics['dist_stats']['min']:.0f}"},
                {"Statistic": "25th Percentile (Q1)", "Value": f"{metrics['dist_stats']['q1']:.1f}"},
                {"Statistic": "Median", "Value": f"{metrics['dist_stats']['median']:.1f}"},
                {"Statistic": "Mean", "Value": f"{metrics['dist_stats']['mean']:.1f}"},
                {"Statistic": "75th Percentile (Q3)", "Value": f"{metrics['dist_stats']['q3']:.1f}"},
                {"Statistic": "Maximum", "Value": f"{metrics['dist_stats']['max']:.0f}"},
                {"Statistic": "IQR (Q3 - Q1)", "Value": f"{metrics['dist_stats']['iqr']:.1f}"},
                {"Statistic": "Std Deviation", "Value": f"{metrics['dist_stats']['std']:.1f}"},
            ])
            st.dataframe(
                stats_df,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Statistic": st.column_config.TextColumn("Statistic", width="medium"),
                    "Value": st.column_config.TextColumn("CVEs per Container", width="medium")
                }
            )
        else:
            st.warning("No distribution data available")

    with col2:
        # Severity chart
        if metrics['severity_counts']:
            fig_severity = create_severity_chart(metrics['severity_counts'])
            st.plotly_chart(fig_severity, use_container_width=True)
        else:
            st.warning("No severity data available")

    # Freshness chart (full width)
    if len(metrics['freshness_dist']) > 0:
        # Get release date from the dataframe
        release_date = df['RELEASE_DATE'].iloc[0] if not df.empty else "Unknown"
        fig_freshness = create_freshness_chart(
            metrics['freshness_dist'],
            metrics['freshness_dates'],
            release_date
        )
        st.plotly_chart(fig_freshness, use_container_width=True)
    else:
        st.warning("No freshness data available")

    # Top Containers by CVE Count
    st.subheader("Top 5 Containers by CVE Count")

    if not metrics['top_containers'].empty:
        st.dataframe(
            metrics['top_containers'],
            use_container_width=True,
            hide_index=True,
            column_config={
                "Container Image": st.column_config.TextColumn(
                    "Container Image",
                    width="large"
                ),
                "CVE Count": st.column_config.NumberColumn(
                    "CVE Count",
                    format="%d"
                )
            }
        )
    else:
        st.warning("No container data available")

    # Additional info
    with st.expander("📊 View Raw Data (CVEs discovered before or on release date)"):
        st.dataframe(metrics['df_filtered'], use_container_width=True)


# ===== TIME SERIES VIEW =====
elif view == "Time Series View":
    st.markdown(f"<h2 style='color: {RED_HAT_DARK};'>📈 Time Series Analysis</h2>", unsafe_allow_html=True)

    # Show active filter with Red Hat styling
    if cvss_threshold is not None:
        st.markdown(f"""
            <div style='background-color: #fff5f5; border-left: 4px solid {RED_HAT_RED}; padding: 10px; margin-bottom: 20px; border-radius: 5px;'>
                <strong style='color: {RED_HAT_RED};'>🔍 Active Filter:</strong> CVSS Score ≥ {cvss_threshold}
            </div>
        """, unsafe_allow_html=True)
    elif severity_filter:
        st.markdown(f"""
            <div style='background-color: #fff5f5; border-left: 4px solid {RED_HAT_RED}; padding: 10px; margin-bottom: 20px; border-radius: 5px;'>
                <strong style='color: {RED_HAT_RED};'>🔍 Active Filter:</strong> Severity = {', '.join(severity_filter)}
            </div>
        """, unsafe_allow_html=True)

    # Metric selector
    metric_options = {
        "Total CVEs at Release": "total_cves",
        "CVEs with RH Fix Available at Release": "cves_with_fix_at_release",
        "Unique CVEs": "unique_cves",
        "Number of Containers with CVEs": "total_containers",
        "Avg CVEs per Container": "avg_cves_per_container",
        "% CVEs with No Fix at Release": "pct_no_fix",
        "% CVEs with Fix at Release": "pct_with_fix",
        "% with RH Fix Version": "pct_fix_version_listed",
        "Container Freshness (View 1)": "freshness_monthly",
        "Container Freshness (View 2)": "freshness_histogram"
    }

    # Initialize session state from query params on first load
    if 'metric' not in st.session_state:
        default_metric = query_params.get("metric", list(metric_options.keys())[0])
        if default_metric not in metric_options:
            default_metric = list(metric_options.keys())[0]
        st.session_state.metric = default_metric

    default_metric_index = list(metric_options.keys()).index(st.session_state.metric)

    def update_metric():
        st.session_state.metric = st.session_state.metric_selector
        st.query_params["metric"] = st.session_state.metric

    selected_metric_label = st.selectbox(
        "Select Metric to Plot",
        options=list(metric_options.keys()),
        index=default_metric_index,
        help="Choose which metric to visualize over time",
        key="metric_selector",
        on_change=update_metric
    )

    metric_col = metric_options[selected_metric_label]

    # Load time series data (convert list to tuple for caching)
    with st.spinner("Loading time series data..."):
        severity_tuple = tuple(severity_filter) if severity_filter else None
        ts_data = get_time_series_data(cvss_threshold=cvss_threshold, severity_filter=severity_tuple)

    if ts_data.empty:
        st.error("No time series data available")
        st.stop()

    # Calculate consistent Y-axis ranges for percentage metrics only
    # Numeric metrics use automatic scaling due to large magnitude differences
    percentage_metrics = ['pct_no_fix', 'pct_with_fix', 'pct_fix_version_listed']

    if metric_col in percentage_metrics:
        # Get min/max across all percentage metrics for consistent axis
        y_min = ts_data[percentage_metrics].min().min()
        y_max = ts_data[percentage_metrics].max().max()
    else:
        # Numeric metrics use automatic Y-axis
        y_min = None
        y_max = None

    # Display chart based on selected metric
    if metric_col == "freshness_monthly":
        # View 1: Monthly binned freshness with release markers
        with st.spinner("Loading freshness data..."):
            freshness_data, release_dates = get_freshness_data_by_release()

        if freshness_data:
            fig_freshness = create_freshness_stacked_chart(freshness_data, release_dates)
            st.plotly_chart(fig_freshness, use_container_width=True)
            st.info(
                "📊 **View 1:** Container build dates are binned by month. "
                "Vertical dashed lines show when each RHOAI release was published. "
                "Bars to the left = containers built before release, bars to the right = containers built after release. "
                "Each color represents a different RHOAI release version."
            )
        else:
            st.warning("No freshness data available")

    elif metric_col == "freshness_histogram":
        # View 2: Stacked histogram by freshness days
        with st.spinner("Loading freshness data..."):
            freshness_data = get_freshness_histogram_data()

        if freshness_data:
            fig_freshness = create_freshness_histogram_stacked(freshness_data)
            st.plotly_chart(fig_freshness, use_container_width=True)
            st.info(
                "📊 **View 2:** Stacked histogram showing container freshness in days. "
                "Negative values (left) = containers built BEFORE release. "
                "Positive values (right) = containers built AFTER release. "
                "Red vertical line marks the release date. "
                "Each color represents a different RHOAI release version."
            )
        else:
            st.warning("No freshness data available")

    else:
        # Show regular time series chart
        fig = create_time_series_chart(ts_data, metric_col, selected_metric_label, y_min, y_max)
        st.plotly_chart(fig, use_container_width=True)

    # Show data table (only for non-freshness views)
    if metric_col not in ["freshness_monthly", "freshness_histogram"]:
        with st.expander("📊 View Time Series Data"):
            st.dataframe(ts_data, use_container_width=True)

        # Summary statistics
        st.subheader("Summary Statistics")
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("Min", f"{ts_data[metric_col].min():.2f}")

        with col2:
            st.metric("Max", f"{ts_data[metric_col].max():.2f}")

        with col3:
            st.metric("Mean", f"{ts_data[metric_col].mean():.2f}")

        with col4:
            st.metric("Latest", f"{ts_data[metric_col].iloc[-1]:.2f}")


# ===== DOCUMENTATION VIEW =====
else:  # view == "Documentation"
    st.markdown(f"<h2 style='color: {RED_HAT_DARK};'>📚 Documentation</h2>", unsafe_allow_html=True)

    # AI-generated notice
    st.warning(
        "🤖 **AI-Generated Documentation** — This documentation was generated by AI based on the codebase. "
        "It's *mostly* right, *probably*... but when in doubt, ask a human for details."
    )

    # Load and display markdown documentation
    from pathlib import Path
    doc_path = Path(__file__).parent / "DOCUMENTATION.md"

    try:
        with open(doc_path, "r") as f:
            st.markdown(f.read(), unsafe_allow_html=False)
    except FileNotFoundError:
        st.error(f"Documentation file not found at: {doc_path}")
        st.info("Please ensure DOCUMENTATION.md exists in the app directory.")


# Footer with Red Hat branding
st.sidebar.markdown("---")
st.sidebar.markdown(f"""
    <div style='text-align: center; padding: 10px;'>
        <p style='color: {RED_HAT_RED}; font-weight: bold; font-size: 16px; margin-bottom: 5px;'>Red Hat OpenShift AI</p>
        <p style='color: {RED_HAT_DARK}; font-size: 14px; margin-bottom: 5px;'>Security Thermometer</p>
        <p style='color: #666; font-size: 12px; margin-bottom: 3px;'>Analyzing {len(releases)} RHOAI releases</p>
        <p style='color: #666; font-size: 11px;'>Data auto-refreshes every 5 minutes</p>
    </div>
    """, unsafe_allow_html=True)
