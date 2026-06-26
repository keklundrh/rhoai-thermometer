"""RHOAI Thermometer - CVE Security Dashboard

A Streamlit dashboard for analyzing CVE vulnerabilities in RHOAI container images.
"""

import streamlit as st
import pandas as pd
from data_loader import get_available_releases, load_release_data, compute_release_metrics, get_time_series_data, get_freshness_data_by_release, get_freshness_histogram_data, get_min_cvss_score
from utils import create_severity_chart, create_time_series_chart, create_freshness_chart, create_freshness_stacked_chart, create_freshness_histogram_stacked


# Page configuration
st.set_page_config(
    page_title="RHOAI Thermometer",
    page_icon="🌡️",
    layout="wide"
)

# Title
st.title("🌡️ RHOAI Thermometer - CVE Dashboard")
st.markdown("Security vulnerability analysis for Red Hat OpenShift AI releases")

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
view = st.sidebar.radio(
    "Select View",
    ["Release View", "Time Series View", "Documentation"],
    help="Choose between single release analysis, trends over time, or documentation"
)

# Load available releases
releases = get_available_releases()

if not releases:
    st.error("No RELEASE.tsv files found in data/summary/")
    st.stop()


# ===== RELEASE VIEW =====
if view == "Release View":
    st.header("Release Analysis")

    # Show active filter
    if cvss_threshold is not None:
        st.info(f"🔍 **Active Filter:** CVSS Score ≥ {cvss_threshold}")
    elif severity_filter:
        st.info(f"🔍 **Active Filter:** Severity = {', '.join(severity_filter)}")

    # Release selector
    release_options = {f"RHOAI {rhoai} (OCP {ocp})": (rhoai, ocp, path)
                      for rhoai, ocp, path in releases}

    selected = st.selectbox(
        "Select RHOAI Release",
        options=list(release_options.keys()),
        help="Choose a RHOAI release to analyze"
    )

    rhoai_ver, ocp_ver, filepath = release_options[selected]

    # Load data
    with st.spinner(f"Loading data for RHOAI {rhoai_ver}..."):
        df = load_release_data(filepath)
        metrics = compute_release_metrics(df, cvss_threshold=cvss_threshold, severity_filter=severity_filter)

    # Display metrics
    st.subheader("Summary Metrics")

    # Row 1: Count metrics
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            label="Total CVEs at Release",
            value=f"{metrics['total_cves']:,}",
            help="High/critical CVEs discovered at or before RHOAI release (DISCOVERY_DATE <= RELEASE_DATE). Excludes NO-RH-VEX entries."
        )

    with col2:
        st.metric(
            label="Unique CVEs",
            value=f"{metrics['unique_cves']:,}",
            help="Number of distinct CVE IDs (same CVE may appear in multiple containers)"
        )

    with col3:
        st.metric(
            label="Total Containers",
            value=f"{metrics['total_containers']:,}",
            help="Number of unique container images scanned"
        )

    with col4:
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
            help="CVEs where a fix already existed at RHOAI release date (FIX_DATE < RELEASE_DATE)"
        )
        st.progress(metrics['pct_with_fix'] / 100)

    with col3:
        st.write("")  # Empty column for spacing

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
    st.header("Time Series Analysis")

    # Show active filter
    if cvss_threshold is not None:
        st.info(f"🔍 **Active Filter:** CVSS Score ≥ {cvss_threshold}")
    elif severity_filter:
        st.info(f"🔍 **Active Filter:** Severity = {', '.join(severity_filter)}")

    # Metric selector
    metric_options = {
        "Total CVEs at release": "total_cves",
        "Unique CVEs at release": "unique_cves",
        "Total Containers": "total_containers",
        "Average CVEs per Container": "avg_cves_per_container",
        "% CVEs with No Fix": "pct_no_fix",
        "% CVEs with Fix": "pct_with_fix",
        "Container Freshness (View 1)": "freshness_monthly",
        "Container Freshness (View 2)": "freshness_histogram"
    }

    selected_metric_label = st.selectbox(
        "Select Metric to Plot",
        options=list(metric_options.keys()),
        help="Choose which metric to visualize over time"
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
    percentage_metrics = ['pct_no_fix', 'pct_with_fix']

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
    st.header("📚 Documentation")

    # Load and display markdown documentation
    from pathlib import Path
    doc_path = Path(__file__).parent / "DOCUMENTATION.md"

    try:
        with open(doc_path, "r") as f:
            st.markdown(f.read(), unsafe_allow_html=False)
    except FileNotFoundError:
        st.error(f"Documentation file not found at: {doc_path}")
        st.info("Please ensure DOCUMENTATION.md exists in the app directory.")


# Footer
st.sidebar.markdown("---")
st.sidebar.info(
    "**RHOAI Thermometer**\n\n"
    f"Analyzing {len(releases)} RHOAI releases\n\n"
    "Data auto-refreshes every 5 minutes"
)
