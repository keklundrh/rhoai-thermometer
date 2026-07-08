"""Utility functions for RHOAI Thermometer dashboard."""

import re
from typing import Optional, Tuple, List
import numpy as np
import plotly.graph_objects as go
from packaging import version


def parse_filename(filename: str) -> Optional[Tuple[str, str]]:
    """
    Parse RHOAI release filename to extract OCP and RHOAI versions.

    Args:
        filename: TSV filename (e.g., 'ocp-4.16-rhoai-2.16.0-RELEASE.tsv')

    Returns:
        Tuple of (ocp_version, rhoai_version) or None if parsing fails
    """
    pattern = r'ocp-(\d+\.\d+)-rhoai-(\d+\.\d+\.\d+)-RELEASE\.tsv'
    match = re.search(pattern, filename)
    if match:
        return (match.group(1), match.group(2))
    return None


def sort_versions(versions: List[str]) -> List[str]:
    """
    Sort RHOAI versions semantically (e.g., 2.22.0 < 3.2.0 < 3.4.0).

    Args:
        versions: List of version strings

    Returns:
        Sorted list of versions
    """
    return sorted(versions, key=lambda v: version.parse(v))


def create_box_plot(data: np.ndarray, title: str = "CVE Distribution Across Containers") -> go.Figure:
    """
    Create a Plotly box plot showing CVE distribution.
    Y-axis is capped at 1.5x IQR to focus on the box, with annotation for outliers.

    Args:
        data: Array of CVE counts per container
        title: Plot title

    Returns:
        Plotly Figure object
    """
    # Calculate quartiles and IQR for intelligent axis scaling
    q1 = np.percentile(data, 25)
    q3 = np.percentile(data, 75)
    iqr = q3 - q1

    # Calculate upper fence (1.5 * IQR above Q3)
    upper_fence = q3 + (1.5 * iqr)

    # Count outliers beyond the fence
    outliers_count = np.sum(data > upper_fence)
    max_outlier = np.max(data)

    fig = go.Figure()
    fig.add_trace(go.Box(
        y=data,
        name='CVEs per Container',
        boxmean='sd',  # Show mean and standard deviation
        marker_color='lightblue',
        line_color='darkblue',
        boxpoints='outliers'  # Show only outlier points
    ))

    # Set y-axis range to focus on the box (cap at upper fence + small margin)
    y_max = upper_fence * 1.2

    fig.update_layout(
        title=title,
        yaxis_title="Number of CVEs",
        yaxis=dict(range=[0, y_max]),
        showlegend=False,
        height=400,
        annotations=[
            dict(
                x=0.5,
                y=0.98,
                xref='paper',
                yref='paper',
                text=f"{outliers_count} containers extend beyond axis (max: {int(max_outlier):,} CVEs)",
                showarrow=False,
                font=dict(size=10, color='gray'),
                xanchor='center',
                yanchor='top'
            )
        ] if outliers_count > 0 else []
    )

    return fig


def create_severity_chart(severity_counts: dict) -> go.Figure:
    """
    Create a horizontal bar chart of CVE severity distribution.

    Args:
        severity_counts: Dict mapping severity level to count

    Returns:
        Plotly Figure object
    """
    # Define severity order and colors
    severity_order = ['Critical', 'High', 'Medium', 'Low']
    colors = {
        'Critical': '#d32f2f',  # Red
        'High': '#ff9800',      # Orange
        'Medium': '#ffd54f',    # Yellow
        'Low': '#42a5f5'        # Blue
    }

    # Filter to only include severities present in data
    severities = [s for s in severity_order if s in severity_counts]
    counts = [severity_counts[s] for s in severities]
    bar_colors = [colors[s] for s in severities]

    fig = go.Figure(go.Bar(
        x=counts,
        y=severities,
        orientation='h',
        marker_color=bar_colors,
        text=counts,
        textposition='auto'
    ))

    fig.update_layout(
        title="Unique CVEs by Severity",
        xaxis_title="Number of Unique CVEs",
        yaxis_title="Severity",
        height=300,
        yaxis={'categoryorder': 'array', 'categoryarray': severity_order}
    )

    return fig


def create_time_series_chart(df, metric_col: str, metric_label: str, y_min: float = None, y_max: float = None) -> go.Figure:
    """
    Create a line chart showing metric evolution over RHOAI versions with a linear trendline.

    Args:
        df: DataFrame with 'rhoai_version' column and metric columns
        metric_col: Column name to plot
        metric_label: Display label for the metric
        y_min: Minimum value for Y-axis (optional, for consistent scaling)
        y_max: Maximum value for Y-axis (optional, for consistent scaling)

    Returns:
        Plotly Figure object
    """
    import pandas as pd

    fig = go.Figure()

    # Main data line
    fig.add_trace(go.Scatter(
        x=df['rhoai_version'],
        y=df[metric_col],
        mode='lines+markers',
        name=metric_label,
        line=dict(color='#1f77b4', width=3),
        marker=dict(size=8),
        hovertemplate='<b>RHOAI %{x}</b><br>' + metric_label + ': %{y:.2f}<extra></extra>'
    ))

    # Calculate linear trendline
    # Convert x-axis to numeric indices for linear regression
    x_numeric = np.arange(len(df))
    y_values = df[metric_col].values

    # Linear regression
    z = np.polyfit(x_numeric, y_values, 1)
    p = np.poly1d(z)
    trendline_y = p(x_numeric)

    # Calculate trend (slope per release)
    slope = z[0]
    trend_direction = "increasing" if slope > 0 else "decreasing"

    # Add trendline
    fig.add_trace(go.Scatter(
        x=df['rhoai_version'],
        y=trendline_y,
        mode='lines',
        name='Trend',
        line=dict(color='lightgray', width=2, dash='dash'),
        hovertemplate=f'<b>Trendline</b><br>Slope: {slope:.2f} per release<extra></extra>',
        showlegend=True
    ))

    # Build layout with optional Y-axis range
    layout_config = {
        'title': f"{metric_label} Over Time",
        'xaxis_title': "RHOAI Version (by release date)",
        'yaxis_title': metric_label,
        'height': 500,
        'hovermode': 'x unified',
        'annotations': [
            dict(
                x=0.02,
                y=0.98,
                xref='paper',
                yref='paper',
                text=f"Trend: {trend_direction} ({slope:+.2f} per release)",
                showarrow=False,
                font=dict(size=11, color='gray'),
                xanchor='left',
                yanchor='top',
                bgcolor='rgba(255, 255, 255, 0.8)',
                bordercolor='lightgray',
                borderwidth=1,
                borderpad=4
            )
        ]
    }

    # Determine Y-axis range based on metric type
    percentage_metrics = ['pct_no_fix', 'pct_with_fix', 'pct_fix_version_listed', 'freshness_score']

    if metric_col in percentage_metrics:
        # Percentage metrics: Y-axis from 0 to 100
        layout_config['yaxis'] = dict(range=[0, 100])
    else:
        # Count metrics: Y-axis from 0 to max + 10%
        data_max = df[metric_col].max()
        y_axis_max = data_max * 1.1
        layout_config['yaxis'] = dict(range=[0, y_axis_max])

    fig.update_layout(**layout_config)

    return fig


def create_freshness_chart(data: np.ndarray, dates: np.ndarray, release_date: str, title: str = "Container Freshness Distribution") -> go.Figure:
    """
    Create a histogram showing container freshness (days between build and RHOAI release).
    Negative values = container built before release (left side)
    Positive values = container built after release (right side)

    Args:
        data: Array of freshness in days (container-build-date - RELEASE_DATE)
        dates: Array of container build dates (datetime64)
        release_date: RHOAI release date string
        title: Plot title

    Returns:
        Plotly Figure object
    """
    import pandas as pd

    # Create DataFrame for easier binning
    df = pd.DataFrame({
        'days': data,
        'date': pd.to_datetime(dates)
    })

    # Bin the data manually to get min/max dates per bin
    bins = np.histogram_bin_edges(data, bins=50)
    df['bin'] = pd.cut(df['days'], bins=bins, include_lowest=True)

    # Group by bin and get stats
    binned = df.groupby('bin', observed=True).agg({
        'days': 'count',
        'date': ['min', 'max']
    }).reset_index()

    # Flatten column names
    binned.columns = ['bin', 'count', 'date_min', 'date_max']

    # Get bin centers for x-axis
    binned['bin_center'] = binned['bin'].apply(lambda x: x.mid)

    # Filter out empty bins
    binned = binned[binned['count'] > 0]

    # Create custom hover text
    hover_text = []
    for _, row in binned.iterrows():
        date_range = f"{row['date_min'].strftime('%Y-%m-%d')} to {row['date_max'].strftime('%Y-%m-%d')}"
        hover_text.append(
            f"Days from release: {row['bin_center']:.0f}<br>"
            f"Container count: {row['count']}<br>"
            f"Build date range: {date_range}"
        )

    fig = go.Figure()

    # Create bar chart (looks like histogram)
    fig.add_trace(go.Bar(
        x=binned['bin_center'],
        y=binned['count'],
        width=np.diff(bins).mean(),  # Uniform bar width
        marker_color='#2ca02c',  # Green color
        marker_line_color='white',
        marker_line_width=1,
        hovertext=hover_text,
        hoverinfo='text'
    ))

    # Add vertical line at x=0 (RHOAI release date)
    fig.add_vline(
        x=0,
        line_dash="dash",
        line_color="red",
        annotation_text=f"RHOAI Released ({release_date})",
        annotation_position="top"
    )

    fig.update_layout(
        title=title,
        xaxis_title="Days from Release (negative = built before, positive = built after)",
        yaxis_title="Number of Containers",
        height=400,
        showlegend=False
    )

    return fig


def create_freshness_stacked_chart(freshness_data_by_release: dict, release_dates: dict, title: str = "Container Build Dates Across Releases") -> go.Figure:
    """
    Create a stacked bar chart showing container build dates binned by month across multiple RHOAI releases.

    Args:
        freshness_data_by_release: Dict mapping release version -> DataFrame with [month, count]
        release_dates: Dict mapping release version -> release date
        title: Plot title

    Returns:
        Plotly Figure object
    """
    import plotly.express as px
    import pandas as pd

    fig = go.Figure()

    # Color palette for different releases
    colors = px.colors.qualitative.Plotly

    # Add bar trace for each release
    for idx, (release, df) in enumerate(freshness_data_by_release.items()):
        if not df.empty:
            fig.add_trace(go.Bar(
                x=df['month'],
                y=df['count'],
                name=f"RHOAI {release}",
                marker_color=colors[idx % len(colors)],
                opacity=0.7,
                hovertemplate=f'<b>RHOAI {release}</b><br>Month: %{{x|%Y-%m}}<br>Containers: %{{y}}<extra></extra>'
            ))

    # Add vertical lines for each RHOAI release date using shapes (more compatible)
    for idx, (release, release_date) in enumerate(release_dates.items()):
        fig.add_shape(
            type="line",
            x0=release_date,
            x1=release_date,
            y0=0,
            y1=1,
            yref="paper",
            line=dict(
                color=colors[idx % len(colors)],
                width=2,
                dash="dash"
            )
        )
        # Add annotation separately
        fig.add_annotation(
            x=release_date,
            y=1,
            yref="paper",
            text=f"RHOAI {release}",
            showarrow=False,
            textangle=-90,
            yanchor="bottom",
            font=dict(color=colors[idx % len(colors)])
        )

    fig.update_layout(
        title=title,
        xaxis_title="Container Build Month",
        yaxis_title="Number of Containers",
        barmode='stack',
        height=600,
        hovermode='x unified',
        legend=dict(
            orientation="v",
            yanchor="top",
            y=1,
            xanchor="left",
            x=0.01
        ),
        xaxis=dict(
            tickformat='%Y-%m'
        )
    )

    return fig


def create_freshness_score_chart(freshness_buckets: dict) -> go.Figure:
    """
    Create a bar chart showing container age distribution by freshness buckets.

    Args:
        freshness_buckets: Dict with keys 'excellent', 'good', 'fair', 'stale' and container counts

    Returns:
        Plotly Figure object
    """
    categories = ['Excellent\n(0-3mo)', 'Good\n(3-6mo)', 'Fair\n(6-12mo)', 'Stale\n(12+mo)']
    values = [
        freshness_buckets['excellent'],
        freshness_buckets['good'],
        freshness_buckets['fair'],
        freshness_buckets['stale']
    ]
    colors = ['#00CC66', '#FFD700', '#FFA500', '#FF4444']  # Green, Gold, Orange, Red

    fig = go.Figure(data=[
        go.Bar(
            x=categories,
            y=values,
            marker_color=colors,
            text=values,
            textposition='auto',
            hovertemplate='<b>%{x}</b><br>Containers: %{y}<extra></extra>'
        )
    ])

    fig.update_layout(
        title="Container Age Distribution at Release",
        xaxis_title="Container Age Category",
        yaxis_title="Number of Containers",
        height=400,
        showlegend=False
    )

    return fig


def create_freshness_histogram_stacked(freshness_data_by_release: dict, title: str = "Container Freshness Distribution") -> go.Figure:
    """
    Create a stacked histogram showing container freshness (days) across multiple RHOAI releases.
    Negative values = built before release, Positive values = built after release.

    Args:
        freshness_data_by_release: Dict mapping release version -> array of freshness days
        title: Plot title

    Returns:
        Plotly Figure object
    """
    import plotly.express as px

    fig = go.Figure()

    # Color palette for different releases
    colors = px.colors.qualitative.Plotly

    # Add histogram trace for each release
    for idx, (release, data) in enumerate(freshness_data_by_release.items()):
        if len(data) > 0:
            fig.add_trace(go.Histogram(
                x=data,
                name=f"RHOAI {release}",
                marker_color=colors[idx % len(colors)],
                opacity=0.7,
                nbinsx=50,
                hovertemplate=f'<b>RHOAI {release}</b><br>Days from release: %{{x}}<br>Count: %{{y}}<extra></extra>'
            ))

    # Add vertical line at x=0 (release date)
    fig.add_vline(
        x=0,
        line_dash="dash",
        line_color="red",
        annotation_text="Release Date",
        annotation_position="top"
    )

    fig.update_layout(
        title=title,
        xaxis_title="Days from Release (negative = built before, positive = built after)",
        yaxis_title="Number of Containers",
        barmode='stack',
        height=600,
        hovermode='x unified',
        legend=dict(
            orientation="v",
            yanchor="top",
            y=1,
            xanchor="left",
            x=0.01
        )
    )

    return fig


def create_fix_timeline_chart(data: np.ndarray, title: str = "Fix Timeline Distribution") -> go.Figure:
    """
    Create a histogram showing when fixes became available relative to RHOAI release date.

    Args:
        data: Array of days differences (negative = fix before release, positive = fix after release)
        title: Plot title

    Returns:
        Plotly Figure object
    """
    fig = go.Figure()

    # Create histogram with custom bins
    fig.add_trace(go.Histogram(
        x=data,
        nbinsx=50,
        marker_color='#1f77b4',
        marker_line_color='white',
        marker_line_width=1,
        hovertemplate='Days: %{x}<br>Count: %{y}<extra></extra>'
    ))

    # Add vertical line at x=0 (RHOAI release date)
    fig.add_vline(
        x=0,
        line_dash="dash",
        line_color="red",
        annotation_text="RHOAI Released",
        annotation_position="top"
    )

    fig.update_layout(
        title=title,
        xaxis_title="Days (negative = fix existed before release, positive = fix after release)",
        yaxis_title="Number of CVEs",
        height=400,
        showlegend=False
    )

    return fig
