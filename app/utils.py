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
        title="CVEs by Severity",
        xaxis_title="Number of CVEs",
        yaxis_title="Severity",
        height=300,
        yaxis={'categoryorder': 'array', 'categoryarray': severity_order}
    )

    return fig


def create_time_series_chart(df, metric_col: str, metric_label: str, y_min: float = None, y_max: float = None) -> go.Figure:
    """
    Create a line chart showing metric evolution over RHOAI versions.

    Args:
        df: DataFrame with 'rhoai_version' column and metric columns
        metric_col: Column name to plot
        metric_label: Display label for the metric
        y_min: Minimum value for Y-axis (optional, for consistent scaling)
        y_max: Maximum value for Y-axis (optional, for consistent scaling)

    Returns:
        Plotly Figure object
    """
    fig = go.Figure()

    fig.add_trace(go.Scatter(
        x=df['rhoai_version'],
        y=df[metric_col],
        mode='lines+markers',
        name=metric_label,
        line=dict(color='#1f77b4', width=3),
        marker=dict(size=8),
        hovertemplate='<b>RHOAI %{x}</b><br>' + metric_label + ': %{y:.2f}<extra></extra>'
    ))

    # Build layout with optional Y-axis range
    layout_config = {
        'title': f"{metric_label} Over Time",
        'xaxis_title': "RHOAI Version",
        'yaxis_title': metric_label,
        'height': 500,
        'hovermode': 'x unified'
    }

    # Set Y-axis range if provided (add 5% margin for readability)
    if y_min is not None and y_max is not None:
        margin = (y_max - y_min) * 0.05
        layout_config['yaxis'] = dict(range=[max(0, y_min - margin), y_max + margin])

    fig.update_layout(**layout_config)

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
