# RHOAI Thermometer

Security analytics tool for scanning Red Hat OpenShift AI (RHOAI) container images for CVE vulnerabilities.

## Setup

### Prerequisites

1. Clone the helper repo in project root:
   ```bash
   git clone https://github.com/red-hat-data-services/rhoai-disconnected-install-helper.git
   ```

2. Install scanning tools:
   * grype
   * syft
   * jq
   * git
   * podman
   * gh (GitHub CLI)

### Install Python Dependencies

```bash
pip install -r requirements.txt
```

## Running Scans

Generate CVE data for a specific RHOAI release:

```bash
./rh-summarize.sh <OCP_VERSION> <RHOAI_VERSION> [today|release]
```

Examples:
- `./rh-summarize.sh 4.18 2.19.0` - Scan RHOAI 2.19.0 on OCP 4.18 using CVEs as of release date
- `./rh-summarize.sh 4.18 2.19.0 today` - Scan using today's CVE database

## Running the Dashboard

Launch the Streamlit web dashboard to visualize CVE data:

```bash
./run.sh
```

Or manually:
```bash
source .venv/bin/activate
streamlit run app.py
```

The dashboard will open in your browser at `http://localhost:8501`

### Dashboard Features

**Release View:**
- Select a RHOAI release to analyze
- View summary metrics: total CVEs, container counts, fix availability
- Box plot showing CVE distribution across containers
- Severity breakdown chart
- Fix timeline analysis:
  - % of CVEs where fix existed before RHOAI release
  - % of CVEs where fix came after RHOAI release
  - Average days from release to fix availability
  - Histogram showing fix timeline distribution (relative to release date)

**Time Series View:**
- Track metrics across RHOAI versions over time
- Compare security posture trends

NOTE: There are other ways to pull this data. Using simple tooling for now while other, more efficient sources are compiled. 
