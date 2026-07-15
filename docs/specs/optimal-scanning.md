# Optimal scanning process 

Review the code base for context. 

## Background 

rh-summarize.sh scans a release ensuring the images scanned reflect the images used on the release date. These are extracted from the operator index and paired with images from the disconnected-install-helper repository from the release date commits. 

rh-summarize.sh creates an SBOM with syft and scans with grype. The results are then enriched with RH, GHSA, and GO VEX data and filtered on specific CVSS scores.

** Caching behavior** 
- SBOMs are cached indefinitely per image SHA (never expire) 
- grype scans are dated and stored locally, they are reused if scanned on same day 
- VEX data is cached and reused as long as it is newer than the cutoff days (today - cutoff days) 

## Goal 

Create a script that recommends optimal scan batching sequence to maximize cache hits across releases. 

**Input:** List of RHOAI releases to analyze. For example: 
- `./optimize-scans.sh 2.25.0` returns all rhoai releases with > 70% shared images 

**Output:** 
- [ ] Prioritized list of "scan groups" (releases sharing > 70% (this number is adjustable) images that should be scanned together) 

**Algorithm:** 
1. parse image lists from `data/releases/` for each release using the same process `rh-summarize.sh` uses to include operator index images and those from the git repo `disconnected-install-helper`
2. Calculate image overlap between releases (by sha) 
3. Identify clusters where overlap > 70%? - ABILITY TO SPECIFY THRESHOLD 
4. Recommend batching those releases in scan sessions run on the same day
5. Consider existing cache: prioritize scans with existing cached resources 

**Success criteria:** 
- minimize total wall-clock time by scanning overlapping releases consecutively 
- highlight releases with high cache hit potential
- flag releases with unique images (no caching benefit) 

**Edge cases to handle:** 
- cache may be stale given the cuttoff variable 
- ignore releases without images lists 
- flag if number of image count is 25% higher than the prior RHOAI version release
  - this compares 2.25.1 to 2.25.0. It is NOT based on release date

**Technical details:** 
- CUTOFF or cache freshness is defined in rh-summarize.sh 
- SBOMs are stored in data/images/IMAGE_NAME/sboms folder with a json file per sha 
- SCANs are stored in data/images/IMAGE_NAME/scans folder with a json & tsv file per sha 
- script should be standalone 
- Accomplish this with bash so it's universal 
- If a RHOAI version is in OCP 4.16 and 4.20, default to the higher (newer) release

---

# SBOM Source Strategy: Red Hat Official vs Syft

## Current Approach

**RHOAI Thermometer uses Syft-generated SBOMs** for vulnerability scanning because:

1. **Comprehensive Coverage** - Syft detects packages across all ecosystems (RPM, Python, Go, Java, JavaScript) including transitive dependencies
2. **Consistency** - Same SBOM format and tooling across all releases enables trend analysis
3. **Historical Scanning** - Can rescan historical images with updated CVE databases
4. **Automated Pipeline** - Proven caching and enrichment workflow

## Red Hat Official SBOMs

Red Hat provides signed SBOMs as attestations, downloadable via:
```bash
cosign download attestation registry.redhat.io/rhods/image@sha256:...
```

**Advantages:**
- Authoritative source from image publisher
- Cryptographically signed for integrity
- Focused on officially supported components
- Aligns with Red Hat security tracking

**Limitations:**
- Requires authentication
- May not include transitive dependencies
- Format varies (SPDX vs CycloneDX)
- Less flexible for historical rescanning

## Comparison Findings

Typical differences between Red Hat SBOMs and Syft SBOMs:

**Package Count:**
- Syft typically finds 10-30% more packages
- Extra packages are transitive dependencies, vendored libraries
- Both cover RPMs well; Syft has broader Python/Go/JavaScript coverage

**Version Format:**
- Red Hat: Full RPM NEVRA (e.g., `openssl-3.0.7-28.el9_4`)
- Syft: Normalized version (e.g., `openssl-3.0.7`)
- This is normal formatting difference, not a mismatch

**Coverage Metrics:**
- Common packages: typically 90-95% overlap
- Version alignment: >90% after normalization
- Ecosystem parity: Both detect same package types

## Recommended Strategy

**Primary Workflow (Current - Keep Using Syft):**
1. Generate SBOMs with Syft
2. Scan with Grype for CVEs
3. Enrich with Red Hat VEX data
4. Track trends over time

**Validation Layer (Add Periodic Checks):**
1. Quarterly: Compare Red Hat vs Syft SBOMs for sample images
2. Track coverage metrics over time
3. Alert if coverage drops below 95%
4. Document any significant discrepancies

**Tools Available:**
- `scripts/compare-sboms.sh` - Quick shell comparison
- `scripts/compare_sboms.py` - Detailed Python analysis
- See `docs/sbom-comparison.md` for full methodology

## When to Switch

Consider using Red Hat SBOMs as primary source IF:
- Red Hat SBOMs become programmatically accessible without auth
- Red Hat provides historical SBOM snapshots
- Syft coverage drops below 95%
- Regulatory compliance requires publisher-signed SBOMs

For now: **Continue using Syft, validate with periodic Red Hat SBOM comparisons**
