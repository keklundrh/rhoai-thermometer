#!/usr/bin/env bash
set -euo pipefail

# compare-sboms.sh - Compare Red Hat official SBOMs with Syft-generated SBOMs
#
# Usage: ./compare-sboms.sh [--reuse] <IMAGE_REF> [OUTPUT_DIR]
#
# Flags:
#   --reuse    Skip regenerating SBOMs if they already exist
#
# Example:
#   ./compare-sboms.sh registry.redhat.io/rhods/odh-dashboard-rhel9@sha256:abc123...
#   ./compare-sboms.sh --reuse registry.redhat.io/rhods/odh-dashboard-rhel9:2.22.0-29
#
# This script:
# 1. Downloads Red Hat's official SBOM (using cosign download attestation)
# 2. Generates an SBOM using Syft (if not already cached)
# 3. Compares the two SBOMs:
#    - Package counts
#    - Package name differences
#    - Version mismatches
#    - Type/ecosystem differences
# 4. Outputs a detailed comparison report

REUSE=false
if [[ "${1:-}" == "--reuse" ]]; then
    REUSE=true
    shift
fi

IMAGE_REF="${1:-}"
OUTPUT_DIR="${2:-./sbom-comparison}"

if [[ -z "$IMAGE_REF" ]]; then
    echo "Usage: $0 [--reuse] <IMAGE_REF> [OUTPUT_DIR]"
    echo ""
    echo "Flags:"
    echo "  --reuse    Skip regenerating SBOMs if they already exist"
    echo ""
    echo "Example:"
    echo "  $0 registry.redhat.io/rhods/odh-dashboard-rhel9@sha256:abc123..."
    echo "  $0 --reuse registry.redhat.io/rhods/odh-dashboard-rhel9:2.22.0-29"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

# Extract image name and SHA/tag for file naming
IMAGE_NAME=$(echo "$IMAGE_REF" | sed -E 's|.*/([^@:]+).*|\1|')
IMAGE_ID=$(echo "$IMAGE_REF" | sed -E 's|.*[@:](.+)|\1|' | tr ':' '-')

RH_SBOM="$OUTPUT_DIR/${IMAGE_NAME}-${IMAGE_ID}-redhat.json"
SYFT_SBOM="$OUTPUT_DIR/${IMAGE_NAME}-${IMAGE_ID}-syft.json"
COMPARISON_REPORT="$OUTPUT_DIR/${IMAGE_NAME}-${IMAGE_ID}-comparison.txt"

echo "Comparing SBOMs for: $IMAGE_REF"
echo "Output directory: $OUTPUT_DIR"
echo ""

# Step 1: Download Red Hat SBOM using cosign
echo "[1/4] Downloading Red Hat official SBOM..."
if [[ "$REUSE" == "true" && -f "$RH_SBOM" ]]; then
    echo "  ↻ Reusing existing Red Hat SBOM"
    RH_FORMAT="existing"
elif cosign download attestation "$IMAGE_REF" --predicate-type=https://spdx.dev/Document > "$RH_SBOM" 2>/dev/null; then
    echo "  ✓ Red Hat SBOM downloaded"
    RH_FORMAT="spdx"
elif cosign download attestation "$IMAGE_REF" --predicate-type=https://cyclonedx.org/bom > "$RH_SBOM" 2>/dev/null; then
    echo "  ✓ Red Hat SBOM downloaded (CycloneDX format)"
    RH_FORMAT="cyclonedx"
else
    echo "  ✗ Failed to download Red Hat SBOM"
    echo ""
    echo "Trying alternative method: cosign download sbom (deprecated)..."
    if cosign download sbom "$IMAGE_REF" > "$RH_SBOM" 2>&1; then
        echo "  ✓ Red Hat SBOM downloaded using deprecated method"
        RH_FORMAT="unknown"
    else
        echo "  ✗ Failed to download Red Hat SBOM using all methods"
        echo ""
        echo "Note: You may need to authenticate first:"
        echo "  podman login registry.redhat.io"
        echo ""
        cat "$RH_SBOM" 2>/dev/null || true
        rm -f "$RH_SBOM"
        RH_SBOM=""
    fi
fi

# Step 2: Generate Syft SBOM
echo ""
echo "[2/4] Generating Syft SBOM..."
if [[ "$REUSE" == "true" && -f "$SYFT_SBOM" ]]; then
    echo "  ↻ Reusing existing Syft SBOM"
elif syft "$IMAGE_REF" -o json > "$SYFT_SBOM" 2>/dev/null; then
    echo "  ✓ Syft SBOM generated"
else
    echo "  ✗ Failed to generate Syft SBOM"
    cat "$SYFT_SBOM" 2>/dev/null || true
    exit 1
fi

# Step 3: Parse and compare SBOMs
echo ""
echo "[3/4] Analyzing SBOMs..."

# Extract package lists
if [[ -n "$RH_SBOM" ]]; then
    # Try to detect format and extract packages

    # Check if payload is base64-encoded (in-toto attestation)
    if jq -e '.payload' "$RH_SBOM" &>/dev/null; then
        echo "  Decoding base64 payload..."
        DECODED_SBOM="$OUTPUT_DIR/rh-decoded.json"
        jq -r '.payload' "$RH_SBOM" | base64 -d > "$DECODED_SBOM"

        # Now parse the decoded SPDX
        if jq -e '.predicate.packages' "$DECODED_SBOM" &>/dev/null; then
            jq -r '.predicate.packages[] | "\(.name)|\(.versionInfo // .SPDXID)"' "$DECODED_SBOM" | sort > "$OUTPUT_DIR/rh-packages.txt"
        else
            echo "  ⚠ Could not parse decoded SBOM"
            jq '.' "$DECODED_SBOM" | head -20
            RH_SBOM=""
        fi
    elif jq -e '.predicate.packages' "$RH_SBOM" &>/dev/null; then
        # SPDX in attestation format (already decoded)
        jq -r '.predicate.packages[] | "\(.name)|\(.versionInfo // .SPDXID)"' "$RH_SBOM" | sort > "$OUTPUT_DIR/rh-packages.txt"
    elif jq -e '.packages' "$RH_SBOM" &>/dev/null; then
        # SPDX direct format
        jq -r '.packages[] | "\(.name)|\(.versionInfo // .SPDXID)"' "$RH_SBOM" | sort > "$OUTPUT_DIR/rh-packages.txt"
    elif jq -e '.components' "$RH_SBOM" &>/dev/null; then
        # CycloneDX format
        jq -r '.components[] | "\(.name)|\(.version)"' "$RH_SBOM" | sort > "$OUTPUT_DIR/rh-packages.txt"
    elif jq -e '.predicate.components' "$RH_SBOM" &>/dev/null; then
        # CycloneDX in attestation format
        jq -r '.predicate.components[] | "\(.name)|\(.version)"' "$RH_SBOM" | sort > "$OUTPUT_DIR/rh-packages.txt"
    else
        echo "  ⚠ Could not parse Red Hat SBOM format"
        jq 'keys' "$RH_SBOM"
        RH_SBOM=""
    fi
fi

jq -r '.artifacts[] | "\(.name)|\(.version)"' "$SYFT_SBOM" | sort > "$OUTPUT_DIR/syft-packages.txt"

# Step 4: Generate comparison report
echo ""
echo "[4/4] Generating comparison report..."

{
    echo "=================================="
    echo "SBOM Comparison Report"
    echo "=================================="
    echo ""
    echo "Image: $IMAGE_REF"
    echo "Date: $(date)"
    echo ""

    if [[ -n "$RH_SBOM" ]]; then
        RH_COUNT=$(wc -l < "$OUTPUT_DIR/rh-packages.txt" | tr -d ' ')
        SYFT_COUNT=$(wc -l < "$OUTPUT_DIR/syft-packages.txt" | tr -d ' ')

        echo "Package Counts:"
        echo "  Red Hat SBOM:    $RH_COUNT packages"
        echo "  Syft SBOM:       $SYFT_COUNT packages"
        echo "  Difference:      $((SYFT_COUNT - RH_COUNT)) packages"
        echo ""

        echo "Packages only in Red Hat SBOM:"
        comm -23 "$OUTPUT_DIR/rh-packages.txt" "$OUTPUT_DIR/syft-packages.txt" | head -20
        if [[ $(comm -23 "$OUTPUT_DIR/rh-packages.txt" "$OUTPUT_DIR/syft-packages.txt" | wc -l) -gt 20 ]]; then
            echo "  ... ($(comm -23 "$OUTPUT_DIR/rh-packages.txt" "$OUTPUT_DIR/syft-packages.txt" | wc -l) total)"
        fi
        echo ""

        echo "Packages only in Syft SBOM:"
        comm -13 "$OUTPUT_DIR/rh-packages.txt" "$OUTPUT_DIR/syft-packages.txt" | head -20
        if [[ $(comm -13 "$OUTPUT_DIR/rh-packages.txt" "$OUTPUT_DIR/syft-packages.txt" | wc -l) -gt 20 ]]; then
            echo "  ... ($(comm -13 "$OUTPUT_DIR/rh-packages.txt" "$OUTPUT_DIR/syft-packages.txt" | wc -l) total)"
        fi
        echo ""

        echo "Common packages:"
        echo "  $(comm -12 "$OUTPUT_DIR/rh-packages.txt" "$OUTPUT_DIR/syft-packages.txt" | wc -l | tr -d ' ') packages"
        echo ""
    else
        SYFT_COUNT=$(wc -l < "$OUTPUT_DIR/syft-packages.txt" | tr -d ' ')
        echo "Red Hat SBOM: Not available"
        echo "Syft SBOM:    $SYFT_COUNT packages"
        echo ""
    fi

    echo "=================================="
    echo "Detailed Analysis"
    echo "=================================="
    echo ""

    if [[ -n "$RH_SBOM" ]]; then
        echo "Red Hat SBOM details:"
        jq -r 'if .predicate then "Format: SBOM Attestation" else "Format: Direct SBOM" end' "$RH_SBOM"
        jq -r 'if (.predicate.spdxVersion // .spdxVersion) then "Type: SPDX \(.predicate.spdxVersion // .spdxVersion)" elif (.predicate.bomFormat // .bomFormat) then "Type: \(.predicate.bomFormat // .bomFormat)" else "Type: Unknown" end' "$RH_SBOM"
    fi

    echo ""
    echo "Syft SBOM details:"
    jq -r '"Tool: \(.descriptor.name) \(.descriptor.version)"' "$SYFT_SBOM"
    jq -r '"Packages by type: " + ([.artifacts[] | .type] | group_by(.) | map("\(.[0]): \(length)") | join(", "))' "$SYFT_SBOM"

    echo ""
    echo "=================================="
    echo "Files"
    echo "=================================="
    echo ""
    if [[ -n "$RH_SBOM" ]]; then
        echo "Red Hat SBOM:    $RH_SBOM"
    fi
    echo "Syft SBOM:       $SYFT_SBOM"
    echo "Package lists:   $OUTPUT_DIR/{rh,syft}-packages.txt"

} > "$COMPARISON_REPORT"

cat "$COMPARISON_REPORT"

echo ""
echo "✓ Comparison complete! Full report saved to: $COMPARISON_REPORT"
