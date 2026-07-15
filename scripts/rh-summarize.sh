#!/bin/bash
# Usage: ./rh-summarize.sh <OCP_VERSION> <RHOAI_VERSION> [CVSS_THRESHOLD]
# Examples:
#   ./rh-summarize.sh 4.18 2.19.0       # Scan at release date, default CVSS 0.0 (no filtering)
#   ./rh-summarize.sh 4.18 2.19.0 8.0   # Scan at release date, filter CVSS >= 8.0

# Validation counters
EXPECTED_IMAGES=0
SBOMS_CREATED=0
SCANS_COMPLETED=0
SUMMARIES_CREATED=0
ENRICHMENTS_COMPLETED=0
UNIQUE_CVES=0
VEX_DOWNLOADED=0
START_TIME=$(date +%s)

BASE_DIR=$(pwd)
RDIH_DIR=rhoai-disconnected-install-helper
VEX_URL="https://security.access.redhat.com/data/csaf/v2/vex"
#VEX_TMP=/tmp/${IMAGE}.vex.dat
RELS_DIR=data/releases/$1
IMGS_DIR=data/images
SUMM_DIR=data/summary
VEX_DIR=data/vex
JOBS=8
CVE_SCORE=${3:-0.0}  # Default to 0.0 (no filtering) to let frontend handle filtering
VER="$2"
[[ "$VER" == *.0 ]] && VER="${VER%.0}"

REL_DATE=$(grep -F $2 $RELS_DIR/../rhoai-dates.csv | cut -f2 -d,)
CUTOFF_VEX=$TMP_DIR/vex-cutoff-30days
touch -d "30 days ago" $CUTOFF_VEX 2> /dev/null || touch -t $(date -v-30d +%Y%m%d%H%M.%S) $CUTOFF_VEX 2>/dev/null
CUTOFF_SCAN=$TMP_DIR/scan-cutoff-7days
touch -d "7 days ago" $CUTOFF_SCAN 2> /dev/null || touch -t $(date -v-7d +%Y%m%d%H%M.%S) $CUTOFF_SCAN 2>/dev/null

TMP_DIR=/tmp/rh-summarize-ocp-$1-rhoai-$VER-$CVE_SCORE
mkdir -p $TMP_DIR

# Export variables so available to xargs

export IMGS_DIR
export JOBS
export CVE_SCORE
export TMP_DIR
export VEX_DIR
export RELS_DIR
export REL_DATE
export CUTOFF_VEX
export CUTOFF_SCAN

# Always scan at release date
SCAN_DATE=$REL_DATE
SCAN="RELEASE"


fn_generate_sbom () {
    local IMAGE=$1
    local BASE_IMAGE=${IMAGE##*/}
    local BASE_IMAGE=${BASE_IMAGE%@*}
    local SHA=${IMAGE##*@sha256:}
    local WORK_DIR=$2/$BASE_IMAGE
    local SBOM_DIR=$WORK_DIR/sboms

    
    mkdir -p $SBOM_DIR
    if [ ! -s ${SBOM_DIR}/${SHA}.syft.json ]; then 
        cmd="syft --platform linux/amd64 $IMAGE -o syft-json --quiet > $SBOM_DIR/$SHA.syft.json"
        echo "CREATE SBOM: using $cmd" 
        eval $cmd
    else 
        echo "SKIP SBOM: $IMAGE"
    fi
}

fn_scan_sbom () {
    local IMAGE=$1 
    local BASE_IMAGE=${IMAGE##*/}
    local BASE_IMAGE=${BASE_IMAGE%@*}
    local SHA=${IMAGE##*@sha256:}
    local WORK_DIR=$2/$BASE_IMAGE
    local SBOM_DIR=$WORK_DIR/sboms
    local SCAN_DIR=$WORK_DIR/scans

    RECENT_SCAN=$(find $SCAN_DIR -name "$SHA.grype.*.json" -newer $CUTOFF_SCAN -type f -size +0 2>/dev/null | sort -r | head -1)

    # scan image 
    mkdir -p $SCAN_DIR
    if [ -s $SCAN_DIR/$SHA.grype.$(date +%F).json ]; then
        echo "SKIP SCAN: $IMAGE" 
    elif [ -n "$RECENT_SCAN" ] && [ -s "$RECENT_SCAN" ]; then
        echo "REUSE SCAN: $IMAGE (using $(basename $RECENT_SCAN))"
        ln -f $RECENT_SCAN $SCAN_DIR/$SHA.grype.$(date +%F).json
    else
        cmd="grype sbom:$SBOM_DIR/$SHA.syft.json -o json --quiet > $SCAN_DIR/$SHA.grype.$(date +%F).json"
        echo "RUN SCAN: using $cmd" 
        eval $cmd
    fi
}

fn_cve_summary () {

    echo "SUMMARIZE FILTERED ($CVE_SCORE) CVEs: $1"

    {
    echo -e "id\tseverity\tbase-score\tpackage\tversion\tfix-version\trel-base-score\tcontainer-build-date" 
    jq -r '
     . as $doc
     | ($doc.source.target.labels["build-date"]? // "UNKNOWN") as $build
     | $doc.matches[] 
     | [
        .vulnerability.id,
        .vulnerability.severity,
        ([ .vulnerability.cvss[]?.metrics.baseScore ] | max // "NA"),
        .artifact.name, 
	    .artifact.version, 
        (.vulnerability.fix.versions[0]? // "None"), 
        ([ .relatedVulnerabilities[]?.cvss[]?.metrics.baseScore ] | max // "NA"),
        (($build | tostring) | split("T")[0])
       ] 
     | @tsv
    ' $2 | sort -k3 -n | awk -v score="$CVE_SCORE" -F\t '($3+0 >= score ) || ($7+0 >= score)'  
} > $3

}

fn_download_vex() {
    local CVE=$1

    # standard CVE, get RH VEX
    if [[ "$CVE" == CVE-* ]]; then
        YEAR=$(echo $CVE | cut -d- -f2)
        CVE_LOW=$(printf '%s' "$CVE" | tr '[:upper:]' '[:lower:]')

        mkdir -p $VEX_DIR/$YEAR
        if [ ! -s $VEX_DIR/$YEAR/$CVE_LOW.json ] || [ $VEX_DIR/$YEAR/$CVE_LOW.json -ot $CUTOFF_VEX ]; then
            curl -s -o $VEX_DIR/$YEAR/$CVE_LOW.json $VEX_URL/$YEAR/$CVE_LOW.json
        fi
    elif [[ "$CVE" == GHSA-* ]]; then
        mkdir -p $VEX_DIR/GHSA

        if [ ! -s $VEX_DIR/GHSA/$CVE.json ] || [ $VEX_DIR/GHSA/$CVE.json -ot $CUTOFF_VEX ]; then
            if ! gh api https://api.github.com/advisories/$CVE > $VEX_DIR/GHSA/$CVE.json 2>/dev/null; then
                # GHSA not found, write placeholder
                echo '{"cve_id":"NO-GHSA","ghsa_id":"'$CVE'"}' > $VEX_DIR/GHSA/$CVE.json
            fi
            sleep 1
        fi

        CVE_TMP=$(cat $VEX_DIR/GHSA/$CVE.json | jq -r '.cve_id // "NO-GHSA"')
        if [ "$CVE_TMP" != "NO-GHSA" ] && [ "$CVE_TMP" != "null" ]; then
            YEAR=$(echo $CVE_TMP | cut -d- -f2)
            CVE_LOW=$(printf '%s' "$CVE_TMP" | tr '[:upper:]' '[:lower:]')

            mkdir -p $VEX_DIR/$YEAR
            if [ ! -s $VEX_DIR/$YEAR/$CVE_LOW.json ] || [ $VEX_DIR/$YEAR/$CVE_LOW.json -ot $CUTOFF_VEX ]; then
                curl -s -o $VEX_DIR/$YEAR/$CVE_LOW.json $VEX_URL/$YEAR/$CVE_LOW.json
            fi
        fi
    elif [[ "$CVE" == GO-* ]]; then
        mkdir -p $VEX_DIR/GO

        if [ ! -s $VEX_DIR/GO/$CVE.json ] || [ $VEX_DIR/GO/$CVE.json -ot $CUTOFF_VEX ]; then
            if ! curl -s -o $VEX_DIR/GO/$CVE.json "https://api.osv.dev/v1/vulns/$CVE" 2>/dev/null; then
                # GO CVE not found, write placeholder
                echo '{"id":"NO-GO","go_id":"'$CVE'"}' > $VEX_DIR/GO/$CVE.json
            fi
            sleep 1
        fi

        # Check if GO CVE has a mapped CVE-* alias and download RH VEX for it
        CVE_TMP=$(cat $VEX_DIR/GO/$CVE.json | jq -r '.aliases[]? // empty' | grep -E '^CVE-' | head -n 1)
        if [ -n "$CVE_TMP" ]; then
            YEAR=$(echo $CVE_TMP | cut -d- -f2)
            CVE_LOW=$(printf '%s' "$CVE_TMP" | tr '[:upper:]' '[:lower:]')

            mkdir -p $VEX_DIR/$YEAR
            if [ ! -s $VEX_DIR/$YEAR/$CVE_LOW.json ] || [ $VEX_DIR/$YEAR/$CVE_LOW.json -ot $CUTOFF_VEX ]; then
                curl -s -o $VEX_DIR/$YEAR/$CVE_LOW.json $VEX_URL/$YEAR/$CVE_LOW.json
            fi
        fi
    fi

}

fn_enrich_image_cve_data() {
    local IMAGE=$1
    local REPO=${IMAGE%%/*}
    local BASE_IMAGE=${IMAGE##*/}
    local BASE_IMAGE=${BASE_IMAGE%@*}
    local SHA=${IMAGE##*@sha256:}
    local WORK_DIR=$IMGS_DIR/$BASE_IMAGE
    local SBOM_DIR=$WORK_DIR/sboms
    local SCAN_DIR=$WORK_DIR/scans

    echo "ENRICH: $IMAGE"
    {
    echo -e "DISCOVERY_DATE\tFIX_DATE"
    tail -n +2 $TMP_DIR/$SHA.grype.$(date +%F).tsv | cut -f1 -w | while read -r CVE; do 
        
        if [[ "$CVE" == CVE* ]]; then 
	        YEAR=$(echo $CVE | cut -d- -f2)
	        CVE_LOW=$(printf '%s' "$CVE" | tr '[:upper:]' '[:lower:]')
	        cat $VEX_DIR/$YEAR/$CVE_LOW.json | jq -r '
                [
                    ([.vulnerabilities[].discovery_date?] | map(select(.!=null)) | sort | .[0] // null | if . then split("T")[0] else "NOT-FOUND" end),
                    ([.vulnerabilities[].remediations[]?.date?] | map(select(.!=null)) | sort | .[0] // null | if . then split("T")[0] else "NOT-FOUND" end)
                ] | @tsv
                '  2> /dev/null || echo -e "NO-RH-VEX\tNO-RH-VEX"
        elif [[ "$CVE" == GHSA-* ]]; then
            CVE_TMP=$(cat $VEX_DIR/GHSA/$CVE.json | jq -r '.cve_id // "NO-GHSA"')
            if [ "$CVE_TMP" == "NO-GHSA" ] || [ "$CVE_TMP" == "null" ]; then
                GHSA_PUBLISHED=$(cat $VEX_DIR/GHSA/$CVE.json | jq -r '.published_at // "NOT-FOUND"' | cut -d'T' -f1)
                GHSA_UPDATED=$(cat $VEX_DIR/GHSA/$CVE.json | jq -r '.updated_at // "NOT-FOUND"' | cut -d'T' -f1)
                echo -e "$GHSA_PUBLISHED\t$GHSA_UPDATED"
            else
                # Has CVE mapping - read RH VEX for mapped CVE
                YEAR=$(echo $CVE_TMP | cut -d- -f2)
                CVE_LOW=$(printf '%s' $CVE_TMP | tr '[:upper:]' '[:lower:]')
                cat $VEX_DIR/$YEAR/$CVE_LOW.json | jq -r '
                    [
                        ([.vulnerabilities[].discovery_date?] | map(select(.!=null)) | sort | .[0] // null | if . then split("T")[0] else "NOT-FOUND" end),
                        ([.vulnerabilities[].remediations[]?.date?] | map(select(.!=null)) | sort | .[0] // null | if . then split("T")[0] else "NOT-FOUND" end)
                    ] | @tsv
                    ' 2> /dev/null || echo -e "NO-RH-VEX\tNO-RH-VEX"
            fi
        elif [[ "$CVE" == GO-* ]]; then
            GO_ID=$(cat $VEX_DIR/GO/$CVE.json | jq -r '.id // "NO-GO"')
            if [ "$GO_ID" == "NO-GO" ] || [ "$GO_ID" == "null" ]; then
                echo -e "NO-GO-VEX\tNO-GO-VEX"
            else
                # Check if GO CVE has a mapped CVE-* alias
                CVE_TMP=$(cat $VEX_DIR/GO/$CVE.json | jq -r '.aliases[]? // empty' | grep -E '^CVE-' | head -n 1)
                if [ -n "$CVE_TMP" ]; then
                    # Has CVE mapping - read RH VEX for mapped CVE
                    YEAR=$(echo $CVE_TMP | cut -d- -f2)
                    CVE_LOW=$(printf '%s' $CVE_TMP | tr '[:upper:]' '[:lower:]')
                    cat $VEX_DIR/$YEAR/$CVE_LOW.json | jq -r '
                        [
                            ([.vulnerabilities[].discovery_date?] | map(select(.!=null)) | sort | .[0] // null | if . then split("T")[0] else "NOT-FOUND" end),
                            ([.vulnerabilities[].remediations[]?.date?] | map(select(.!=null)) | sort | .[0] // null | if . then split("T")[0] else "NOT-FOUND" end)
                        ] | @tsv
                        ' 2> /dev/null || echo -e "NO-RH-VEX\tNO-RH-VEX"
                else
                    # No CVE mapping - use GO CVE published/modified dates
                    GO_PUBLISHED=$(cat $VEX_DIR/GO/$CVE.json | jq -r '.published // "NOT-FOUND"' | cut -d'T' -f1)
                    GO_MODIFIED=$(cat $VEX_DIR/GO/$CVE.json | jq -r '.modified // "NOT-FOUND"' | cut -d'T' -f1)
                    echo -e "$GO_PUBLISHED\t$GO_MODIFIED"
                fi
            fi
        else
            echo -e "NO-RH-VEX\tNO-RH-VEX"
        fi

    done
    } > $TMP_DIR/$SHA.grype.$(date +%F).vex.dat

    N=$(wc -l < $TMP_DIR/$SHA.grype.$(date +%F).tsv)
    ((N--))
    echo -e "RELEASE_DATE\tREPOSITORY\tIMAGE\tSHA" > $TMP_DIR/$SHA.meta.dat

    # Only generate metadata lines if there are CVEs (N > 0)
    if [ $N -gt 0 ]; then
        yes "$(printf '%s\t%s\t%s\t%s\n' $REL_DATE $REPO $BASE_IMAGE $SHA)" | head -n $N >> $TMP_DIR/$SHA.meta.dat
    fi

    paste $TMP_DIR/$SHA.grype.$(date +%F).tsv $TMP_DIR/$SHA.grype.$(date +%F).vex.dat $TMP_DIR/$SHA.meta.dat > $SCAN_DIR/$SHA.grype.$(date +%F).tsv

}

# Export functions so they're available to subshells spawned by xargs
export -f fn_generate_sbom
export -f fn_scan_sbom
export -f fn_cve_summary
export -f fn_enrich_image_cve_data

echo "CLEAN ENVIRONMENT: $TMP_DIR"
rm $TMP_DIR/*.tsv $TMP_DIR/*.dat 2>/dev/null

echo "GET IMAGES: rhoai $2 images on OCP $1"

# Detect catalog format (JSON for OCP <= 4.18, YAML for OCP >= 4.20)
CATALOG_FILE=$(podman run --rm --entrypoint bash registry.redhat.io/redhat/redhat-operator-index:v$1 -c 'ls /configs/rhods-operator/catalog.* 2>/dev/null | head -1' 2>&1)

if [[ "$CATALOG_FILE" == *"catalog.json" ]]; then
    echo "Using JSON catalog format"
    YQ_FORMAT="-p=json"
elif [[ "$CATALOG_FILE" == *"catalog.yaml" ]]; then
    echo "Using YAML catalog format"
    YQ_FORMAT=""
else
    echo "ERROR: No catalog file found for OCP $1"
    echo "Expected: /configs/rhods-operator/catalog.json or catalog.yaml"
    exit 1
fi

# Fetch the catalog
CATALOG=$(podman run --rm --entrypoint bash registry.redhat.io/redhat/redhat-operator-index:v$1 -c "cat $CATALOG_FILE" 2>&1)
CATALOG_EXIT=$?

# Check if podman command failed
if [ $CATALOG_EXIT -ne 0 ]; then
    echo "ERROR: Failed to fetch operator catalog for OCP $1"
    echo "$CATALOG" | grep -i error
    exit 1
fi

# Extract bundle images using yq (works for both JSON and YAML)
BUNDLE=$(echo "$CATALOG" | yq eval $YQ_FORMAT 'select(.schema == "olm.bundle") | select(.name == "rhods-operator.'${RHOAI_VERSION:-$2}'") | .relatedImages[] | .image' 2>&1)

if [ -z "$BUNDLE" ]; then
    echo "ERROR: No images found for rhods-operator.$2 in OCP $1 catalog"
    exit 1
fi


cd $RDIH_DIR
echo "UPDATE: disconnected install helper repo"
# git pull
git fetch origin
git checkout main 
git reset --hard origin/main

# Extract images from disconnected-install-helper, excluding unsupported ones
# Step 1: Get list of unsupported SHA256 hashes
UNSUPPORTED_SHAS=$(git show "$(git rev-list -n 1 --before="$SCAN_DATE" main)":rhoai-$VER.md | sed -n '/^# Unsupported Images:/,/^#/p' | grep -oE 'sha256:[a-f0-9]{64}' | sort -u)

# Step 2: Extract all images, then filter out unsupported SHAs
if [ -n "$UNSUPPORTED_SHAS" ]; then
    # Build grep pattern to exclude unsupported SHAs
    EXCLUDE_PATTERN=$(echo "$UNSUPPORTED_SHAS" | tr '\n' '|' | sed 's/|$//')
    IMAGES=$(git show "$(git rev-list -n 1 --before="$SCAN_DATE" main)":rhoai-$VER.md | grep -oE '[a-z0-9.-]+(\.[a-z]{2,})?/[^ ]+@sha256:[a-f0-9]{64}' | grep -v -E 'rhods-operator|stable|fast' | grep -vE "$EXCLUDE_PATTERN")
else
    # No unsupported section, extract all images normally
    IMAGES=$(git show "$(git rev-list -n 1 --before="$SCAN_DATE" main)":rhoai-$VER.md | grep -oE '[a-z0-9.-]+(\.[a-z]{2,})?/[^ ]+@sha256:[a-f0-9]{64}' | grep -v -E 'rhods-operator|stable|fast')
fi
cd $BASE_DIR

#IMAGES=$(grep name rhoai-disconnected-install-helper/rhoai-$VER.md | cut -f 2,3 -d: | grep -v -E 'rhods-operator|stable|fast')

mkdir -p $RELS_DIR
echo $BUNDLE $IMAGES | tr -s '[:space:]' '\n' | sort -u > $RELS_DIR/rhoai-$2.txt

# Count expected images
EXPECTED_IMAGES=$(wc -l < $RELS_DIR/rhoai-$2.txt)
echo "Expected images to process: $EXPECTED_IMAGES"

# Sequential processing (original)
# cat $RELS_DIR/rhoai-$2.txt | while read -r IMAGE; do
#     fn_generate_sbom $IMAGE $IMGS_DIR
#     fn_scan_sbom $IMAGE $IMGS_DIR
# done


# Parallel processing with xargs
echo "Stage 1: Generate SBOMs and scan images..."
cat $RELS_DIR/rhoai-$2.txt | xargs -n 1 -P $JOBS bash -c '
    IMAGE="$1"
    REPO=${IMAGE%%/*}
    BASE_IMAGE=${IMAGE##*/}
    BASE_IMAGE=${BASE_IMAGE%@*}
    SHA=${IMAGE##*@sha256:}
    WORK_DIR=$IMGS_DIR/$BASE_IMAGE
    SBOM_DIR=$WORK_DIR/sboms
    SCAN_DIR=$WORK_DIR/scans

    fn_generate_sbom "$IMAGE" "$IMGS_DIR"
    fn_scan_sbom "$IMAGE" "$IMGS_DIR"
    fn_cve_summary "$IMAGE" "$SCAN_DIR/$SHA.grype.$(date +%F).json" "$TMP_DIR/$SHA.grype.$(date +%F).tsv"
' _

# Validate Stage 1: Count SBOMs and scans
echo "Validating Stage 1..."
for IMAGE in $(cat $RELS_DIR/rhoai-$2.txt); do
    BASE_IMAGE=${IMAGE##*/}
    BASE_IMAGE=${BASE_IMAGE%@*}
    SHA=${IMAGE##*@sha256:}
    WORK_DIR=$IMGS_DIR/$BASE_IMAGE

    # Check SBOM
    if [ -f "$WORK_DIR/sboms/$SHA.syft.json" ]; then
        ((SBOMS_CREATED++))
    fi

    # Check scan
    if [ -f "$WORK_DIR/scans/$SHA.grype.$(date +%F).json" ]; then
        ((SCANS_COMPLETED++))
    fi

    # Check summary
    if [ -f "$TMP_DIR/$SHA.grype.$(date +%F).tsv" ]; then
        ((SUMMARIES_CREATED++))
    fi
done

echo "  SBOMs created: $SBOMS_CREATED/$EXPECTED_IMAGES"
echo "  Scans completed: $SCANS_COMPLETED/$EXPECTED_IMAGES"
echo "  Summaries created: $SUMMARIES_CREATED/$EXPECTED_IMAGES"

if [ $SCANS_COMPLETED -ne $EXPECTED_IMAGES ]; then
    echo "⚠️  WARNING: Not all images were scanned successfully"
fi

echo ""
echo "Stage 2: Extract unique CVEs..."
cat $RELS_DIR/rhoai-$2.txt | while read -r IMAGE; do

    BASE_IMAGE=${IMAGE##*/}
    BASE_IMAGE=${BASE_IMAGE%@*}
    SHA=${IMAGE##*@sha256:}

    if [ -f "$TMP_DIR/$SHA.grype.$(date +%F).tsv" ]; then
        tail -n +2 $TMP_DIR/$SHA.grype.$(date +%F).tsv | cut -f1 -w
    fi
done | sort -u > $TMP_DIR/rhoai-$2-unique-cves.txt

UNIQUE_CVES=$(wc -l < $TMP_DIR/rhoai-$2-unique-cves.txt)
echo "  Unique CVEs found: $UNIQUE_CVES"

echo ""
echo "Stage 3: Download VEX data for $UNIQUE_CVES unique CVEs..."
VEX_COUNT=0
while read -r CVE; do
    fn_download_vex $CVE
    ((VEX_COUNT++))
    if [ $((VEX_COUNT % 100)) -eq 0 ]; then
        echo "  Downloaded VEX data: $VEX_COUNT/$UNIQUE_CVES"
    fi
done < $TMP_DIR/rhoai-$2-unique-cves.txt
echo "  Downloaded VEX data: $VEX_COUNT/$UNIQUE_CVES"
VEX_DOWNLOADED=$VEX_COUNT

echo ""
echo "Stage 4: Enrich image CVE data..."
cat $RELS_DIR/rhoai-$2.txt | xargs -n 1 -P $JOBS bash -c '
    IMAGE="$1"
    fn_enrich_image_cve_data $IMAGE
' _

# Validate Stage 4: Count enriched files
echo "Validating Stage 4..."
for IMAGE in $(cat $RELS_DIR/rhoai-$2.txt); do
    BASE_IMAGE=${IMAGE##*/}
    BASE_IMAGE=${BASE_IMAGE%@*}
    SHA=${IMAGE##*@sha256:}
    WORK_DIR=$IMGS_DIR/$BASE_IMAGE

    # Check enriched file
    if [ -f "$WORK_DIR/scans/$SHA.grype.$(date +%F).tsv" ]; then
        ((ENRICHMENTS_COMPLETED++))
    fi
done

echo "  Enrichments completed: $ENRICHMENTS_COMPLETED/$EXPECTED_IMAGES"

if [ $ENRICHMENTS_COMPLETED -ne $EXPECTED_IMAGES ]; then
    echo "⚠️  WARNING: Not all images were enriched successfully"
fi

echo ""
echo "Stage 5: Assemble final summary file..."
mkdir -p $SUMM_DIR

SCAN_FILES_LIST=""
MISSING_FILES=0
for IMAGE in $(cat $RELS_DIR/rhoai-$2.txt); do
    REPO=${IMAGE%%/*}
    BASE_IMAGE=${IMAGE##*/}
    BASE_IMAGE=${BASE_IMAGE%@*}
    SHA=${IMAGE##*@sha256:}
    WORK_DIR=$IMGS_DIR/$BASE_IMAGE
    SBOM_DIR=$WORK_DIR/sboms
    SCAN_DIR=$WORK_DIR/scans

    TSV_PATH="$SCAN_DIR/$SHA.grype.$(date +%F).tsv"
    if [ -f "$TSV_PATH" ]; then
        SCAN_FILES_LIST="$SCAN_FILES_LIST $TSV_PATH"
    else
        ((MISSING_FILES++))
        echo "⚠️  Missing: $TSV_PATH"
    fi
done

if [ $MISSING_FILES -gt 0 ]; then
    echo "⚠️  WARNING: $MISSING_FILES enriched files are missing"
fi

FIRST_FILE=$(echo $SCAN_FILES_LIST | awk '{print $1}')
head -n 1 $FIRST_FILE > $SUMM_DIR/ocp-$1-rhoai-$2-$SCAN.tsv

for TSV_FILE in $SCAN_FILES_LIST; do
    tail -n +2 $TSV_FILE >> $SUMM_DIR/ocp-$1-rhoai-$2-$SCAN.tsv
done

# Count final output
TOTAL_CVES=$(tail -n +2 $SUMM_DIR/ocp-$1-rhoai-$2-$SCAN.tsv | wc -l)
echo "  Final summary file: $SUMM_DIR/ocp-$1-rhoai-$2-$SCAN.tsv"
echo "  Total CVE entries: $TOTAL_CVES"

# ============================================
# FINAL SUMMARY
# ============================================
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
MINUTES=$((ELAPSED / 60))
SECONDS=$((ELAPSED % 60))

echo ""
echo "=========================================="
echo "SCAN SUMMARY: RHOAI $2 on OCP $1"
echo "=========================================="
echo "Release Date: $REL_DATE"
echo "Scan Date: $(date +%F)"
echo "CVSS Threshold: $CVE_SCORE"
echo ""
echo "Stage 1: SBOM Generation & Scanning"
echo "  Expected images: $EXPECTED_IMAGES"
echo "  SBOMs created: $SBOMS_CREATED"
echo "  Scans completed: $SCANS_COMPLETED"
echo "  Summaries created: $SUMMARIES_CREATED"
echo ""
echo "Stage 2: CVE Extraction"
echo "  Unique CVEs found: $UNIQUE_CVES"
echo ""
echo "Stage 3: VEX Data Download"
echo "  VEX files downloaded: $VEX_DOWNLOADED"
echo ""
echo "Stage 4: Data Enrichment"
echo "  Enrichments completed: $ENRICHMENTS_COMPLETED"
echo ""
echo "Stage 5: Final Assembly"
echo "  Output file: $SUMM_DIR/ocp-$1-rhoai-$2-$SCAN.tsv"
echo "  Total CVE entries: $TOTAL_CVES"
echo ""
echo "Execution Time: ${MINUTES}m ${SECONDS}s"
echo ""

# Validation checks
ERROR_COUNT=0

if [ $SBOMS_CREATED -ne $EXPECTED_IMAGES ]; then
    echo "❌ ERROR: SBOM count mismatch ($SBOMS_CREATED != $EXPECTED_IMAGES)"
    ((ERROR_COUNT++))
fi

if [ $SCANS_COMPLETED -ne $EXPECTED_IMAGES ]; then
    echo "❌ ERROR: Scan count mismatch ($SCANS_COMPLETED != $EXPECTED_IMAGES)"
    ((ERROR_COUNT++))
fi

if [ $SUMMARIES_CREATED -ne $EXPECTED_IMAGES ]; then
    echo "❌ ERROR: Summary count mismatch ($SUMMARIES_CREATED != $EXPECTED_IMAGES)"
    ((ERROR_COUNT++))
fi

if [ $ENRICHMENTS_COMPLETED -ne $EXPECTED_IMAGES ]; then
    echo "❌ ERROR: Enrichment count mismatch ($ENRICHMENTS_COMPLETED != $EXPECTED_IMAGES)"
    ((ERROR_COUNT++))
fi

if [ $VEX_DOWNLOADED -ne $UNIQUE_CVES ]; then
    echo "❌ ERROR: VEX download count mismatch ($VEX_DOWNLOADED != $UNIQUE_CVES)"
    ((ERROR_COUNT++))
fi

if [ $ERROR_COUNT -eq 0 ]; then
    echo "✅ All validation checks passed"
    echo "=========================================="
    exit 0
else
    echo ""
    echo "⚠️  $ERROR_COUNT validation error(s) detected"
    echo "=========================================="
    exit 1
fi
