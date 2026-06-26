#!/bin/bash
# Usage: ./rh-summarize.sh <OCP_VERSION> <RHOAI_VERSION> [today|release] [CVSS_THRESHOLD]
# Examples:
#   ./rh-summarize.sh 4.18 2.19.0              # Scan at release date, default CVSS 0.0 (no filtering)
#   ./rh-summarize.sh 4.18 2.19.0 today        # Scan with today's CVE data, default CVSS 0.0
#   ./rh-summarize.sh 4.18 2.19.0 release 8.0  # Scan at release date, filter CVSS >= 8.0


#BASENAME=${1##*/}
#IMAGE=${BASENAME%%:*}
#EXPORT_IMAGE=/tmp/${IMAGE}.tar
#GRYPE_DIR=grype_scans
#GRYPE_OUT=${GRYPE_DIR}/${IMAGE}.grype.$(date +%m%d%Y).json
#SUMM_TMP=/tmp/${IMAGE}.grype.$(date +%m%d%Y).tsv
#SUMM_OUT=${GRYPE_OUT%.*}.tsv
BASE_DIR=$(pwd)
RDIH_DIR=rhoai-disconnected-install-helper
VEX_URL="https://security.access.redhat.com/data/csaf/v2/vex"
#VEX_TMP=/tmp/${IMAGE}.vex.dat
RELS_DIR=data/releases/$1
IMGS_DIR=data/images
SUMM_DIR=data/summary
VEX_DIR=data/vex
TMP_DIR=/tmp/
JOBS=8
CVE_SCORE=${4:-0.0}  # Default to 0.0 (no filtering) to let frontend handle filtering
VER="$2"
[[ "$VER" == *.0 ]] && VER="${VER%.0}"

REL_DATE=$(grep -F $2 $RELS_DIR/../rhoai-dates.csv | cut -f2 -d,)
CUTOFF_FILE=$TMP_DIR/vex-cutoff-30days
touch -d "30 days ago" $CUTOFF_FILE 2> /dev/null || touch -t $(date -v-30d +%Y%m%d%H%M.%S) $CUTOFF_FILE 2>/dev/null

# Export variables so available to xargs

export IMGS_DIR
export JOBS
export CVE_SCORE
export TMP_DIR
export VEX_DIR
export RELS_DIR
export REL_DATE

if [[ $3 == "today" ]]; then 
    SCAN_DATE=$(date +%F)
    SCAN="CVEs-TODAY"
    
else 
    SCAN_DATE=$REL_DATE
    SCAN="RELEASE"
fi

#TODO 
# create reference file to join later, or pass args to jq to print on each line
# GHSA has published date in the local json file, don't need to hit RH VEX DATA since RH doesn't always have CVEs mapped to GHSA
# need to make it clear the cve counter looks at CVEs on release date 
# add parallel scanning back to the script


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

    # scan image 
    mkdir -p $SCAN_DIR
    if [ ! -s $SCAN_DIR/$SHA.grype.$(date +%F).json ]; then
        cmd="grype sbom:$SBOM_DIR/$SHA.syft.json -o json --quiet > $SCAN_DIR/$SHA.grype.$(date +%F).json"
        echo "RUN SCAN: using $cmd" 
        eval $cmd
    else
        echo "SKIP SCAN: $IMAGE" 
    fi
}

fn_cve_summary () {

    echo "SUMMARIZE FILTERED ($CVE_SCORE) CVEs: $1"

    {
    echo -e "id\tseverity\tbase-score\tpackage\tversion\tfix-verion\trel-base-score\tcontainer-build-date" 
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
    ' $2 | sort -k3 -n | awk -v score="$CVE_SCORE" -F\t '($3+0 > score ) || ($7+0 > score)'  
} > $3

}

fn_download_vex() {
    local CVE=$1 

    # standard CVE, get RH VEX
    if [[ "$CVE" == CVE-* ]]; then 
        YEAR=$(echo $CVE | cut -d- -f2)
        CVE_LOW=$(printf '%s' "$CVE" | tr '[:upper:]' '[:lower:]') 

        mkdir -p $VEX_DIR/$YEAR
        if [ ! -s $VEX_DIR/$YEAR/$CVE_LOW.json ] || [ $VEX_DIR/$YEAR/$CVE_LOW.json -ot $CUTOFF_FILE ]; then
            curl -s -o $VEX_DIR/$YEAR/$CVE_LOW.json $VEX_URL/$YEAR/$CVE_LOW.json 
        fi
    elif [[ "$CVE" == GHSA-* ]]; then 
        mkdir -p $VEX_DIR/GHSA

        if [ ! -s $VEX_DIR/GHSA/$CVE.json ] || [ $VEX_DIR/GHSA/$CVE.json -ot $CUTOFF_FILE ]; then
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
            if [ ! -s $VEX_DIR/$YEAR/$CVE_LOW.json ] || [ $VEX_DIR/$YEAR/$CVE_LOW.json -ot $CUTOFF_FILE ]; then
                curl -s -o $VEX_DIR/$YEAR/$CVE_LOW.json $VEX_URL/$YEAR/$CVE_LOW.json
            fi
        fi
    elif [[ "$CVE" == GO-* ]]; then 
        : # not doing yet 
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
            echo -e "NO-GO-VEX\tNO-GO-VEX"
        else
            echo -e "NO-RH-VEX\tNO-RH-VEX"
        fi

    done
    } > $TMP_DIR/$SHA.grype.$(date +%F).vex.dat

    N=$(wc -l < $TMP_DIR/$SHA.grype.$(date +%F).tsv)
    ((N--))
    echo -e "RELEASE_DATE\tREPOSITORY\tIMAGE\tSHA" > $TMP_DIR/$SHA.meta.dat
    yes "$(printf '%s\t%s\t%s\t%s\n' $REL_DATE $REPO $BASE_IMAGE $SHA)" | head -n $N >> $TMP_DIR/$SHA.meta.dat

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

# Fetch the catalog with error handling
CATALOG=$(podman run --rm --entrypoint bash registry.redhat.io/redhat/redhat-operator-index:v$1 -c 'cat /configs/rhods-operator/catalog.json' 2>&1)
CATALOG_EXIT=$?

# Check if podman command failed
if [ $CATALOG_EXIT -ne 0 ]; then
    echo "ERROR: Failed to fetch operator catalog for OCP $1"
    echo "$CATALOG" | grep -i error
    exit 1
fi

# Check if catalog is valid JSON
if ! echo "$CATALOG" | tr -d '\000-\037' | jq empty 2>/dev/null; then
    echo "ERROR: Invalid catalog data received from OCP $1"
    exit 1
fi

# Extract bundle images
BUNDLE=$(echo $CATALOG | tr -d '\000-\037' | jq -r '
    select( .schema=="olm.bundle" )
    | select( .name=="rhods-operator.'${RHOAI_VERSION:-$2}'" )
    | .relatedImages[]
    | if .name == "" then "olm_bundle: " + .image else .name + ": " + .image end
    ' | cut -f 2 -w)

# Check if any bundle images were found
if [ -z "$BUNDLE" ]; then
    echo "ERROR: No bundle found for rhods-operator.$2 in OCP $1 catalog"
    echo ""
    echo "Available versions in this catalog:"
    echo "$CATALOG" | tr -d '\000-\037' | jq -r 'select(.schema=="olm.bundle") | .name' | grep "^rhods-operator\." | sort -V | tail -10
    echo ""
    echo "Hint: RHOAI 3.x requires OCP 4.20 or later"
    exit 1
fi

cd $RDIH_DIR
echo "UPDATE: disconnected install helper repo"
# git pull
git fetch origin
git checkout main 
git reset --hard origin/main

IMAGES=$(git show "$(git rev-list -n 1 --before="$SCAN_DATE" main)":rhoai-$VER.md | grep name | cut -f 2,3 -d: | grep -v -E 'rhods-operator|stable|fast')
cd $BASE_DIR

#IMAGES=$(grep name rhoai-disconnected-install-helper/rhoai-$VER.md | cut -f 2,3 -d: | grep -v -E 'rhods-operator|stable|fast')

mkdir -p $RELS_DIR
echo $BUNDLE $IMAGES | tr -s '[:space:]' '\n' > $RELS_DIR/rhoai-$2.txt

# Sequential processing (original)
# cat $RELS_DIR/rhoai-$2.txt | while read -r IMAGE; do
#     fn_generate_sbom $IMAGE $IMGS_DIR
#     fn_scan_sbom $IMAGE $IMGS_DIR
# done


# Parallel processing with xargs
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

echo "GET UNIQUE CVEs" 
cat $RELS_DIR/rhoai-$2.txt | while read -r IMAGE; do
    
    BASE_IMAGE=${IMAGE##*/}
    BASE_IMAGE=${BASE_IMAGE%@*}
    SHA=${IMAGE##*@sha256:}

    if [ -f "$TMP_DIR/$SHA.grype.$(date +%F).tsv" ]; then 
        tail -n +2 $TMP_DIR/$SHA.grype.$(date +%F).tsv | cut -f1 -w 
    fi
done | sort -u > $TMP_DIR/rhoai-$2-unique-cves.txt 

echo "GET VEX FOR UNIQUE CVES"
while read -r CVE; do 
    fn_download_vex $CVE
done < $TMP_DIR/rhoai-$2-unique-cves.txt

cat $RELS_DIR/rhoai-$2.txt | xargs -n 1 -P $JOBS bash -c ' 
    IMAGE="$1"
    fn_enrich_image_cve_data $IMAGE
' _

mkdir -p $SUMM_DIR

# Original - bugged
# FIRST_FILE=$(find . -type f -name "*$(date +%F).tsv" | sort | head -n 1)
# head -n 1 $FIRST_FILE > $SUMM_DIR/ocp-$1-rhoai-$2-$SCAN.tsv 
# find . -type f -name "*$(date +%F).tsv" -exec tail -q -n +2 {} + >> $SUMM_DIR/ocp-$1-rhoai-$2-$SCAN.tsv

SCAN_FILES_LIST=""
for IMAGE in $(cat $RELS_DIR/rhoai-$2.txt); do
    REPO=${IMAGE%%/*}
    BASE_IMAGE=${IMAGE##*/}
    BASE_IMAGE=${BASE_IMAGE%@*}
    SHA=${IMAGE##*@sha256:}
    WORK_DIR=$IMGS_DIR/$BASE_IMAGE
    SBOM_DIR=$WORK_DIR/sboms
    SCAN_DIR=$WORK_DIR/scans

    SCAN_FILES_LIST="$SCAN_FILES_LIST $SCAN_DIR/$SHA.grype.$(date +%F).tsv"
done

FIRST_FILE=$(echo $SCAN_FILES_LIST | awk '{print $1}')
head -n 1 $FIRST_FILE > $SUMM_DIR/ocp-$1-rhoai-$2-$SCAN.tsv

for TSV_FILE in $SCAN_FILES_LIST; do 
    tail -n +2 $TSV_FILE >> $SUMM_DIR/ocp-$1-rhoai-$2-$SCAN.tsv
done
