#!/bin/bash 


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
VER="$2"
[[ "$VER" == *.0 ]] && VER="${VER%.0}"

REL_DATE=$(grep -F $2 $RELS_DIR/../rhoai-dates.csv | cut -f2 -d,)


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

    {
    echo "id\tseverity\tbase-score\tpackage\tversion\tfix-verion\tlocation\trel-base-score\tcontainer-build-date" 
    jq -r '
     . as $doc
     | ($doc.source.target.labels["build-date"]? // "WTF") as $build
     | $doc.matches[] 
     | [
        .vulnerability.id,
        .vulnerability.severity,
        ([ .vulnerability.cvss[]?.metrics.baseScore ] | max),
        .artifact.name, 
	    .artifact.version, 
        (.vulnerability.fix.versions[0]? // "None"), 
	    (.artifact.locations | map(.path) | join("; ")),
        ([ .relatedVulnerabilities[]?.cvss[]?.metrics.baseScore ] | max // "NA"),
        (($build | tostring) | split("T")[0])
       ] 
     | @tsv
    ' $1 | sort -k3 -n | awk -F\t '($3+0 > 7.9) || ($8+0 > 7.9)'  
} > $2

}

echo "CLEAN ENVIRONMENT: $TMP_DIR"
rm $TMP_DIR/*.tsv $TMP_DIR/*.dat

echo "GET IMAGES: rhoai $2 images on OCP $1" 
CATALOG=$(podman run --rm -it --entrypoint bash registry.redhat.io/redhat/redhat-operator-index:v$1 -c 'cat /configs/rhods-operator/catalog.json')
BUNDLE=$(echo $CATALOG | tr -d '\000-\037' | jq -r '
    select( .schema=="olm.bundle" ) 
    | select( .name=="rhods-operator.'${RHOAI_VERSION:-$2}'" ) 
    | .relatedImages[] 
    | if .name == "" then "olm_bundle: " + .image else .name + ": " + .image end
    ' | cut -f 2 -w)

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


cat $RELS_DIR/rhoai-$2.txt | while read -r IMAGE; do #xargs -n 1 -P $JOBS bash -c '
    fn_generate_sbom $IMAGE $IMGS_DIR
    fn_scan_sbom $IMAGE $IMGS_DIR
#' -
done


cat $RELS_DIR/rhoai-$2.txt | while read -r IMAGE; do 
    
    REPO=${IMAGE%%/*}
    BASE_IMAGE=${IMAGE##*/}
    BASE_IMAGE=${BASE_IMAGE%@*}
    SHA=${IMAGE##*@sha256:}
    WORK_DIR=$IMGS_DIR/$BASE_IMAGE
    SBOM_DIR=$WORK_DIR/sboms
    SCAN_DIR=$WORK_DIR/scans

    echo "SUMMARIZE CVEs: $IMAGE"
    fn_cve_summary $SCAN_DIR/$SHA.grype.$(date +%F).json $TMP_DIR/$SHA.grype.$(date +%F).tsv

    {
    echo "DISCOVERY_DATE\tFIX_DATE"
    tail -n +2 $TMP_DIR/$SHA.grype.$(date +%F).tsv | cut -f1 -w | while read -r CVE; do 
        
        if [[ "$CVE" == CVE* ]]; then 
	        YEAR=$(echo $CVE | cut -d- -f2)
	        CVE_LOW=$(printf '%s' "$CVE" | tr '[:upper:]' '[:lower:]')
        else 
            mkdir -p $VEX_DIR/GHSA
            if [ ! -s $VEX_DIR/GHSA/$CVE/$CVE.json ] || [ $(find $VEX_DIR/GHSA/$CVE.json -mtime +30 2>/dev/null) ]; then 
                gh api https://api.github.com/advisories/$CVE > $VEX_DIR/GHSA/$CVE.json 
                sleep 1
            fi 

            CVE_TMP=$(cat $VEX_DIR/GHSA/$CVE.json | jq -r '.cve_id')
            YEAR=$(echo $CVE_TMP | cut -d- -f2)
            CVE_LOW=$(printf '%s' $CVE_TMP | tr '[:upper:]' '[:lower:]')
        fi

        mkdir -p $VEX_DIR/$YEAR
        if [ ! -s $VEX_DIR/$YEAR/$CVE_LOW.json ] || [ $(find $VEX_DIR/$YEAR/$CVE_LOW.json -mtime +30 2>/dev/null) ]; then
            curl -s -o $VEX_DIR/$YEAR/$CVE_LOW.json $VEX_URL/$YEAR/$CVE_LOW.json 
        fi
            

	    cat $VEX_DIR/$YEAR/$CVE_LOW.json | jq -r '
                [ 
                    ([.vulnerabilities[].discovery_date?] | map(select(.!=null)) | sort | .[0] | split("T")[0] // "NOT-FOUND"),
                    ([.vulnerabilities[].remediations[]?.date?] | map(select(.!=null)) | sort | .[0] | split("T")[0] // "NOT-FOUND")
                ] | @tsv
                '  2> /dev/null || echo "NO-RH-VEX\tNO-RH-VEX"
    done
    } > $TMP_DIR/$SHA.grype.$(date +%F).vex.dat

    N=$(wc -l < $TMP_DIR/$SHA.grype.$(date +%F).tsv)
    ((N--))
    echo "RELEASE_DATE\tREPOSITORY\tIMAGE\tSHA" > $TMP_DIR/$SHA.meta.dat
    yes "$(printf '%s\t%s\t%s\t%s\n' $REL_DATE $REPO $BASE_IMAGE $SHA)" | head -n $N >> $TMP_DIR/$SHA.meta.dat


    paste $TMP_DIR/$SHA.grype.$(date +%F).tsv $TMP_DIR/$SHA.grype.$(date +%F).vex.dat $TMP_DIR/$SHA.meta.dat > $SCAN_DIR/$SHA.grype.$(date +%F).tsv

done 

mkdir -p $SUMM_DIR
FIRST_FILE=$(find . -type f -name "*$(date +%F).tsv" | sort | head -n 1)
head -n 1 $FIRST_FILE > $SUMM_DIR/ocp-$1-rhoai-$2.tsv 
find . -type f -name "*$(date +%F).tsv" -exec tail -q -n +2 {} + >> $SUMM_DIR/ocp-$1-rhoai-$2-$SCAN.tsv

