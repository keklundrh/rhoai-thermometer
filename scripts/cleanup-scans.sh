#!/bin/bash
# Cleanup old scan data to free up disk space while preserving optimal caching
#
# Usage: ./cleanup-scans.sh [--dry-run] [--keep-days N]
#
# This script removes:
# - Old Grype scan JSON files (*.grype.YYYY-MM-DD.json)
# - Old TSV summary files (*.grype.YYYY-MM-DD.tsv)
#
# This script NEVER removes:
# - SBOM files (*.syft.json) - these are expensive to regenerate
# - The most recent scan files (based on --keep-days)

set -e

# Default: keep scans from the last 7 days
KEEP_DAYS=7
DRY_RUN=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --keep-days)
            KEEP_DAYS="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--dry-run] [--keep-days N]"
            echo ""
            echo "Options:"
            echo "  --dry-run        Show what would be deleted without actually deleting"
            echo "  --keep-days N    Keep scans from the last N days (default: 7)"
            echo "  -h, --help       Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

IMAGES_DIR="data/images"

if [ ! -d "$IMAGES_DIR" ]; then
    echo "ERROR: $IMAGES_DIR directory not found"
    exit 1
fi

echo "==================================================="
echo "RHOAI Thermometer - Scan Data Cleanup"
echo "==================================================="
echo "Directory: $IMAGES_DIR"
echo "Keep scans from last: $KEEP_DAYS days"
echo "Dry run: $DRY_RUN"
echo ""

# Calculate cutoff date (N days ago)
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    CUTOFF_DATE=$(date -v-${KEEP_DAYS}d +%Y-%m-%d)
else
    # Linux
    CUTOFF_DATE=$(date -d "${KEEP_DAYS} days ago" +%Y-%m-%d)
fi

echo "Cutoff date: $CUTOFF_DATE"
echo "Files older than this will be removed."
echo ""

# Function to get file size in human readable format
get_size() {
    du -sh "$1" 2>/dev/null | cut -f1
}

# Count and size before cleanup
echo "Analyzing current disk usage..."
TOTAL_SIZE_BEFORE=$(du -sh "$IMAGES_DIR" 2>/dev/null | cut -f1)
JSON_COUNT=$(find "$IMAGES_DIR" -type f -name "*.grype.*.json" 2>/dev/null | wc -l | tr -d ' ')
TSV_COUNT=$(find "$IMAGES_DIR" -type f -name "*.grype.*.tsv" 2>/dev/null | wc -l | tr -d ' ')
SBOM_COUNT=$(find "$IMAGES_DIR" -type f -name "*.syft.json" 2>/dev/null | wc -l | tr -d ' ')

echo "Current state:"
echo "  Total size: $TOTAL_SIZE_BEFORE"
echo "  Grype JSON files: $JSON_COUNT"
echo "  TSV summary files: $TSV_COUNT"
echo "  SBOM files: $SBOM_COUNT (will NOT be deleted)"
echo ""

# Find old files
echo "Finding files to remove..."
OLD_JSON=$(find "$IMAGES_DIR" -type f -name "*.grype.*.json" 2>/dev/null | \
    grep -E "\.grype\.[0-9]{4}-[0-9]{2}-[0-9]{2}\.json$" | \
    while read file; do
        FILE_DATE=$(echo "$file" | grep -oE "[0-9]{4}-[0-9]{2}-[0-9]{2}" | tail -1)
        if [[ "$FILE_DATE" < "$CUTOFF_DATE" ]]; then
            echo "$file"
        fi
    done)

OLD_TSV=$(find "$IMAGES_DIR" -type f -name "*.grype.*.tsv" 2>/dev/null | \
    grep -E "\.grype\.[0-9]{4}-[0-9]{2}-[0-9]{2}\.tsv$" | \
    while read file; do
        FILE_DATE=$(echo "$file" | grep -oE "[0-9]{4}-[0-9]{2}-[0-9]{2}" | tail -1)
        if [[ "$FILE_DATE" < "$CUTOFF_DATE" ]]; then
            echo "$file"
        fi
    done)

OLD_JSON_COUNT=$(echo "$OLD_JSON" | grep -c "." 2>/dev/null || echo "0")
OLD_TSV_COUNT=$(echo "$OLD_TSV" | grep -c "." 2>/dev/null || echo "0")

echo "Files to be removed:"
echo "  Old Grype JSON files: $OLD_JSON_COUNT"
echo "  Old TSV summary files: $OLD_TSV_COUNT"
echo ""

if [ "$OLD_JSON_COUNT" -eq 0 ] && [ "$OLD_TSV_COUNT" -eq 0 ]; then
    echo "No old files to remove. Cleanup complete!"
    exit 0
fi

# Calculate space that will be freed (approximate)
if [ "$OLD_JSON_COUNT" -gt 0 ]; then
    SAMPLE_JSON_SIZE=$(echo "$OLD_JSON" | head -1 | xargs du -sh 2>/dev/null | cut -f1)
    echo "Sample JSON file size: $SAMPLE_JSON_SIZE"
fi

if [ "$DRY_RUN" = true ]; then
    echo ""
    echo "=== DRY RUN MODE ==="
    echo "The following files would be deleted:"
    echo ""

    if [ "$OLD_JSON_COUNT" -gt 0 ]; then
        echo "Old Grype JSON files (showing first 10):"
        echo "$OLD_JSON" | head -10
        if [ "$OLD_JSON_COUNT" -gt 10 ]; then
            echo "... and $((OLD_JSON_COUNT - 10)) more"
        fi
        echo ""
    fi

    if [ "$OLD_TSV_COUNT" -gt 0 ]; then
        echo "Old TSV files (showing first 10):"
        echo "$OLD_TSV" | head -10
        if [ "$OLD_TSV_COUNT" -gt 10 ]; then
            echo "... and $((OLD_TSV_COUNT - 10)) more"
        fi
        echo ""
    fi

    echo "Run without --dry-run to actually delete these files."
else
    echo ""
    echo "=== DELETING FILES ==="

    DELETED=0

    if [ "$OLD_JSON_COUNT" -gt 0 ]; then
        echo "Deleting old Grype JSON files..."
        echo "$OLD_JSON" | while read file; do
            rm -f "$file"
            DELETED=$((DELETED + 1))
            if [ $((DELETED % 100)) -eq 0 ]; then
                echo "  Deleted $DELETED files..."
            fi
        done
        echo "  Deleted $OLD_JSON_COUNT JSON files"
    fi

    if [ "$OLD_TSV_COUNT" -gt 0 ]; then
        echo "Deleting old TSV files..."
        echo "$OLD_TSV" | while read file; do
            rm -f "$file"
        done
        echo "  Deleted $OLD_TSV_COUNT TSV files"
    fi

    echo ""
    echo "=== CLEANUP COMPLETE ==="

    # Show final stats
    TOTAL_SIZE_AFTER=$(du -sh "$IMAGES_DIR" 2>/dev/null | cut -f1)
    JSON_COUNT_AFTER=$(find "$IMAGES_DIR" -type f -name "*.grype.*.json" 2>/dev/null | wc -l | tr -d ' ')
    TSV_COUNT_AFTER=$(find "$IMAGES_DIR" -type f -name "*.grype.*.tsv" 2>/dev/null | wc -l | tr -d ' ')

    echo ""
    echo "Final state:"
    echo "  Total size: $TOTAL_SIZE_AFTER (was $TOTAL_SIZE_BEFORE)"
    echo "  Grype JSON files: $JSON_COUNT_AFTER (was $JSON_COUNT)"
    echo "  TSV summary files: $TSV_COUNT_AFTER (was $TSV_COUNT)"
    echo "  SBOM files: $SBOM_COUNT (unchanged)"
    echo ""
    echo "Space freed: Deleted $((OLD_JSON_COUNT + OLD_TSV_COUNT)) files"
fi
