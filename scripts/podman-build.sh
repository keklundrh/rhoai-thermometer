#!/bin/bash
# Build RHOAI Thermometer container image with Podman

set -e

IMAGE_NAME="rhoai-thermometer"
IMAGE_TAG="latest"

echo "Building container image: ${IMAGE_NAME}:${IMAGE_TAG}"
podman build -t ${IMAGE_NAME}:${IMAGE_TAG} .

echo ""
echo "✅ Build complete!"
echo ""
echo "To run the container:"
echo "  ./podman-run.sh"
echo ""
echo "To run with custom data path:"
echo "  podman run -p 8501:8501 -v /path/to/data:/data:ro ${IMAGE_NAME}:${IMAGE_TAG}"
