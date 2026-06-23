#!/bin/bash
# Run RHOAI Thermometer container with Podman

set -e

IMAGE_NAME="rhoai-thermometer"
IMAGE_TAG="latest"
CONTAINER_NAME="rhoai-thermometer"
DATA_PATH="$(pwd)/data"

# Stop and remove existing container if running
if podman ps -a --format "{{.Names}}" | grep -q "^${CONTAINER_NAME}$"; then
    echo "Stopping existing container..."
    podman stop ${CONTAINER_NAME} 2>/dev/null || true
    podman rm ${CONTAINER_NAME} 2>/dev/null || true
fi

echo "Starting RHOAI Thermometer..."
echo "Data directory: ${DATA_PATH}"
echo ""

# Run container
podman run -d \
    --name ${CONTAINER_NAME} \
    -p 8501:8501 \
    -v ${DATA_PATH}:/data:ro \
    ${IMAGE_NAME}:${IMAGE_TAG}

echo "✅ Container started!"
echo ""
echo "Access the dashboard at: http://localhost:8501"
echo ""
echo "Useful commands:"
echo "  podman logs ${CONTAINER_NAME}           # View logs"
echo "  podman logs -f ${CONTAINER_NAME}        # Follow logs"
echo "  podman stop ${CONTAINER_NAME}           # Stop container"
echo "  podman start ${CONTAINER_NAME}          # Start container"
echo "  podman restart ${CONTAINER_NAME}        # Restart container"
