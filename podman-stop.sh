#!/bin/bash
# Stop RHOAI Thermometer container

CONTAINER_NAME="rhoai-thermometer"

echo "Stopping RHOAI Thermometer..."
podman stop ${CONTAINER_NAME}
podman rm ${CONTAINER_NAME}

echo "✅ Container stopped and removed"
