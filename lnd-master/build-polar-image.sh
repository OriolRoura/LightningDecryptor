#!/bin/bash

# Build script for creating LND Docker image with Brontide logging for Polar
# Usage: ./build-polar-image.sh [tag_name]

set -e

# Default tag name
TAG=${1:-lnd-brontide-logging}
FULL_TAG="polarlightning/${TAG}:latest"

echo "🔨 Building LND Docker image with Brontide handshake logging..."
echo "📦 Image tag: ${FULL_TAG}"

# Build the Docker image
docker build -f Dockerfile.polar -t "${FULL_TAG}" .

echo "✅ Build completed successfully!"
echo "📋 Image details:"
docker images "${FULL_TAG}"

echo ""
echo "🚀 To use this image in Polar:"
echo "   1. Open Polar"
echo "   2. Go to Settings > Docker Images"
echo "   3. Add custom image: ${FULL_TAG}"
echo "   4. Set the image for LND nodes in your network"
echo ""
echo "🔍 To verify brontide logging works:"
echo "   1. Create a network with this LND image"
echo "   2. Set log level to 'debug' for BRNT subsystem"
echo "   3. Check logs for handshake key information"
echo ""
echo "📝 Log configuration example:"
echo "   --debuglevel=BRNT:debug"
echo "   or in lnd.conf: debuglevel=BRNT:debug"
