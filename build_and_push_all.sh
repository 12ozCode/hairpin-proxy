#!/bin/sh
set -e  # Exit immediately if any command fails

# --- Version variables ---
controllerVersion="0.3.0-python"
haproxyVersion="0.2.1"

# --- Build and push hairpin-proxy-controller ---
echo "Building hairpin-proxy-controller:$controllerVersion..."
cd ./hairpin-proxy-controller
docker build -t "12ozcode/hairpin-proxy-controller:$controllerVersion" .
docker push "12ozcode/hairpin-proxy-controller:$controllerVersion"
cd ..

# --- Build and push hairpin-proxy-haproxy ---
echo "Building hairpin-proxy-haproxy:$haproxyVersion..."
cd ./hairpin-proxy-haproxy
docker build -t "12ozcode/hairpin-proxy-haproxy:$haproxyVersion" .
docker push "12ozcode/hairpin-proxy-haproxy:$haproxyVersion"
cd ..

echo "✅ All builds and pushes completed successfully."
