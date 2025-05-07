# Stop script on first error
$ErrorActionPreference = "Stop"

# --- Version variables ---
$controllerVersion = "0.3.0-python"
$haproxyVersion = "0.2.1"

# --- Build and push hairpin-proxy-controller ---
Write-Host "Building hairpin-proxy-controller:$controllerVersion..."
Set-Location "./hairpin-proxy-controller"
docker build -t "12ozcode/hairpin-proxy-controller:$controllerVersion" .
docker push "12ozcode/hairpin-proxy-controller:$controllerVersion"
Set-Location ".."

# --- Build and push hairpin-proxy-haproxy ---
Write-Host "Building hairpin-proxy-haproxy:$haproxyVersion..."
Set-Location "./hairpin-proxy-haproxy"
docker build -t "12ozcode/hairpin-proxy-haproxy:$haproxyVersion" .
docker push "12ozcode/hairpin-proxy-haproxy:$haproxyVersion"
Set-Location ".."

Write-Host "✅ All builds and pushes completed successfully."
