#!/bin/bash
set -e

echo "═══════════════════════════════════════"
echo "     DOGE WSL Runtime Qualification"
echo "═══════════════════════════════════════"
echo ""

echo "=== OS ==="
uname -a
echo ""
cat /etc/os-release | head -5
echo ""

echo "=== Go ==="
if command -v go &>/dev/null; then
    echo "✓ go → $(which go)"
    go version
else
    echo "✗ go → NOT FOUND"
fi
echo ""

echo "=== Security Tools ==="
TOOLS="nmap httpx subfinder ffuf nuclei dnsx katana"
FOUND=0
MISSING=0
for tool in $TOOLS; do
    if command -v "$tool" &>/dev/null; then
        echo "✓ $tool → $(which $tool)"
        FOUND=$((FOUND + 1))
    else
        echo "✗ $tool → NOT FOUND"
        MISSING=$((MISSING + 1))
    fi
done
echo ""
echo "Found: $FOUND/7"
echo "Missing: $MISSING/7"
echo ""

echo "=== Tool Versions ==="
for tool in $TOOLS; do
    if command -v "$tool" &>/dev/null; then
        case "$tool" in
            nmap) echo "$tool: $(nmap --version 2>&1 | head -1)" ;;
            httpx) echo "$tool: $(httpx -version 2>&1 | head -1)" ;;
            subfinder) echo "$tool: $(subfinder -version 2>&1 | head -1)" ;;
            ffuf) echo "$tool: $(ffuf -V 2>&1 | head -1)" ;;
            nuclei) echo "$tool: $(nuclei -version 2>&1 | head -1)" ;;
            dnsx) echo "$tool: $(dnsx -version 2>&1 | head -1)" ;;
            katana) echo "$tool: $(katana -version 2>&1 | head -1)" ;;
        esac
    fi
done
echo ""

echo "=== DOGE Build Test ==="
cd /mnt/c/Users/k8659/OneDrive/Desktop/Doge
echo "Working directory: $(pwd)"
echo ""

echo "Building DOGE..."
go build -o /tmp/doge ./cmd/workspace
echo "✓ Build successful"
echo ""

echo "/tmp/doge --help"
/tmp/doge --help 2>&1 | head -20
echo ""

echo "=== DOGE Test Suite ==="
echo "Running tests..."
RESULT=$(go test ./... 2>&1)
PASS_COUNT=$(echo "$RESULT" | grep -c "^ok" || true)
FAIL_COUNT=$(echo "$RESULT" | grep -c "^FAIL" || true)
echo "$RESULT" | grep -E "^ok|^FAIL|^---" | tail -20
echo ""
echo "Modules passing: $PASS_COUNT"
echo "Modules failing: $FAIL_COUNT"
echo ""

echo "═══════════════════════════════════════"
echo "     Qualification Complete"
echo "═══════════════════════════════════════"
