#!/bin/bash

# LockBox Node Build Script

echo "🔨 Building LockBox Node..."

# Get commit hash for version info
commit_hash=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Build the binary
echo "📦 Compiling Go binary..."
go build -o lockbox-node -ldflags="-s -w -X github.com/dueldanov/lockbox/v2/components/app.Version=${commit_hash}"

if [ $? -ne 0 ]; then
    echo "❌ Build failed!"
    exit 1
fi

echo "✅ Build successful!"

# Code signing for macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "🍎 Detected macOS - applying code signature..."
    codesign --force --deep --sign - ./lockbox-node
    
    if [ $? -ne 0 ]; then
        echo "⚠️  Code signing failed, but binary was built."
        echo "   You may need to manually sign it with:"
        echo "   codesign --force --deep --sign - ./lockbox-node"
    else
        echo "✅ Code signature applied!"
    fi
fi

echo ""
echo "🚀 Ready to run! Start the node with: ./start.sh"

