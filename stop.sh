#!/bin/bash

# LockBox Node Stop Script

echo "🛑 Stopping LockBox Node..."

# Find and kill the process
if pgrep -f "lockbox-node" > /dev/null; then
    pkill -SIGTERM -f "lockbox-node"
    echo "⏳ Waiting for graceful shutdown..."
    sleep 3
    
    # Check if still running
    if pgrep -f "lockbox-node" > /dev/null; then
        echo "⚠️  Process still running, forcing shutdown..."
        pkill -SIGKILL -f "lockbox-node"
        sleep 1
    fi
    
    echo "✅ LockBox Node stopped"
else
    echo "ℹ️  LockBox Node is not running"
fi

# Clean up lock files
if [ -f "lockbox_devnet_db/tangle/LOCK" ]; then
    echo "🧹 Cleaning up lock files..."
    rm -f lockbox_devnet_db/tangle/LOCK
    rm -f lockbox_devnet_db/utxo/LOCK
fi

echo "✅ Done"

