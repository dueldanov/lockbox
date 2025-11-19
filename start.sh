#!/bin/bash

# LockBox Node Startup Script

echo "🔒 Starting LockBox Node..."

# Check if snapshot exists
if [ ! -f "lockbox_devnet_snapshots/full_snapshot.bin" ]; then
    echo "❌ Snapshot not found! Creating genesis snapshot..."
    ./lockbox-node tool snap-gen \
        --protocolParametersPath=protocol_parameters_devnet.json \
        --mintAddress=tst1qpszqzadsym6wpppd6z037dvlejmjuke7s24hm95s9fg9vpua7vlupxvxq2 \
        --treasuryAllocation=0 \
        --outputPath=lockbox_devnet_snapshots/full_snapshot.bin
    
    if [ $? -ne 0 ]; then
        echo "❌ Failed to create snapshot!"
        exit 1
    fi
    echo "✅ Snapshot created successfully!"
fi

# Check if database is locked
if [ -f "lockbox_devnet_db/tangle/LOCK" ]; then
    echo "⚠️  Database appears to be locked. Checking for running processes..."
    if pgrep -f "lockbox-node" > /dev/null; then
        echo "❌ LockBox Node is already running!"
        echo "   Use './stop.sh' to stop it first."
        exit 1
    else
        echo "⚠️  Stale lock file detected. Removing..."
        rm -f lockbox_devnet_db/tangle/LOCK
        rm -f lockbox_devnet_db/utxo/LOCK
    fi
fi

# Start the node
echo "🚀 Launching LockBox Node..."
./lockbox-node --config config_lockbox_devnet.json

