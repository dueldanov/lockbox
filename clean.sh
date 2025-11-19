#!/bin/bash

# LockBox Node Clean Script - removes all data and starts fresh

echo "🧹 LockBox Node Clean Script"
echo "============================"
echo ""
echo "⚠️  WARNING: This will delete ALL node data!"
echo "   - Database (lockbox_devnet_db/)"
echo "   - P2P store (lockbox_devnet_p2pstore/)"
echo "   - Snapshots (lockbox_devnet_snapshots/)"
echo ""
read -p "Are you sure? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "❌ Cancelled"
    exit 0
fi

# Stop node if running
if pgrep -f "lockbox-node" > /dev/null; then
    echo "🛑 Stopping running node..."
    ./stop.sh
fi

# Remove data directories
echo "🗑️  Removing data directories..."
rm -rf lockbox_devnet_db/
rm -rf lockbox_devnet_p2pstore/
rm -rf lockbox_devnet_snapshots/

# Remove log files
rm -f shutdown.log

echo "✅ All data removed!"
echo ""
echo "To start fresh, run: ./start.sh"

