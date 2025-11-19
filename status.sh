#!/bin/bash

# LockBox Node Status Script

echo "📊 LockBox Node Status"
echo "====================="

# Check if process is running
if pgrep -f "lockbox-node" > /dev/null; then
    echo "✅ Status: RUNNING"
    echo ""
    echo "Process info:"
    ps aux | grep lockbox-node | grep -v grep | awk '{print "   PID: "$2", CPU: "$3"%, MEM: "$4"%"}'
else
    echo "❌ Status: STOPPED"
fi

echo ""

# Check API
if curl -s http://127.0.0.1:14265/health > /dev/null 2>&1; then
    echo "✅ REST API: http://127.0.0.1:14265"
    echo ""
    echo "Node Info:"
    curl -s http://127.0.0.1:14265/api/core/v2/info | jq -r '
        "   Name: \(.name)",
        "   Version: \(.version)",
        "   Network: \(.protocol.networkName)",
        "   Token: \(.baseToken.name) (\(.baseToken.tickerSymbol))",
        "   Healthy: \(.status.isHealthy)",
        "   Latest Milestone: \(.status.latestMilestone.index)",
        "   Confirmed Milestone: \(.status.confirmedMilestone.index)"
    ' 2>/dev/null || echo "   (jq not installed, use: curl http://127.0.0.1:14265/api/core/v2/info)"
else
    echo "❌ REST API: Not responding"
fi

echo ""
echo "Database:"
if [ -d "lockbox_devnet_db" ]; then
    DB_SIZE=$(du -sh lockbox_devnet_db 2>/dev/null | awk '{print $1}')
    echo "   Path: lockbox_devnet_db/"
    echo "   Size: $DB_SIZE"
    if [ -f "lockbox_devnet_db/tangle/LOCK" ]; then
        echo "   Status: Locked (in use)"
    else
        echo "   Status: Unlocked"
    fi
else
    echo "   Not initialized"
fi

