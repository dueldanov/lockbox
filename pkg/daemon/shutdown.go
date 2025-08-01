package daemon

const (
	PriorityCloseDatabase = iota
	PriorityFlushToDatabase
	PriorityDatabaseHealth
	PriorityTipselection
	PriorityMilestoneSolidifier
	PriorityMilestoneProcessor
	PrioritySolidifierGossip
	PriorityReceiveTxWorker
	PriorityMessageProcessor
	PriorityPeerGossipProtocolWrite
	PriorityPeerGossipProtocolRead
	PriorityGossipService
	PriorityRequestsProcessor
	PriorityBroadcastQueue
	PriorityP2PManager
	PriorityAutopeering
	PriorityHeartbeats
	PriorityWarpSync
	PrioritySnapshots
	PriorityPruning
	PriorityMetricsUpdater
	PriorityPoWHandler
	PriorityRestAPI
	PriorityIndexer
	PriorityStatusReport
	PriorityPrometheus
	PriorityLockBox // Add LockBox priority
)