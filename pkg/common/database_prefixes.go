package common

const (
	StorePrefixSnapshot           byte = 1
	StorePrefixBlocks             byte = 2
	StorePrefixBlockMetadata      byte = 3
	StorePrefixMilestoneIndexes   byte = 4
	StorePrefixMilestones         byte = 5
	StorePrefixChildren           byte = 6
	StorePrefixUnreferencedBlocks byte = 7
	StorePrefixProtocol           byte = 8
	StorePrefixShards             byte = 9  // Added for shard storage
	StorePrefixShardDistribution  byte = 10 // Added for shard distribution
	StorePrefixHealth             byte = 255
)