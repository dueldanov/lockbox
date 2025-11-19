package gossip

import (
	hiveproto "github.com/dueldanov/lockbox/v2/pkg/protocol/protocol/message"
	"github.com/dueldanov/lockbox/v2/pkg/protocol/protocol/tlv"
)

var (
	// contains the definition for gossip messages.
	gossipMessageRegistry *hiveproto.Registry
)

func init() {
	definitions := []*hiveproto.Definition{
		tlv.HeaderMessageDefinition,
		milestoneRequestMessageDefinition,
		blockMessageDefinition,
		blockRequestMessageDefinition,
		heartbeatMessageDefinition,
	}
	gossipMessageRegistry = hiveproto.NewRegistry(definitions)
}
