//nolint:forcetypeassert,varnamelen,revive,exhaustruct // we don't care about these linters in test cases
package value_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dueldanov/lockbox/v2/integration-tests/tester/framework"
	"github.com/dueldanov/lockbox/v2/pkg/dag"
	"github.com/dueldanov/lockbox/v2/pkg/tpkg"
	iotago "github.com/iotaledger/iota.go/v3"
	"github.com/iotaledger/iota.go/v3/builder"
)

// TestValue boots up a statically peered network and then checks that spending
// the genesis output to create multiple new output works.
func TestValue(t *testing.T) {
	n, err := f.CreateStaticNetwork("test_value", nil, framework.DefaultStaticPeeringLayout())
	require.NoError(t, err)
	defer framework.ShutdownNetwork(t, n)

	syncCtx, syncCtxCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer syncCtxCancel()

	assert.NoError(t, n.AwaitAllSync(syncCtx))

	infoRes, err := n.Coordinator().DebugNodeAPIClient.Info(context.Background())
	require.NoError(t, err)
	protoParams := &infoRes.Protocol
	parents := fetchParents(t, n.Coordinator().DebugNodeAPIClient, n.Nodes)

	// create two targets
	target1 := ed25519.NewKeyFromSeed(tpkg.RandSeed())
	target1Addr := iotago.Ed25519AddressFromPubKey(target1.Public().(ed25519.PublicKey))

	target2 := ed25519.NewKeyFromSeed(tpkg.RandSeed())
	target2Addr := iotago.Ed25519AddressFromPubKey(target2.Public().(ed25519.PublicKey))

	var target1Deposit, target2Deposit uint64 = 10_000_000, protoParams.TokenSupply - 10_000_000

	genesisAddrKey := iotago.AddressKeys{Address: &framework.GenesisAddress, Keys: framework.GenesisSeed}
	genesisInputID := &iotago.UTXOInput{TransactionID: [32]byte{}, TransactionOutputIndex: 0}

	// build and sign transaction spending the total supply and create block
	block, err := builder.NewTransactionBuilder(protoParams.NetworkID()).
		AddInput(&builder.TxInput{
			UnlockTarget: &framework.GenesisAddress,
			InputID:      genesisInputID.ID(),
			Input: &iotago.BasicOutput{
				Amount: protoParams.TokenSupply,
				Conditions: iotago.UnlockConditions{
					&iotago.AddressUnlockCondition{
						Address: &framework.GenesisAddress,
					},
				},
			},
		}).
		AddTaggedDataPayload(dag.ParentsSignatureTaggedData(parents)).
		AddOutput(&iotago.BasicOutput{
			Amount: target1Deposit,
			Conditions: iotago.UnlockConditions{
				&iotago.AddressUnlockCondition{
					Address: &target1Addr,
				},
			},
		}).
		AddOutput(&iotago.BasicOutput{
			Amount: target2Deposit,
			Conditions: iotago.UnlockConditions{
				&iotago.AddressUnlockCondition{
					Address: &target2Addr,
				},
			},
		}).
		BuildAndSwapToBlockBuilder(protoParams, iotago.NewInMemoryAddressSigner(genesisAddrKey), nil).
		ProtocolVersion(protoParams.Version).
		Parents(parents).
		Build()
	require.NoError(t, err)

	// broadcast to a node
	log.Println("submitting transaction ...")
	submittedBlockID, err := n.Nodes[2].DebugNodeAPIClient.SubmitBlock(context.Background(), block, protoParams)
	require.NoError(t, err)

	log.Println("checking that the transaction gets confirmed ...")
	require.Eventually(t, func() bool {
		blockMeta, err := n.Coordinator().DebugNodeAPIClient.BlockMetadataByBlockID(context.Background(), submittedBlockID)
		if err != nil {
			return false
		}

		return blockMeta.LedgerInclusionState == "included"
	}, 2*time.Minute, 200*time.Millisecond)

	// check that indeed the balances are available
	balance, err := n.Coordinator().DebugNodeAPIClient.BalanceByAddress(context.Background(), &framework.GenesisAddress)
	require.NoError(t, err)
	require.Zero(t, balance)

	balance, err = n.Coordinator().DebugNodeAPIClient.BalanceByAddress(context.Background(), &target1Addr)
	require.NoError(t, err)
	require.EqualValues(t, target1Deposit, balance)

	balance, err = n.Coordinator().DebugNodeAPIClient.BalanceByAddress(context.Background(), &target2Addr)
	require.NoError(t, err)
	require.EqualValues(t, target2Deposit, balance)

	// the genesis output should be spent
	outputMetadata, err := n.Coordinator().DebugNodeAPIClient.OutputMetadataByID(context.Background(), genesisInputID.ID())
	require.NoError(t, err)
	require.True(t, outputMetadata.Spent)
}

func fetchParents(t *testing.T, coordinator *framework.DebugNodeAPIClient, nodes []*framework.Node) iotago.BlockIDs {
	t.Helper()
	require.NotNil(t, coordinator)
	require.NotEmpty(t, nodes)

	parents, err := fetchParentsFromMilestones(coordinator, 20*time.Second, 250*time.Millisecond)
	if err == nil {
		return normalizeParents(t, parents)
	}

	t.Logf("milestone parent selection unavailable, falling back to tips: %v", err)

	parents, err = fetchParentsFromTips(nodes, coordinator, 12, 500*time.Millisecond)
	require.NoError(t, err)

	return normalizeParents(t, parents)
}

func collectTipsParents(nodes []*framework.Node) iotago.BlockIDs {
	seen := make(map[iotago.BlockID]struct{})

	for _, node := range nodes {
		tips, err := node.DebugNodeAPIClient.Tips(context.Background())
		if err != nil {
			continue
		}

		nodeTips, err := tips.Tips()
		if err != nil {
			continue
		}

		for _, tip := range nodeTips {
			seen[tip] = struct{}{}
		}
	}

	parents := make(iotago.BlockIDs, 0, len(seen))
	for tip := range seen {
		parents = append(parents, tip)
	}

	return parents.RemoveDupsAndSort()
}

func fetchParentsFromMilestones(
	api *framework.DebugNodeAPIClient,
	timeout time.Duration,
	pollInterval time.Duration,
) (iotago.BlockIDs, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error

	for time.Now().Before(deadline) {
		ctxInfo, cancelInfo := context.WithTimeout(context.Background(), 3*time.Second)
		info, err := api.Info(ctxInfo)
		cancelInfo()
		if err != nil {
			lastErr = fmt.Errorf("info request failed: %w", err)
			time.Sleep(pollInterval)
			continue
		}

		confirmedIndex := info.Status.ConfirmedMilestone.Index
		if confirmedIndex == 0 {
			lastErr = errors.New("confirmed milestone index is 0")
			time.Sleep(pollInterval)
			continue
		}

		parents, err := collectConfirmedMilestoneParents(api, confirmedIndex, 12)
		if err != nil {
			lastErr = err
			time.Sleep(pollInterval)
			continue
		}

		return parents, nil
	}

	if lastErr == nil {
		lastErr = errors.New("timed out waiting for confirmed milestone parents")
	}

	return nil, lastErr
}

func fetchParentsFromTips(
	nodes []*framework.Node,
	coordinator *framework.DebugNodeAPIClient,
	maxWarmupAttempts int,
	settleDelay time.Duration,
) (iotago.BlockIDs, error) {
	if maxWarmupAttempts <= 0 {
		maxWarmupAttempts = 1
	}

	var lastErr error

	for warmupAttempt := 1; warmupAttempt <= maxWarmupAttempts; warmupAttempt++ {
		parents := collectTipsParents(nodes)
		if len(parents) >= 3 {
			return parents, nil
		}

		spammed, err := nodes[len(nodes)-1].Spam(1500*time.Millisecond, 3)
		if err != nil {
			lastErr = fmt.Errorf("warmup attempt %d failed after %d blocks: %w", warmupAttempt, spammed, err)
		} else {
			lastErr = fmt.Errorf("only %d tips after warmup attempt %d (spammed=%d)", len(parents), warmupAttempt, spammed)
		}

		time.Sleep(settleDelay)
	}

	parents := collectTipsParents(nodes)
	if len(parents) >= 3 {
		return parents, nil
	}

	diag := collectParentDiagnostics(nodes, coordinator)
	if lastErr == nil {
		lastErr = errors.New("unable to reach 3 tips after warmup attempts")
	}

	return nil, fmt.Errorf("%w; %s", lastErr, diag)
}

func collectConfirmedMilestoneParents(
	api *framework.DebugNodeAPIClient,
	confirmedIndex iotago.MilestoneIndex,
	maxMilestones int,
) (iotago.BlockIDs, error) {
	if maxMilestones <= 0 {
		maxMilestones = 1
	}

	seen := make(map[iotago.BlockID]struct{})
	checked := 0

	for index := confirmedIndex; index > 0 && checked < maxMilestones; index-- {
		ctxMilestone, cancelMilestone := context.WithTimeout(context.Background(), 3*time.Second)
		milestone, err := api.MilestoneByIndex(ctxMilestone, index)
		cancelMilestone()
		if err != nil {
			return nil, fmt.Errorf("fetch milestone %d failed: %w", index, err)
		}

		checked++
		for _, parent := range milestone.Parents {
			seen[parent] = struct{}{}
		}

		if len(seen) >= 3 {
			break
		}
	}

	parents := make(iotago.BlockIDs, 0, len(seen))
	for parent := range seen {
		parents = append(parents, parent)
	}

	parents = parents.RemoveDupsAndSort()
	if len(parents) < 3 {
		return nil, fmt.Errorf(
			"confirmed milestone %d yielded only %d unique parents across %d milestones",
			confirmedIndex,
			len(parents),
			checked,
		)
	}

	return parents, nil
}

func normalizeParents(t *testing.T, parents iotago.BlockIDs) iotago.BlockIDs {
	t.Helper()

	parents = parents.RemoveDupsAndSort()
	if len(parents) > 3 {
		parents = parents[:3]
	}
	require.Len(t, parents, 3)

	return parents
}

func collectParentDiagnostics(nodes []*framework.Node, coordinator *framework.DebugNodeAPIClient) string {
	var builder strings.Builder
	builder.WriteString("parent acquisition diagnostics")

	for i, node := range nodes {
		builder.WriteString(fmt.Sprintf("; node[%d]=%s", i, node.Name))

		ctxInfo, cancelInfo := context.WithTimeout(context.Background(), 2*time.Second)
		info, infoErr := node.DebugNodeAPIClient.Info(ctxInfo)
		cancelInfo()
		if infoErr != nil {
			builder.WriteString(fmt.Sprintf(" info_err=%q", infoErr.Error()))
		} else {
			builder.WriteString(fmt.Sprintf(
				" healthy=%t latest_ms=%d confirmed_ms=%d",
				info.Status.IsHealthy,
				info.Status.LatestMilestone.Index,
				info.Status.ConfirmedMilestone.Index,
			))
		}

		ctxTips, cancelTips := context.WithTimeout(context.Background(), 2*time.Second)
		tipsRes, tipsErr := node.DebugNodeAPIClient.Tips(ctxTips)
		cancelTips()
		if tipsErr != nil {
			builder.WriteString(fmt.Sprintf(" tips_err=%q", tipsErr.Error()))
			continue
		}

		tips, tipsParseErr := tipsRes.Tips()
		if tipsParseErr != nil {
			builder.WriteString(fmt.Sprintf(" tips_parse_err=%q", tipsParseErr.Error()))
			continue
		}
		builder.WriteString(fmt.Sprintf(" tips_count=%d", len(tips.RemoveDupsAndSort())))
	}

	ctxCooInfo, cancelCooInfo := context.WithTimeout(context.Background(), 2*time.Second)
	cooInfo, cooInfoErr := coordinator.Info(ctxCooInfo)
	cancelCooInfo()
	if cooInfoErr != nil {
		builder.WriteString(fmt.Sprintf("; coordinator_info_err=%q", cooInfoErr.Error()))
	} else {
		builder.WriteString(fmt.Sprintf(
			"; coordinator_latest_ms=%d coordinator_confirmed_ms=%d",
			cooInfo.Status.LatestMilestone.Index,
			cooInfo.Status.ConfirmedMilestone.Index,
		))
	}

	return builder.String()
}
