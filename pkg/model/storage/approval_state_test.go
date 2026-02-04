package storage

import (
	"testing"
	"time"

	iotago "github.com/iotaledger/iota.go/v3"
	"github.com/stretchr/testify/require"
)

func TestApprovalStateApplyApproval(t *testing.T) {
	state := NewApprovalState(iotago.BlockID{1})

	t1 := time.Unix(100, 0)
	newlyConfirmed, firstAt, confirmedAt, count := state.ApplyApproval(t1, 3)
	require.False(t, newlyConfirmed)
	require.Equal(t, uint32(1), count)
	require.Equal(t, t1.UnixNano(), firstAt)
	require.Equal(t, int64(0), confirmedAt)

	t2 := time.Unix(200, 0)
	newlyConfirmed, _, confirmedAt, count = state.ApplyApproval(t2, 3)
	require.False(t, newlyConfirmed)
	require.Equal(t, uint32(2), count)
	require.Equal(t, int64(0), confirmedAt)

	t3 := time.Unix(300, 0)
	newlyConfirmed, firstAt, confirmedAt, count = state.ApplyApproval(t3, 3)
	require.True(t, newlyConfirmed)
	require.Equal(t, uint32(3), count)
	require.Equal(t, t1.UnixNano(), firstAt)
	require.Equal(t, t3.UnixNano(), confirmedAt)

	t4 := time.Unix(400, 0)
	newlyConfirmed, _, confirmedAt, count = state.ApplyApproval(t4, 3)
	require.False(t, newlyConfirmed)
	require.Equal(t, uint32(4), count)
	require.Equal(t, t3.UnixNano(), confirmedAt)
}
