package b2b

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/iotaledger/hive.go/kvstore"
	"github.com/iotaledger/hive.go/logger"
	"github.com/iotaledger/hive.go/serializer/v2/marshalutil"
	"github.com/dueldanov/lockbox/v2/internal/tiering"
	iotago "github.com/iotaledger/iota.go/v3"
)

const (
	StorePrefixRevenue       byte = 5
	StorePrefixPaymentStatus byte = 6
	StorePrefixPartnerStats  byte = 7
)

type RevenueManager struct {
	*logger.WrappedLogger
	store          kvstore.KVStore
	tierManager    *tiering.Manager
	paymentLock    sync.RWMutex
	revenueShares  map[string]float64 // partnerID -> share percentage
	paymentEnabled bool
}

type RevenueRecord struct {
	PartnerID     string    `json:"partner_id"`
	Amount        uint64    `json:"amount"`
	Currency      string    `json:"currency"`
	Timestamp     time.Time `json:"timestamp"`
	TransactionID string    `json:"transaction_id"`
	Status        string    `json:"status"`
}

type PaymentStatus struct {
	PartnerID        string    `json:"partner_id"`
	LastPaymentDate  time.Time `json:"last_payment_date"`
	LastPaymentID    string    `json:"last_payment_id"`
	TotalPaid        uint64    `json:"total_paid"`
	PendingAmount    uint64    `json:"pending_amount"`
	NextPaymentDate  time.Time `json:"next_payment_date"`
}

type PartnerStatistics struct {
	PartnerID            string    `json:"partner_id"`
	TotalTransactions    uint64    `json:"total_transactions"`
	TotalRevenue         uint64    `json:"total_revenue"`
	AverageTransactionSize uint64  `json:"average_transaction_size"`
	LastActivityDate     time.Time `json:"last_activity_date"`
	ActiveUsers          uint64    `json:"active_users"`
}

func NewRevenueManager(log *logger.Logger, store kvstore.KVStore, tierManager *tiering.Manager) (*RevenueManager, error) {
	revenueStore, err := store.WithRealm([]byte{0xFE})
	if err != nil {
		return nil, err
	}

	return &RevenueManager{
		WrappedLogger:  logger.NewWrappedLogger(log),
		store:          revenueStore,
		tierManager:    tierManager,
		revenueShares:  make(map[string]float64),
		paymentEnabled: true,
	}, nil
}

// RecordRevenue records a revenue event for a partner
func (rm *RevenueManager) RecordRevenue(ctx context.Context, partnerID string, amount uint64, transactionID string) error {
	rm.paymentLock.Lock()
	defer rm.paymentLock.Unlock()

	record := &RevenueRecord{
		PartnerID:     partnerID,
		Amount:        amount,
		Currency:      "IOTA",
		Timestamp:     time.Now(),
		TransactionID: transactionID,
		Status:        "pending",
	}

	key := rm.revenueKey(partnerID, transactionID)
	value, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal revenue record: %w", err)
	}

	if err := rm.store.Set(key, value); err != nil {
		return fmt.Errorf("failed to store revenue record: %w", err)
	}

	// Update partner statistics
	if err := rm.updatePartnerStats(partnerID, amount); err != nil {
		rm.LogWarnf("Failed to update partner stats: %v", err)
	}

	// Update pending amount
	if err := rm.updatePendingAmount(partnerID, amount); err != nil {
		return fmt.Errorf("failed to update pending amount: %w", err)
	}

	rm.LogDebugf("Recorded revenue for partner %s: %d", partnerID, amount)
	return nil
}

// ProcessDailyPayments processes payments for all partners
func (rm *RevenueManager) ProcessDailyPayments(ctx context.Context) error {
	rm.LogInfo("Starting daily payment processing")

	partners, err := rm.getPartnersWithPendingPayments()
	if err != nil {
		return fmt.Errorf("failed to get partners with pending payments: %w", err)
	}

	processed := 0
	failed := 0

	for _, partnerID := range partners {
		select {
		case <-ctx.Done():
			rm.LogWarnf("Payment processing interrupted: %d processed, %d failed", processed, failed)
			return ctx.Err()
		default:
		}

		if err := rm.processPartnerPayment(ctx, partnerID); err != nil {
			rm.LogErrorf("Failed to process payment for partner %s: %v", partnerID, err)
			failed++
			continue
		}

		processed++
	}

	rm.LogInfof("Daily payment processing completed: %d processed, %d failed", processed, failed)
	return nil
}

// processPartnerPayment processes payment for a single partner
func (rm *RevenueManager) processPartnerPayment(ctx context.Context, partnerID string) error {
	rm.paymentLock.Lock()
	defer rm.paymentLock.Unlock()

	// Get payment status
	status, err := rm.getPaymentStatus(partnerID)
	if err != nil {
		return err
	}

	// Check if payment is due
	if time.Now().Before(status.NextPaymentDate) {
		return nil
	}

	// Check minimum threshold
	minThreshold := rm.getMinimumPaymentThreshold(partnerID)
	if status.PendingAmount < minThreshold {
		rm.LogDebugf("Partner %s pending amount %d below threshold %d", partnerID, status.PendingAmount, minThreshold)
		return nil
	}

	// Calculate revenue share
	sharePercentage, ok := rm.revenueShares[partnerID]
	if !ok {
		sharePercentage = rm.getDefaultRevenueShare(partnerID)
	}

	paymentAmount := uint64(float64(status.PendingAmount) * sharePercentage / 100)

	// Execute payment
	paymentID, err := rm.executePayment(ctx, partnerID, paymentAmount)
	if err != nil {
		return fmt.Errorf("failed to execute payment: %w", err)
	}

	// Update payment status
	status.LastPaymentDate = time.Now()
	status.LastPaymentID = paymentID
	status.TotalPaid += paymentAmount
	status.PendingAmount = 0
	status.NextPaymentDate = time.Now().Add(24 * time.Hour)

	if err := rm.updatePaymentStatus(partnerID, status); err != nil {
		return fmt.Errorf("failed to update payment status: %w", err)
	}

	// Mark revenue records as paid
	if err := rm.markRecordsAsPaid(partnerID, paymentID); err != nil {
		rm.LogWarnf("Failed to mark records as paid: %v", err)
	}

	rm.LogInfof("Processed payment for partner %s: %d (%s)", partnerID, paymentAmount, paymentID)
	return nil
}

// executePayment executes the actual payment transaction
func (rm *RevenueManager) executePayment(ctx context.Context, partnerID string, amount uint64) (string, error) {
	// TODO: Integrate with IOTA payment system
	// For now, return a mock payment ID
	paymentID := fmt.Sprintf("PAY_%s_%d", partnerID, time.Now().Unix())
	
	// Simulate payment processing
	time.Sleep(100 * time.Millisecond)
	
	return paymentID, nil
}

// SetRevenueShare sets the revenue share percentage for a partner
func (rm *RevenueManager) SetRevenueShare(partnerID string, sharePercentage float64) error {
	if sharePercentage < 0 || sharePercentage > 100 {
		return fmt.Errorf("invalid share percentage: %f", sharePercentage)
	}

	rm.paymentLock.Lock()
	defer rm.paymentLock.Unlock()

	rm.revenueShares[partnerID] = sharePercentage
	rm.LogInfof("Set revenue share for partner %s: %.2f%%", partnerID, sharePercentage)
	return nil
}

// GetPartnerStatistics retrieves statistics for a partner
func (rm *RevenueManager) GetPartnerStatistics(partnerID string) (*PartnerStatistics, error) {
	key := rm.partnerStatsKey(partnerID)
	value, err := rm.store.Get(key)
	if err != nil {
		if kvstore.IsKeyNotFoundError(err) {
			return &PartnerStatistics{
				PartnerID: partnerID,
			}, nil
		}
		return nil, err
	}

	var stats PartnerStatistics
	if err := json.Unmarshal(value, &stats); err != nil {
		return nil, err
	}

	return &stats, nil
}

// Helper methods

func (rm *RevenueManager) revenueKey(partnerID, transactionID string) []byte {
	ms := marshalutil.New(1 + len(partnerID) + 1 + len(transactionID))
	ms.WriteByte(StorePrefixRevenue)
	ms.WriteBytes([]byte(partnerID))
	ms.WriteByte(0) // separator
	ms.WriteBytes([]byte(transactionID))
	return ms.Bytes()
}

func (rm *RevenueManager) paymentStatusKey(partnerID string) []byte {
	ms := marshalutil.New(1 + len(partnerID))
	ms.WriteByte(StorePrefixPaymentStatus)
	ms.WriteBytes([]byte(partnerID))
	return ms.Bytes()
}

func (rm *RevenueManager) partnerStatsKey(partnerID string) []byte {
	ms := marshalutil.New(1 + len(partnerID))
	ms.WriteByte(StorePrefixPartnerStats)
	ms.WriteBytes([]byte(partnerID))
	return ms.Bytes()
}

func (rm *RevenueManager) getPaymentStatus(partnerID string) (*PaymentStatus, error) {
	key := rm.paymentStatusKey(partnerID)
	value, err := rm.store.Get(key)
	if err != nil {
		if kvstore.IsKeyNotFoundError(err) {
			return &PaymentStatus{
				PartnerID:       partnerID,
				NextPaymentDate: time.Now().Add(24 * time.Hour),
			}, nil
		}
		return nil, err
	}

	var status PaymentStatus
	if err := json.Unmarshal(value, &status); err != nil {
		return nil, err
	}

	return &status, nil
}

func (rm *RevenueManager) updatePaymentStatus(partnerID string, status *PaymentStatus) error {
	key := rm.paymentStatusKey(partnerID)
	value, err := json.Marshal(status)
	if err != nil {
		return err
	}

	return rm.store.Set(key, value)
}

func (rm *RevenueManager) updatePendingAmount(partnerID string, amount uint64) error {
	status, err := rm.getPaymentStatus(partnerID)
	if err != nil {
		return err
	}

	status.PendingAmount += amount
	return rm.updatePaymentStatus(partnerID, status)
}

func (rm *RevenueManager) updatePartnerStats(partnerID string, amount uint64) error {
	stats, err := rm.GetPartnerStatistics(partnerID)
	if err != nil {
		return err
	}

	stats.TotalTransactions++
	stats.TotalRevenue += amount
	stats.AverageTransactionSize = stats.TotalRevenue / stats.TotalTransactions
	stats.LastActivityDate = time.Now()

	key := rm.partnerStatsKey(partnerID)
	value, err := json.Marshal(stats)
	if err != nil {
		return err
	}

	return rm.store.Set(key, value)
}

func (rm *RevenueManager) getPartnersWithPendingPayments() ([]string, error) {
	var partners []string
	prefix := []byte{StorePrefixPaymentStatus}

	if err := rm.store.Iterate(prefix, func(key kvstore.Key, value kvstore.Value) bool {
		var status PaymentStatus
		if err := json.Unmarshal(value, &status); err != nil {
			return true
		}

		if status.PendingAmount > 0 {
			partners = append(partners, status.PartnerID)
		}
		return true
	}); err != nil {
		return nil, err
	}

	return partners, nil
}

func (rm *RevenueManager) markRecordsAsPaid(partnerID, paymentID string) error {
	prefix := append([]byte{StorePrefixRevenue}, []byte(partnerID)...)
	
	return rm.store.Iterate(prefix, func(key kvstore.Key, value kvstore.Value) bool {
		var record RevenueRecord
		if err := json.Unmarshal(value, &record); err != nil {
			return true
		}

		if record.Status == "pending" {
			record.Status = "paid"
			updatedValue, _ := json.Marshal(record)
			rm.store.Set(key, updatedValue)
		}
		return true
	})
}

func (rm *RevenueManager) getMinimumPaymentThreshold(partnerID string) uint64 {
	// TODO: Get from partner configuration
	return 1000000 // 1 MIOTA
}

func (rm *RevenueManager) getDefaultRevenueShare(partnerID string) float64 {
	// TODO: Get from partner configuration based on tier
	return 70.0 // 70% default share
}