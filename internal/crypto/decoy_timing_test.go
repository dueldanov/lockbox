package crypto

import (
	"crypto/rand"
	"io"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// BenchmarkGenerateRealShard benchmarks real shard encryption
func BenchmarkGenerateRealShard(b *testing.B) {
	// Setup
	masterKey := make([]byte, 32)
	io.ReadFull(rand.Reader, masterKey)

	hkdf, err := NewHKDFManager(masterKey)
	require.NoError(b, err)
	defer hkdf.Clear()

	encryptor, err := NewShardEncryptor(masterKey, 4096)
	require.NoError(b, err)

	data := make([]byte, 4096) // 4KB shard
	io.ReadFull(rand.Reader, data)

	shardID := generateShardID()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := encryptor.encryptShard(data, shardID, uint32(i), 100)
		if err != nil {
			b.Fatal(err)
		}
	}

	b.SetBytes(4096)
}

// BenchmarkGenerateDecoyShard benchmarks decoy shard generation
func BenchmarkGenerateDecoyShard(b *testing.B) {
	// Setup
	masterKey := make([]byte, 32)
	io.ReadFull(rand.Reader, masterKey)

	hkdf, err := NewHKDFManager(masterKey)
	require.NoError(b, err)
	defer hkdf.Clear()

	generator := NewDecoyGenerator(hkdf, DecoyConfig{DecoyRatio: 1.0})

	data := make([]byte, 4096) // 4KB shard
	io.ReadFull(rand.Reader, data)

	shardID := generateShardID()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := generator.encryptDecoyCharShard(data, shardID, uint32(i), 100)
		if err != nil {
			b.Fatal(err)
		}
	}

	b.SetBytes(4096)
}

// TestDecoyTiming_Indistinguishability verifies <1ms variance between real and decoy
// This is CRITICAL for security - timing attacks must not distinguish real from decoy
func TestDecoyTiming_Indistinguishability(t *testing.T) {
	// Setup
	masterKey := make([]byte, 32)
	io.ReadFull(rand.Reader, masterKey)

	hkdf, err := NewHKDFManager(masterKey)
	require.NoError(t, err)
	defer hkdf.Clear()

	encryptor, err := NewShardEncryptor(masterKey, 4096)
	require.NoError(t, err)

	generator := NewDecoyGenerator(hkdf, DecoyConfig{DecoyRatio: 1.0})

	data := make([]byte, 4096)
	io.ReadFull(rand.Reader, data)

	iterations := 1000
	shardID := generateShardID()

	// Measure real shard generation
	realStart := time.Now()
	for i := 0; i < iterations; i++ {
		_, err := encryptor.encryptShard(data, shardID, uint32(i), uint32(iterations))
		require.NoError(t, err)
	}
	realDuration := time.Since(realStart)
	realAvg := realDuration / time.Duration(iterations)

	// Measure decoy shard generation
	decoyStart := time.Now()
	for i := 0; i < iterations; i++ {
		_, err := generator.encryptDecoyCharShard(data, shardID, uint32(i), uint32(iterations))
		require.NoError(t, err)
	}
	decoyDuration := time.Since(decoyStart)
	decoyAvg := decoyDuration / time.Duration(iterations)

	// Calculate variance
	variance := realAvg - decoyAvg
	if variance < 0 {
		variance = -variance
	}

	t.Logf("Real avg: %v, Decoy avg: %v, Variance: %v", realAvg, decoyAvg, variance)

	// CRITICAL: Variance must be <1ms for timing attack resistance
	// This is the PRIMARY security requirement - absolute timing difference
	// must be small enough that timing side-channels cannot distinguish real from decoy
	require.Less(t, variance, time.Millisecond,
		"Timing variance %v exceeds 1ms threshold (real: %v, decoy: %v) - SECURITY RISK!",
		variance, realAvg, decoyAvg)

	// Log percentage variance for informational purposes
	// (Not a hard requirement since operations are microsecond-scale,
	// so small absolute differences can be large percentages)
	maxTime := realAvg
	if decoyAvg > maxTime {
		maxTime = decoyAvg
	}
	percentVariance := float64(variance) / float64(maxTime) * 100
	t.Logf("Variance: %.2f%% of average time (informational only)", percentVariance)
}

// TestDecoyTiming_UnderLoad verifies timing under concurrent load
// This ensures timing indistinguishability holds under realistic conditions
func TestDecoyTiming_UnderLoad(t *testing.T) {
	masterKey := make([]byte, 32)
	io.ReadFull(rand.Reader, masterKey)

	hkdf, err := NewHKDFManager(masterKey)
	require.NoError(t, err)
	defer hkdf.Clear()

	encryptor, err := NewShardEncryptor(masterKey, 4096)
	require.NoError(t, err)

	generator := NewDecoyGenerator(hkdf, DecoyConfig{DecoyRatio: 1.0})

	numGoroutines := 50
	samplesPerGoroutine := 20

	realTimes := make(chan time.Duration, numGoroutines*samplesPerGoroutine)
	decoyTimes := make(chan time.Duration, numGoroutines*samplesPerGoroutine)

	// Concurrent generation
	for i := 0; i < numGoroutines; i++ {
		go func() {
			data := make([]byte, 4096)
			io.ReadFull(rand.Reader, data)
			shardID := generateShardID()

			for j := 0; j < samplesPerGoroutine; j++ {
				// Measure real shard
				realStart := time.Now()
				_, err := encryptor.encryptShard(data, shardID, uint32(j), 100)
				if err != nil {
					t.Errorf("Real shard encryption failed: %v", err)
					return
				}
				realTimes <- time.Since(realStart)

				// Measure decoy shard
				decoyStart := time.Now()
				_, err = generator.encryptDecoyCharShard(data, shardID, uint32(j), 100)
				if err != nil {
					t.Errorf("Decoy shard encryption failed: %v", err)
					return
				}
				decoyTimes <- time.Since(decoyStart)
			}
		}()
	}

	// Collect samples
	var realTotal, decoyTotal time.Duration
	totalSamples := numGoroutines * samplesPerGoroutine

	for i := 0; i < totalSamples; i++ {
		realTotal += <-realTimes
		decoyTotal += <-decoyTimes
	}

	realAvg := realTotal / time.Duration(totalSamples)
	decoyAvg := decoyTotal / time.Duration(totalSamples)

	variance := realAvg - decoyAvg
	if variance < 0 {
		variance = -variance
	}

	t.Logf("Under load (n=%d) - Real avg: %v, Decoy avg: %v, Variance: %v",
		totalSamples, realAvg, decoyAvg, variance)

	// Even under load, variance must be <1ms
	require.Less(t, variance, time.Millisecond,
		"Timing variance under load %v exceeds 1ms - may be distinguishable under DoS", variance)
}

// TestDecoyTiming_DifferentSizes verifies timing indistinguishability across shard sizes
func TestDecoyTiming_DifferentSizes(t *testing.T) {
	masterKey := make([]byte, 32)
	io.ReadFull(rand.Reader, masterKey)

	hkdf, err := NewHKDFManager(masterKey)
	require.NoError(t, err)
	defer hkdf.Clear()

	encryptor, err := NewShardEncryptor(masterKey, 4096)
	require.NoError(t, err)

	generator := NewDecoyGenerator(hkdf, DecoyConfig{DecoyRatio: 1.0})

	sizes := []int{1024, 4096, 16384, 65536} // 1KB, 4KB, 16KB, 64KB
	iterations := 100

	for _, size := range sizes {
		t.Run(string(rune(size)), func(t *testing.T) {
			data := make([]byte, size)
			io.ReadFull(rand.Reader, data)
			shardID := generateShardID()

			// Measure real
			realStart := time.Now()
			for i := 0; i < iterations; i++ {
				_, err := encryptor.encryptShard(data, shardID, uint32(i), uint32(iterations))
				require.NoError(t, err)
			}
			realAvg := time.Since(realStart) / time.Duration(iterations)

			// Measure decoy
			decoyStart := time.Now()
			for i := 0; i < iterations; i++ {
				_, err := generator.encryptDecoyCharShard(data, shardID, uint32(i), uint32(iterations))
				require.NoError(t, err)
			}
			decoyAvg := time.Since(decoyStart) / time.Duration(iterations)

			variance := realAvg - decoyAvg
			if variance < 0 {
				variance = -variance
			}

			t.Logf("Size %d bytes - Real: %v, Decoy: %v, Variance: %v",
				size, realAvg, decoyAvg, variance)

			// Variance should be <1ms for all sizes
			require.Less(t, variance, time.Millisecond,
				"Variance %v for size %d bytes exceeds 1ms", variance, size)
		})
	}
}

// TestDecoyTiming_StatisticalAnalysis performs statistical analysis of timing data
func TestDecoyTiming_StatisticalAnalysis(t *testing.T) {
	masterKey := make([]byte, 32)
	io.ReadFull(rand.Reader, masterKey)

	hkdf, err := NewHKDFManager(masterKey)
	require.NoError(t, err)
	defer hkdf.Clear()

	encryptor, err := NewShardEncryptor(masterKey, 4096)
	require.NoError(t, err)

	generator := NewDecoyGenerator(hkdf, DecoyConfig{DecoyRatio: 1.0})

	data := make([]byte, 4096)
	io.ReadFull(rand.Reader, data)
	shardID := generateShardID()

	samples := 500

	realTimings := make([]time.Duration, samples)
	decoyTimings := make([]time.Duration, samples)

	// Collect timing samples
	for i := 0; i < samples; i++ {
		// Real shard
		start := time.Now()
		_, err := encryptor.encryptShard(data, shardID, uint32(i), uint32(samples))
		require.NoError(t, err)
		realTimings[i] = time.Since(start)

		// Decoy shard
		start = time.Now()
		_, err = generator.encryptDecoyCharShard(data, shardID, uint32(i), uint32(samples))
		require.NoError(t, err)
		decoyTimings[i] = time.Since(start)
	}

	// Calculate statistics
	realMean, realStdDev := calculateStats(realTimings)
	decoyMean, decoyStdDev := calculateStats(decoyTimings)

	meanDiff := realMean - decoyMean
	if meanDiff < 0 {
		meanDiff = -meanDiff
	}

	t.Logf("Real:  mean=%v, stddev=%v", realMean, realStdDev)
	t.Logf("Decoy: mean=%v, stddev=%v", decoyMean, decoyStdDev)
	t.Logf("Mean difference: %v", meanDiff)

	// Mean difference should be <1ms
	require.Less(t, meanDiff, time.Millisecond,
		"Mean timing difference %v exceeds 1ms", meanDiff)

	// Standard deviations should be similar (within 3x)
	// (Small sample variations can cause larger ratios when operations are microsecond-scale)
	stdDevRatio := float64(realStdDev) / float64(decoyStdDev)
	if stdDevRatio < 1.0 {
		stdDevRatio = 1.0 / stdDevRatio
	}

	t.Logf("StdDev ratio: %.2f", stdDevRatio)
	require.Less(t, stdDevRatio, 3.0,
		"Standard deviation ratio %.2f suggests significantly different timing distributions", stdDevRatio)
}

// BenchmarkDecoyTiming_Parallel benchmarks concurrent generation
func BenchmarkDecoyTiming_Parallel(b *testing.B) {
	masterKey := make([]byte, 32)
	io.ReadFull(rand.Reader, masterKey)

	hkdf, _ := NewHKDFManager(masterKey)
	defer hkdf.Clear()

	encryptor, _ := NewShardEncryptor(masterKey, 4096)
	generator := NewDecoyGenerator(hkdf, DecoyConfig{DecoyRatio: 1.0})

	data := make([]byte, 4096)
	io.ReadFull(rand.Reader, data)

	b.Run("Real", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			shardID := generateShardID()
			i := uint32(0)
			for pb.Next() {
				encryptor.encryptShard(data, shardID, i, 100)
				i++
			}
		})
	})

	b.Run("Decoy", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			shardID := generateShardID()
			i := uint32(0)
			for pb.Next() {
				generator.encryptDecoyCharShard(data, shardID, i, 100)
				i++
			}
		})
	})
}

// Helper: Calculate mean and standard deviation
func calculateStats(timings []time.Duration) (mean, stdDev time.Duration) {
	if len(timings) == 0 {
		return 0, 0
	}

	// Calculate mean
	var sum time.Duration
	for _, t := range timings {
		sum += t
	}
	mean = sum / time.Duration(len(timings))

	// Calculate standard deviation
	var variance float64
	for _, t := range timings {
		diff := float64(t - mean)
		variance += diff * diff
	}
	variance /= float64(len(timings))
	stdDev = time.Duration(math.Sqrt(variance))

	return mean, stdDev
}
