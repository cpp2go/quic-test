package utils

import (
	"math"
	"sync/atomic"
	"time"
)

// NewReno implements the NewReno congestion control algorithm (RFC 9002 / RFC 6582).
type NewReno struct {
	// Congestion window (in bytes)
	cwnd atomic.Int64

	// Slow start threshold (in bytes)
	ssthresh atomic.Int64

	// Minimum congestion window
	minCwnd int64

	// Maximum datagram size
	maxDatagramSize int64

	// Bytes in flight tracking
	bytesInFlight atomic.Int64

	// Number of bytes acknowledged in recovery
	recoveryBytesAcked atomic.Int64

	// Recovery state
	inRecovery    atomic.Bool
	recoveryPoint atomic.Int64 // packet number when recovery started
}

// NewNewReno creates a NewReno congestion controller.
// Start with cwnd = 10 * maxDatagramSize (RFC 9002 initial window).
func NewNewReno() *NewReno {
	r := &NewReno{
		minCwnd:         2 * 1200,
		maxDatagramSize: 1200,
	}
	r.cwnd.Store(10 * 1200) // initial cwnd = 10 * 1200
	r.ssthresh.Store(math.MaxInt32)
	return r
}

// OnPacketSent increases bytes in flight.
func (r *NewReno) OnPacketSent(bytes int64) {
	r.bytesInFlight.Add(bytes)
}

// OnPacketAcked is called when a packet is acknowledged.
// Returns true if the congestion window was updated.
func (r *NewReno) OnPacketAcked(ackedBytes int64, packetNumber int64, now time.Time) bool {
	if r.cwnd.Load() <= 0 {
		r.cwnd.Store(int64(r.minCwnd))
	}

	// Don't increase cwnd during recovery
	if r.inRecovery.Load() {
		if packetNumber <= r.recoveryPoint.Load() {
			r.bytesInFlight.Add(-ackedBytes)
			return false
		}
		// Exit recovery
		r.inRecovery.Store(false)
	}

	r.bytesInFlight.Add(-ackedBytes)

	cwnd := r.cwnd.Load()
	ssthresh := r.ssthresh.Load()

	if cwnd < ssthresh {
		// Slow start: cwnd += ackedBytes per ACK
		newCwnd := cwnd + ackedBytes
		if newCwnd > ssthresh && ssthresh > 0 {
			newCwnd = ssthresh
		}
		r.cwnd.Store(newCwnd)
	} else {
		// Congestion avoidance: cwnd += ackedBytes * maxDatagramSize / cwnd
		increase := float64(ackedBytes) * float64(r.maxDatagramSize) / float64(cwnd)
		newCwnd := cwnd + int64(increase)
		if newCwnd <= cwnd {
			newCwnd = cwnd + 1
		}
		r.cwnd.Store(newCwnd)
	}

	return true
}

// OnPacketLost is called when a packet is detected as lost (3 duplicate ACKs or timeout).
func (r *NewReno) OnPacketLost(largestSentPNSinceLastLoss int64) {
	if r.inRecovery.Load() {
		return
	}

	// Enter recovery
	r.inRecovery.Store(true)
	r.recoveryPoint.Store(largestSentPNSinceLastLoss)

	// Update ssthresh = cwnd / 2
	cwnd := r.cwnd.Load()
	newSsthresh := cwnd / 2
	if newSsthresh < r.minCwnd {
		newSsthresh = r.minCwnd
	}
	r.ssthresh.Store(newSsthresh)

	// Reset cwnd to minCwnd (or ssthresh for NewReno)
	r.cwnd.Store(newSsthresh)
}

// OnPacketDiscarded decrements bytes in flight (packet lost, not ACKed).
func (r *NewReno) OnPacketDiscarded(bytes int64) {
	r.bytesInFlight.Add(-bytes)
}

// OnPacketNeedsRetransmit handles the case where we need to retransmit (timeout).
func (r *NewReno) OnPacketNeedsRetransmit() {
	// For timeout, reset cwnd to minimum
	r.inRecovery.Store(false)
	r.ssthresh.Store(r.cwnd.Load() / 2)
	if r.ssthresh.Load() < r.minCwnd {
		r.ssthresh.Store(r.minCwnd)
	}
	r.cwnd.Store(r.minCwnd)
}

// CanSend checks if we can send a packet of the given size.
func (r *NewReno) CanSend(bytes int64) bool {
	return r.bytesInFlight.Load()+bytes <= r.cwnd.Load()
}

// Cwnd returns the current congestion window.
func (r *NewReno) Cwnd() int64 {
	return r.cwnd.Load()
}

// Ssthresh returns the current slow start threshold.
func (r *NewReno) Ssthresh() int64 {
	return r.ssthresh.Load()
}

// BytesInFlight returns the current bytes in flight.
func (r *NewReno) BytesInFlight() int64 {
	return r.bytesInFlight.Load()
}

// InRecovery returns whether we're in recovery.
func (r *NewReno) InRecovery() bool {
	return r.inRecovery.Load()
}

// Name returns the algorithm name.
func (r *NewReno) Name() string { return "NewReno" }

// SetMaxDatagramSize sets the max datagram size.
func (r *NewReno) SetMaxDatagramSize(size int64) {
	r.maxDatagramSize = size
}
