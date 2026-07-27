package utils

import "time"

// Controller is the interface for congestion control algorithms.
type Controller interface {
	// OnPacketSent records a packet being sent.
	OnPacketSent(bytes int64)

	// OnPacketAcked records a packet being acknowledged.
	// packetNumber is the packet number (for recovery state tracking).
	// now is the current time (for BBR's delivery rate estimation).
	OnPacketAcked(ackedBytes int64, packetNumber int64, now time.Time) bool

	// OnPacketLost signals packet loss detected.
	OnPacketLost(largestSentPNSinceLastLoss int64)

	// OnPacketNeedsRetransmit signals a timeout-based retransmit.
	OnPacketNeedsRetransmit()

	// CanSend checks if a packet of the given size can be sent.
	CanSend(bytes int64) bool

	// Cwnd returns the current congestion window (bytes).
	Cwnd() int64

	// BytesInFlight returns the estimated bytes in flight.
	BytesInFlight() int64

	// InRecovery returns true if currently in recovery/loss-recovery phase.
	InRecovery() bool

	// Name returns the algorithm name for logging.
	Name() string
}
