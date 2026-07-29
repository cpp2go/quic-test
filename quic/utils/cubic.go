package utils

import (
	"math"
	"sync/atomic"
	"time"
)

const (
	// CUBIC scaling factor (RFC 8312 §4)
	cubicC = 0.4
	// Multiplicative decrease factor: cwnd = cwnd * (1 - cubicBeta)
	cubicBeta = 0.3
)

// Cubic implements the CUBIC congestion control algorithm (RFC 8312).
type Cubic struct {
	// Congestion window
	cwnd atomic.Int64

	// Slow start threshold
	ssthresh atomic.Int64

	// Window just before last loss (W_max in the RFC)
	wMax int64

	// Time of last congestion event (loss)
	lastLossTime time.Time

	// Whether we're in slow start
	inSlowStart bool

	// Minimum congestion window
	minCwnd int64

	// Max datagram size
	maxDatagramSize int64

	// Points in flight
	bytesInFlight atomic.Int64

	// Recovery state
	inRecovery    atomic.Bool
	recoveryPoint int64

	// RTT estimation (set from connection's RTT stats)
	rtt time.Duration

	// ACK count for epoch tracking
	ackedBytesSinceLoss int64
}

// NewCubic creates a CUBIC congestion controller.
func NewCubic() *Cubic {
	c := &Cubic{
		minCwnd:         2 * 1200,
		maxDatagramSize: 1200,
		inSlowStart:     true,
		rtt:             100 * time.Millisecond,
	}
	c.cwnd.Store(10 * 1200) // initial window = 10 MSS
	c.ssthresh.Store(math.MaxInt32)
	c.wMax = 10 * 1200
	return c
}

// Name returns "CUBIC".
func (c *Cubic) Name() string { return "CUBIC" }

// SetRTT updates the RTT estimate used in TCP mode calculations.
func (c *Cubic) SetRTT(rtt time.Duration) {
	if rtt > 0 {
		c.rtt = rtt
	}
}

// OnPacketSent records a sent packet.
func (c *Cubic) OnPacketSent(bytes int64) {
	c.bytesInFlight.Add(bytes)
}

// OnPacketAcked processes an ACK and updates the congestion window.
func (c *Cubic) OnPacketAcked(ackedBytes int64, packetNumber int64, now time.Time) bool {
	c.bytesInFlight.Add(-ackedBytes)
	c.ackedBytesSinceLoss += ackedBytes

	if c.cwnd.Load() <= 0 {
		c.cwnd.Store(c.minCwnd)
	}

	cwnd := c.cwnd.Load()
	ssthresh := c.ssthresh.Load()

	if cwnd < ssthresh {
		// Slow start: exponential growth
		newCwnd := cwnd + ackedBytes
		if newCwnd > ssthresh && ssthresh > 0 {
			newCwnd = ssthresh
			c.inSlowStart = false
		}
		c.cwnd.Store(newCwnd)
	} else {
		c.inSlowStart = false
		// Congestion avoidance: use CUBIC update
		c.cubicUpdate(ackedBytes, now)
	}

	return true
}

// cubicUpdate applies the CUBIC window growth function (RFC 8312 §4).
func (c *Cubic) cubicUpdate(ackedBytes int64, now time.Time) {
	if c.lastLossTime.IsZero() {
		return
	}

	cwnd := float64(c.cwnd.Load())
	wMax := float64(c.wMax)
	rtt := c.rtt.Seconds()

	// Time elapsed since last loss (in seconds)
	t := now.Sub(c.lastLossTime).Seconds()
	if t <= 0 {
		t = 0.001 // minimum 1ms
	}

	// K = cube_root(W_max * beta / C)  (RFC 8312 §4)
	beta := cubicBeta
	K := math.Cbrt(wMax * beta / cubicC)

	// W_cubic(t) = C * (t - K)^3 + W_max
	wt := t - K
	wCubic := cubicC*wt*wt*wt + wMax

	// W_tcp(t) = W_max * (1 - beta) + 3 * beta / (2 - beta) * t / RTT
	wTcp := wMax*(1-beta) + 3.0*beta/(2.0-beta)*t/rtt

	// Use the larger of CUBIC and TCP windows
	var target float64
	if wCubic > wTcp {
		target = wCubic
	} else {
		target = wTcp
	}

	// Ensure minimum
	if target < float64(c.minCwnd) {
		target = float64(c.minCwnd)
	}

	// Convert to integer cwnd
	// For fairness, use a smoother update: cwnd += (target - cwnd) * ackedBytes / cwnd
	inc := (target - cwnd) * float64(ackedBytes) / cwnd
	if inc < 0 {
		inc = float64(ackedBytes) * float64(c.maxDatagramSize) / cwnd
	}

	newCwnd := cwnd + inc
	if newCwnd < cwnd {
		newCwnd = cwnd + 1
	}
	c.cwnd.Store(int64(newCwnd))
}

// OnPacketLost handles packet loss: multiplicative decrease.
func (c *Cubic) OnPacketLost(largestSentPNSinceLastLoss int64) {
	if c.inRecovery.Load() {
		return
	}

	c.inRecovery.Store(true)
	c.recoveryPoint = largestSentPNSinceLastLoss

	cwnd := c.cwnd.Load()

	// Record W_max before reduction
	c.wMax = cwnd

	// Multiplicative decrease: cwnd = cwnd * (1 - beta)
	newCwnd := int64(float64(cwnd) * (1.0 - cubicBeta))
	if newCwnd < c.minCwnd {
		newCwnd = c.minCwnd
	}

	// ssthresh = max(cwnd_reduced, 2*MSS)
	newSsthresh := newCwnd
	if newSsthresh < c.minCwnd {
		newSsthresh = c.minCwnd
	}
	c.ssthresh.Store(newSsthresh)

	c.cwnd.Store(newCwnd)

	// Record loss time for cubic function
	c.lastLossTime = time.Now()
	c.ackedBytesSinceLoss = 0
}

// OnPacketDiscarded decrements bytes in flight (packet lost, not ACKed).
func (c *Cubic) OnPacketDiscarded(bytes int64) {
	c.bytesInFlight.Add(-bytes)
}

// OnPacketNeedsRetransmit handles timeout-based retransmit.
func (c *Cubic) OnPacketNeedsRetransmit() {
	c.inRecovery.Store(false)

	// Record W_max before reduction
	cwnd := c.cwnd.Load()
	c.wMax = cwnd

	// ssthresh = cwnd / 2
	newSsthresh := cwnd / 2
	if newSsthresh < c.minCwnd {
		newSsthresh = c.minCwnd
	}
	c.ssthresh.Store(newSsthresh)

	// Reset to minimum on timeout
	c.cwnd.Store(c.minCwnd)
	c.lastLossTime = time.Now()
	c.ackedBytesSinceLoss = 0
}

// CanSend checks if a packet of the given size can be sent.
func (c *Cubic) CanSend(bytes int64) bool {
	inFlight := c.bytesInFlight.Load()
	cwnd := c.cwnd.Load()
	if c.inRecovery.Load() {
		return inFlight+bytes <= cwnd+c.maxDatagramSize
	}
	return inFlight+bytes <= cwnd
}

// Cwnd returns the congestion window.
func (c *Cubic) Cwnd() int64 { return c.cwnd.Load() }

// BytesInFlight returns the estimated bytes in flight.
func (c *Cubic) BytesInFlight() int64 { return c.bytesInFlight.Load() }

// InRecovery returns the recovery state.
func (c *Cubic) InRecovery() bool { return c.inRecovery.Load() }
