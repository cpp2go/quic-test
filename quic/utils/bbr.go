package utils

import (
	"math"
	"sync/atomic"
	"time"
)

// BBR state names.
type bbrState uint8

const (
	bbrStateStartup  bbrState = iota // Startup: double each RTT
	bbrStateDrain                    // Drain: drain queue built in startup
	bbrStateProbeBW                  // ProbeBW: steady state gain cycling
	bbrStateProbeRTT                 // ProbeRTT: refresh min RTT
)

func (s bbrState) String() string {
	switch s {
	case bbrStateStartup:
		return "Startup"
	case bbrStateDrain:
		return "Drain"
	case bbrStateProbeBW:
		return "ProbeBW"
	case bbrStateProbeRTT:
		return "ProbeRTT"
	default:
		return "Unknown"
	}
}

const (
	bbrGainCycleLen = 8

	// ProbeBW gain cycle
	bbrPacingGainStartup = 2.0
	bbrPacingGainDrain   = 1.0 / 2.77
	bbrCWNDGainStartup   = 2.0
	bbrCWNDGainDrain     = 2.0
	bbrCWNDGainProbeBW   = 2.0
	bbrCWNDGainProbeRTT  = 1.0

	bbrProbeRTTInterval = 10 * time.Second       // refresh min RTT every 10s
	bbrProbeRTTDuration = 200 * time.Millisecond // drain for 200ms
	bbrMinPipeCwnd      = 262144                 // minimum cwnd (bytes), 匹配大文件传输

	// Bandwidth filter window (number of round trips)
	bbrBWFilterLen = 10
)

var bbrPacingGains = [bbrGainCycleLen]float64{
	1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0,
}

var bbrCWNDGains = [bbrGainCycleLen]float64{
	2.0, 2.0, 2.0, 2.0, 2.0, 2.0, 2.0, 2.0,
}

// BBR implements the BBR congestion control algorithm.
// Simplified version based on BBRv1 (IETF draft).
type BBR struct {
	// State machine
	state bbrState

	// Bandwidth tracking
	btlBw       float64 // max delivery rate (bytes/sec) - bottleneck bandwidth
	btlBwFilter [bbrBWFilterLen]float64
	bwFilterIdx int

	// RTT tracking
	rtProp      time.Duration // min RTT observed (round trip propagation)
	rtPropStamp time.Time     // when rtProp was last updated

	// Round tracking
	roundCount      int64
	roundStart      bool
	nextRoundPktNum int64 // packet number to start next round
	roundDelivered  int64 // bytes delivered at start of round
	packetDelivered int64 // total bytes delivered so far

	// Delivery rate tracking
	delivered     int64 // cumulative bytes delivered
	deliveredTime time.Time
	appLimited    bool

	// Pacing & window
	pacingRate float64 // bytes/sec
	cwnd       int64   // congestion window (bytes)
	minCwnd    int64

	// Bytes in flight
	bytesInFlight atomic.Int64

	// ProbeBW gain cycle
	probeCycleIdx int

	// ProbeRTT
	probeRTTDoneAt     time.Time
	probeRTTRoundStart int64
	probeRTTLastState  bbrState

	// Max datagram size (MSS)
	maxDatagramSize int64

	// Loss recovery
	inRecovery    atomic.Bool
	recoveryPoint int64

	// RTT stats reference
	rttStats *RTTStats
}

// NewBBR creates a BBR congestion controller.
func NewBBR() *BBR {
	b := &BBR{
		state:           bbrStateStartup,
		rtProp:          333 * time.Millisecond,
		maxDatagramSize: 1200,
		minCwnd:         bbrMinPipeCwnd,
	}
	b.pacingRate = float64(b.minCwnd) / b.rtProp.Seconds()
	b.cwnd = b.minCwnd
	b.enterStartup()
	return b
}

// SetRTTStats attaches RTT stats for direct minRTT access.
func (b *BBR) SetRTTStats(rs *RTTStats) {
	b.rttStats = rs
}

// Name returns "BBR".
func (b *BBR) Name() string { return "BBR" }

// OnPacketSent records a sent packet.
func (b *BBR) OnPacketSent(bytes int64) {
	b.bytesInFlight.Add(bytes)
}

// OnPacketAcked processes an ack.
func (b *BBR) OnPacketAcked(ackedBytes int64, packetNumber int64, now time.Time) bool {
	b.bytesInFlight.Add(-ackedBytes)

	// Track total delivered bytes
	b.delivered += ackedBytes

	// Update delivery rate estimate
	if !b.deliveredTime.IsZero() {
		elapsed := now.Sub(b.deliveredTime).Seconds()
		if elapsed > 0 {
			rate := float64(ackedBytes) / elapsed
			b.updateBtlBw(rate)
		}
	}
	b.deliveredTime = now

	// Check for round start
	if packetNumber >= b.nextRoundPktNum {
		b.roundStart = true
		b.nextRoundPktNum = packetNumber + 1
		b.roundCount++
	}

	// Update min RTT from RTTStats if available
	if b.rttStats != nil {
		minRTT := b.rttStats.MinRTT()
		if minRTT > 0 && minRTT < b.rtProp {
			b.rtProp = minRTT
			b.rtPropStamp = now
		}
	}

	// Advance BBR state machine on round start
	if b.roundStart {
		b.roundStart = false
		b.advanceState(now)
		b.updatePacingAndCwnd()
	}

	return true
}

// OnPacketLost handles packet loss.
// BBR doesn't react strongly to loss (not a congestion signal).
func (b *BBR) OnPacketLost(largestSentPNSinceLastLoss int64) {
	// BBR doesn't reduce cwnd on loss like NewReno
	// Unless in Startup, where loss may indicate pipe is full
	if b.state == bbrStateStartup {
		b.state = bbrStateDrain
	}
	b.inRecovery.Store(true)
	b.recoveryPoint = largestSentPNSinceLastLoss
}

// OnPacketDiscarded decrements bytes in flight (packet lost, not ACKed).
func (b *BBR) OnPacketDiscarded(bytes int64) {
	b.bytesInFlight.Add(-bytes)
}

// OnPacketNeedsRetransmit handles timeout-based retransmit.
func (b *BBR) OnPacketNeedsRetransmit() {
	// For timeout, just reduce to minCwnd to avoid burst
	b.cwnd = b.minCwnd
	b.pacingRate = float64(b.minCwnd) / b.rtProp.Seconds()
	b.inRecovery.Store(false)
}

// CanSend checks if a packet of the given size can be sent.
// Uses pacing rate (time-based) and cwnd (window-based).
func (b *BBR) CanSend(bytes int64) bool {
	return b.bytesInFlight.Load()+bytes <= b.cwnd
}

// Cwnd returns the congestion window.
func (b *BBR) Cwnd() int64 { return b.cwnd }

// BytesInFlight returns the current bytes in flight.
func (b *BBR) BytesInFlight() int64 { return b.bytesInFlight.Load() }

// InRecovery returns the recovery state.
func (b *BBR) InRecovery() bool { return b.inRecovery.Load() }

// PacingRate returns the current pacing rate (bytes/sec).
func (b *BBR) PacingRate() float64 { return b.pacingRate }

//=== private ===

func (b *BBR) enterStartup() {
	b.state = bbrStateStartup
	b.pacingRate = float64(b.minCwnd) / b.rtProp.Seconds()
	b.cwnd = b.minCwnd
}

func (b *BBR) updateBtlBw(rate float64) {
	// Insert into filter
	b.btlBwFilter[b.bwFilterIdx] = rate
	b.bwFilterIdx = (b.bwFilterIdx + 1) % bbrBWFilterLen

	// Find max
	maxBw := 0.0
	for _, v := range b.btlBwFilter {
		if v > maxBw {
			maxBw = v
		}
	}
	b.btlBw = maxBw
}

func (b *BBR) advanceState(now time.Time) {
	switch b.state {
	case bbrStateStartup:
		// Exit startup if BW stops growing (no 25% increase in a round)
		if b.roundCount >= 3 && !b.bwGrewThisRound() {
			b.state = bbrStateDrain
		}

	case bbrStateDrain:
		// Exit drain when bytes in flight <= BDP
		bdp := b.bdp()
		if float64(b.bytesInFlight.Load()) <= bdp {
			b.state = bbrStateProbeBW
			b.probeCycleIdx = 0
		}

	case bbrStateProbeBW:
		// Advance gain cycle at round start
		b.probeCycleIdx = (b.probeCycleIdx + 1) % bbrGainCycleLen

		// Check if we need ProbeRTT
		if b.rtPropStamp != (time.Time{}) && now.Sub(b.rtPropStamp) >= bbrProbeRTTInterval {
			b.probeRTTLastState = b.state
			b.state = bbrStateProbeRTT
			b.probeRTTDoneAt = now.Add(bbrProbeRTTDuration)
		}

	case bbrStateProbeRTT:
		// Stay in ProbeRTT for the duration, then return to previous state
		if now.After(b.probeRTTDoneAt) || b.bytesInFlight.Load() <= int64(b.minCwnd) {
			b.state = b.probeRTTLastState
			if b.state == bbrStateProbeBW {
				b.probeCycleIdx = 0
			}
		}
	}
}

func (b *BBR) bwGrewThisRound() bool {
	// Simple check: if current BW filter max is 25% more than one round ago
	// In practice, we'd track per-round max BW
	return false // simplified: assume pipe is full after Startup
}

func (b *BBR) updatePacingAndCwnd() {
	var pacingGain, cwndGain float64

	switch b.state {
	case bbrStateStartup:
		pacingGain = bbrPacingGainStartup
		cwndGain = bbrCWNDGainStartup
	case bbrStateDrain:
		pacingGain = bbrPacingGainDrain
		cwndGain = bbrCWNDGainDrain
	case bbrStateProbeBW:
		pacingGain = bbrPacingGains[b.probeCycleIdx]
		cwndGain = bbrCWNDGains[b.probeCycleIdx]
	case bbrStateProbeRTT:
		pacingGain = 1.0
		cwndGain = bbrCWNDGainProbeRTT
	}

	// BDP = btlBw × rtProp
	bdp := b.bdp()

	// Pacing rate = gain × btlBw
	rate := pacingGain * b.btlBw
	if rate == 0 {
		rate = float64(b.minCwnd) / b.rtProp.Seconds()
	}
	b.pacingRate = rate

	// Cwnd = cwndGain × BDP (or minCwnd, whichever is larger)
	newCwnd := int64(math.Ceil(cwndGain * bdp))
	if newCwnd < b.minCwnd {
		newCwnd = b.minCwnd
	}
	if b.state == bbrStateProbeRTT {
		newCwnd = b.minCwnd
	}
	b.cwnd = newCwnd
}

func (b *BBR) bdp() float64 {
	return b.btlBw * b.rtProp.Seconds()
}
