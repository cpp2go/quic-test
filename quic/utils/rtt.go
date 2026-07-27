// Package utils provides RTT estimation and congestion control for QUIC.
package utils

import (
	"math"
	"time"
)

// RTTStats stores round-trip time statistics.
type RTTStats struct {
	minRTT      time.Duration
	smoothedRTT time.Duration
	rttvar      time.Duration
	maxAckDelay time.Duration

	// Initial RTT
	initialRTT time.Duration

	// Latest RTT measurement
	latestRTT time.Duration
}

// NewRTTStats creates a new RTT stats tracker.
func NewRTTStats() *RTTStats {
	return &RTTStats{
		initialRTT:  333 * time.Millisecond, // default initial RTT
		rttvar:      166 * time.Millisecond, // default initial RTTVAR
		maxAckDelay: 25 * time.Millisecond,
	}
}

// UpdateRTT updates the RTT estimation with a new measurement.
// sendTime: when the packet was sent
// ackDelay: the delay field from the ACK frame (peer's acknowledgment delay)
// now: current time
func (r *RTTStats) UpdateRTT(sendTime time.Time, ackDelay time.Duration, now time.Time) {
	if sendTime.IsZero() {
		return
	}

	// Calculate the RTT sample
	minRTT := now.Sub(sendTime)
	if minRTT <= 0 {
		minRTT = time.Microsecond
	}

	// Subtract ack delay, but don't go below minRTT
	var ackDelayTime time.Duration
	if ackDelay < r.maxAckDelay {
		ackDelayTime = ackDelay
	} else {
		ackDelayTime = r.maxAckDelay
	}
	adjustedRTT := minRTT - ackDelayTime
	if adjustedRTT <= 0 {
		adjustedRTT = minRTT
	}

	r.latestRTT = adjustedRTT

	// Update minRTT
	if r.minRTT == 0 || adjustedRTT < r.minRTT {
		r.minRTT = adjustedRTT
	}

	// Update smoothed RTT and RTTVAR (RFC 6298)
	if r.smoothedRTT == 0 || r.smoothedRTT == r.initialRTT {
		r.smoothedRTT = adjustedRTT
		r.rttvar = adjustedRTT / 2
	} else {
		rttvarDiff := r.smoothedRTT - adjustedRTT
		if rttvarDiff < 0 {
			rttvarDiff = -rttvarDiff
		}
		r.rttvar = (3*r.rttvar + rttvarDiff) / 4
		r.smoothedRTT = (7*r.smoothedRTT + adjustedRTT) / 8
	}
}

// SmoothedRTT returns the smoothed RTT.
func (r *RTTStats) SmoothedRTT() time.Duration {
	return r.smoothedRTT
}

// RTTVar returns the RTT variation.
func (r *RTTStats) RTTVar() time.Duration {
	return r.rttvar
}

// MinRTT returns the minimum observed RTT.
func (r *RTTStats) MinRTT() time.Duration {
	return r.minRTT
}

// LatestRTT returns the latest RTT measurement.
func (r *RTTStats) LatestRTT() time.Duration {
	return r.latestRTT
}

// PTO returns the Probe Timeout duration (RFC 9002).
// PTO = smoothedRTT + 4 * rttvar
func (r *RTTStats) PTO() time.Duration {
	pto := r.smoothedRTT + 4*r.rttvar
	if pto < 200*time.Millisecond {
		pto = 200 * time.Millisecond
	}
	return pto
}

// LossDelay returns the time after which a packet should be considered lost.
// Based on the RFC 9002 loss detection threshold (9/8 * max(SRTT, latestRTT) + 4 * rttvar).
func (r *RTTStats) LossDelay() time.Duration {
	maxRTT := r.smoothedRTT
	if r.latestRTT > maxRTT {
		maxRTT = r.latestRTT
	}
	threshold := time.Duration(math.Ceil(float64(maxRTT)*9.0/8.0)) + 4*r.rttvar
	if threshold < 2*r.smoothedRTT && r.smoothedRTT > 0 {
		return 2 * r.smoothedRTT
	}
	return threshold
}
