//go:build loadfleet

package main

import (
	"math"
	"sync/atomic"
	"time"
)

// hist is a lock-free log-scale latency histogram: bucket i holds latencies up
// to bucketLo*factor^i. Resolution is factor-1 (5%), finer than the run-to-run
// noise of any load test, and millions of samples fit in a few KB.
type hist struct {
	counts [nBuckets]atomic.Uint64
	sumNs  atomic.Uint64
	maxNs  atomic.Uint64
}

const (
	nBuckets = 400
	bucketLo = 10_000 // 10us, in ns
	factor   = 1.05
)

var logFactor = math.Log(factor)

func (h *hist) add(d time.Duration) {
	ns := uint64(max(d, 0))
	i := 0
	if ns > bucketLo {
		i = min(int(math.Ceil(math.Log(float64(ns)/bucketLo)/logFactor)), nBuckets-1)
	}
	h.counts[i].Add(1)
	h.sumNs.Add(ns)
	for {
		m := h.maxNs.Load()
		if ns <= m || h.maxNs.CompareAndSwap(m, ns) {
			return
		}
	}
}

func (h *hist) count() uint64 {
	var n uint64
	for i := range h.counts {
		n += h.counts[i].Load()
	}
	return n
}

// quantile returns the upper bound of the bucket holding the q-th sample.
func (h *hist) quantile(q float64) time.Duration {
	n := h.count()
	if n == 0 {
		return 0
	}
	want := uint64(math.Ceil(q * float64(n)))
	var cum uint64
	for i := range h.counts {
		if cum += h.counts[i].Load(); cum >= want {
			return time.Duration(float64(bucketLo) * math.Pow(factor, float64(i)))
		}
	}
	return time.Duration(h.maxNs.Load())
}

func (h *hist) mean() time.Duration {
	if n := h.count(); n > 0 {
		return time.Duration(h.sumNs.Load() / n)
	}
	return 0
}
