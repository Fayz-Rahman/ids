package main

import (
	"fmt"
	"math"
)

type Anomaly struct {
	Rule string  `json:"rule"`
	SrcIP string  `json:"src_ip"`
	Severity string  `json:"severity"`
	Score float64  `json:"score"`
	Detail string  `json:"detail"`
}

type RuleConfig struct {
	PortScanPorts int  `yaml:"ports"`
	RateSpikeMultiple float64  `yaml:"multiple"`
	SYNFloodRatio float64  `yaml:"syn_ratio"`
}

type Baseline struct {
	ewma map[string]float64
}

func NewBaseline() *Baseline {
	return &Baseline{ewma: make(map[string]float64)}
}

func (b *Baseline) update(src string, rate float64) float64 {
	const alpha = 0.3
	prev, ok := b.ewma[src]
	if !ok {
		b.ewma[src] = rate
		return rate
	}
	next := alpha*rate + (1-alpha)*prev
	b.ewma[src] = next
	return next
}

func (b *Baseline) get(src string) float64 {
	return b.ewma[src]
}

func EvalRules(cfg RuleConfig, snap Snapshot, baseline *Baseline) []Anomaly {
	var out []Anomaly

	if cfg.PortScanPorts > 0 && snap.DistinctPorts >= cfg.PortScanPorts {
		out = append(out, Anomaly{
			Rule: "port_scan",
			SrcIP: snap.SrcIP,
			Severity: sevLevel(snap.DistinctPorts, cfg.PortScanPorts, cfg.PortScanPorts*3),
			Score: float64(snap.DistinctPorts) / float64(cfg.PortScanPorts),
			Detail: fmt.Sprintf("%d distinct ports in %ds window", snap.DistinctPorts, snap.WindowS),
		})
	}

	rate := float64(snap.Total) / float64(snap.WindowS)
	ewma := baseline.update(snap.SrcIP, rate)
	if cfg.RateSpikeMultiple > 0 && ewma > 1 && rate >= ewma*cfg.RateSpikeMultiple {
		out = append(out, Anomaly{
			Rule: "rate_spike",
			SrcIP: snap.SrcIP,
			Severity: sevLevelFloat(rate, ewma*cfg.RateSpikeMultiple, cfg.RateSpikeMultiple*2),
			Score: rate / ewma,
			Detail: fmt.Sprintf("%.1f pps vs %.1f baseline (%.1fx)", rate, ewma, rate/ewma),
		})
	}

	if cfg.SYNFloodRatio > 0 && snap.Total > 50 && float64(snap.SYNs)/float64(snap.Total) >= cfg.SYNFloodRatio {
		out = append(out, Anomaly{
			Rule: "syn_flood",
			SrcIP: snap.SrcIP,
			Severity: sevLevelFloat(float64(snap.SYNs)/float64(snap.Total), cfg.SYNFloodRatio, math.Min(1.0, cfg.SYNFloodRatio*1.15)),
			Score: float64(snap.SYNs) / float64(snap.Total),
			Detail: fmt.Sprintf("%d SYN of %d total (%.0f%%)", snap.SYNs, snap.Total, 100*float64(snap.SYNs)/float64(snap.Total)),
		})
	}

	return out
}

func sevLevel(val, warn, crit int) string {
	if val >= crit {
		return "crit"
	}
	return "warn"
}
func sevLevelFloat(val, warn, crit float64) string {
	if val >= crit {
		return "crit"
	}
	return "warn"
}
