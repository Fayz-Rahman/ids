package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket/pcap"
	"gopkg.in/yaml.v3"
)

var hostname string

type Config struct {
	Interface string  `yaml:"interface"`
	BPF string  `yaml:"bpf"`
	IntervalMs int  `yaml:"interval_ms"`
	SnapLen int32  `yaml:"snaplen"`
	Rules struct {
		PortScanPorts int  `yaml:"port_scan_ports"`
		RateSpikeMultiple float64  `yaml:"rate_spike_multiple"`
		SYNFloodRatio float64  `yaml:"syn_flood_ratio"`
	} `yaml:"rules"`
	Notify struct {
		Webhook string  `yaml:"webhook"`
		LogFile string  `yaml:"log_file"`
		CooldownS int64  `yaml:"cooldown_s"`
	} `yaml:"notify"`
	EvictIdleS int64  `yaml:"evict_idle_s"`
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{
		IntervalMs: 1000,
		SnapLen: 128,
		EvictIdleS: 120,
	}
	if err := yaml.Unmarshal(b, cfg); err != nil {
		return nil, err
	}
	if cfg.Interface == "" {
		return nil, fmt.Errorf("config: interface is required")
	}
	if cfg.IntervalMs <= 0 {
		cfg.IntervalMs = 1000
	}
	if cfg.SnapLen <= 0 {
		cfg.SnapLen = 128
	}
	if cfg.EvictIdleS <= 0 {
		cfg.EvictIdleS = 120
	}
	return cfg, nil
}

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to config file")
	listFlag := flag.Bool("list", false, "list available capture interfaces and exit")
	flag.Parse()

	if *listFlag {
		listInterfaces()
		return
	}

	hostname, _ = os.Hostname()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	store := NewCounterStore()
	notifier, err := NewNotifier(cfg.Notify.Webhook, cfg.Notify.LogFile, cfg.Notify.CooldownS)
	if err != nil {
		log.Fatalf("notifier: %v", err)
	}
	defer notifier.Close()

	coll, err := NewCollector(cfg.Interface, cfg.BPF, cfg.SnapLen)
	if err != nil {
		log.Fatalf("collector: %v", err)
	}
	coll.Run(store)
	log.Printf("ids: capturing on %s (bpf=%q) eval every %dms",
		cfg.Interface, cfg.BPF, cfg.IntervalMs)

	ruleCfg := RuleConfig{
		PortScanPorts: cfg.Rules.PortScanPorts,
		RateSpikeMultiple: cfg.Rules.RateSpikeMultiple,
		SYNFloodRatio: cfg.Rules.SYNFloodRatio,
	}
	baseline := NewBaseline()

	stop := make(chan struct{})
	go detectorLoop(cfg, ruleCfg, store, baseline, notifier, stop)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("ids: shutting down")
	close(stop)
	coll.Stop()
}

func detectorLoop(
	cfg *Config,
	ruleCfg RuleConfig,
	store *CounterStore,
	baseline *Baseline,
	notifier *Notifier,
	stop chan struct{},
) {
	ticker := time.NewTicker(time.Duration(cfg.IntervalMs) * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			now := time.Now().Unix()
			store.ForEach(now, cfg.EvictIdleS, func(snap Snapshot) {
				anomalies := EvalRules(ruleCfg, snap, baseline)
				for _, a := range anomalies {
					if notifier.Send(a) {
						log.Printf("ALERT rule=%s src=%s sev=%s detail=%s",
							a.Rule, a.SrcIP, a.Severity, a.Detail)
					}
				}
			})
		}
	}
}

func listInterfaces() {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error listing interfaces: %v\n", err)
		os.Exit(1)
	}
	if len(devs) == 0 {
		fmt.Println("no interfaces found")
		return
	}
	fmt.Printf("Found %d interface(s):\n\n", len(devs))
	for _, d := range devs {
		fmt.Printf("  %s\n", d.Name)
		if d.Description != "" {
			fmt.Printf("    description: %s\n", d.Description)
		}
		for _, a := range d.Addresses {
			if a.IP != nil && a.IP.String() != "<nil>" {
				fmt.Printf("    address:      %s\n", a.IP)
			}
		}
		fmt.Println("    flags:        " + devFlags(d))
		fmt.Println()
	}
	fmt.Println("Set `interface:` in config.yaml to the name shown above.")
}

func devFlags(d pcap.Interface) string {
	var parts []string
	f := d.Flags
	if f&0x1 != 0 {
		parts = append(parts, "loopback")
	}
	if f&0x2 != 0 {
		parts = append(parts, "up")
	}
	if f&0x4 != 0 {
		parts = append(parts, "running")
	}
	if f&0x8 != 0 {
		parts = append(parts, "wireless")
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ",")
}
