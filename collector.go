package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Collector struct {
	handle *pcap.Handle
	parser *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType
	loopback layers.Loopback
	eth layers.Ethernet
	ip4 layers.IPv4
	ip6 layers.IPv6
	tcp layers.TCP
	udp layers.UDP
	stopCh chan struct{}
	wg sync.WaitGroup
}

func NewCollector(iface, bpf string, snapLen int32) (*Collector, error) {
	handle, err := pcap.OpenLive(iface, snapLen, false, time.Second)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", iface, err)
	}
	if bpf != "" {
		if err := handle.SetBPFFilter(bpf); err != nil {
			handle.Close()
			return nil, fmt.Errorf("bpf %q: %w", bpf, err)
		}
	}

	c := &Collector{
		handle: handle,
		stopCh: make(chan struct{}),
		decoded: make([]gopacket.LayerType, 0, 4),
	}
	c.parser = gopacket.NewDecodingLayerParser(
		collectorRootLayer(handle.LinkType()), &c.loopback, &c.eth, &c.ip4, &c.ip6, &c.tcp, &c.udp)
	return c, nil
}

func collectorRootLayer(linkType layers.LinkType) gopacket.LayerType {
	switch linkType {
	case layers.LinkTypeNull, layers.LinkTypeLoop:
		return layers.LayerTypeLoopback
	default:
		return layers.LayerTypeEthernet
	}
}

func (c *Collector) Stats() (received, dropped int) {
	s, err := c.handle.Stats()
	if err != nil {
		return 0, 0
	}
	return s.PacketsReceived, s.PacketsDropped
}

func (c *Collector) Run(store *CounterStore) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		for {
			select {
			case <-c.stopCh:
				return
			default:
			}
			data, ci, err := c.handle.ReadPacketData()
			if err != nil {
				if err.Error() == "EOF" {
					return
				}
				continue
			}
			c.processPacket(data, ci.Timestamp, store)
		}
	}()
}

func (c *Collector) processPacket(data []byte, ts time.Time, store *CounterStore) {
	if err := c.parser.DecodeLayers(data, &c.decoded); err != nil {
		return
	}
	var srcIP string
	var dstPort uint16
	var isSYN bool
	var isIPv6 bool

	for _, typ := range c.decoded {
		switch typ {
		case layers.LayerTypeIPv4:
			srcIP = c.ip4.SrcIP.String()
		case layers.LayerTypeIPv6:
			srcIP = c.ip6.SrcIP.String()
			isIPv6 = true
		case layers.LayerTypeTCP:
			dstPort = uint16(c.tcp.DstPort)
			isSYN = c.tcp.SYN && !c.tcp.ACK
		case layers.LayerTypeUDP:
			dstPort = uint16(c.udp.DstPort)
		}
	}
	if srcIP == "" || (dstPort == 0 && !isSYN) {
		_ = isIPv6
		return
	}
	store.Add(srcIP, dstPort, isSYN, ts.Unix())
}

func (c *Collector) Stop() {
	close(c.stopCh)
	c.handle.Close()
	c.wg.Wait()
}
