package main

import (
	"hash/fnv"
	"sync"
)

type Counter struct {
	srcIP string
	lastSeen int64

	buckets []bucket
	totalPkts int64
	totalSYN int64
	ports map[uint16]portState
}

type bucket struct {
	ts int64
	pkts int64
	syns int64
}

type portState struct {
	ts int64
	count int64
}

const (
	windowSecs  = 30
	portExpireS = 30
)

func newCounter(ip string) *Counter {
	return &Counter{
		srcIP: ip,
		buckets: make([]bucket, windowSecs),
		ports: make(map[uint16]portState, 16),
	}
}

func (c *Counter) addPacket(nowS int64, dstPort uint16, isSYN bool) {
	c.lastSeen = nowS

	idx := nowS % windowSecs
	if c.buckets[idx].ts != nowS {
		old := c.buckets[idx]
		if old.ts != 0 {
			c.totalPkts -= old.pkts
			c.totalSYN -= old.syns
			if c.totalPkts < 0 {
				c.totalPkts = 0
			}
			if c.totalSYN < 0 {
				c.totalSYN = 0
			}
		}
		c.buckets[idx] = bucket{ts: nowS}
	}
	c.buckets[idx].pkts++
	c.totalPkts++
	if isSYN {
		c.buckets[idx].syns++
		c.totalSYN++
	}

	if dstPort != 0 {
		ps := c.ports[dstPort]
		if ps.ts == 0 {
			ps = portState{ts: nowS, count: 1}
		} else {
			ps.ts = nowS
			ps.count++
		}
		c.ports[dstPort] = ps
	}
}

func (c *Counter) prunePorts(nowS int64) {
	for p, ps := range c.ports {
		if nowS-ps.ts > portExpireS {
			delete(c.ports, p)
		}
	}
}

type Snapshot struct {
	SrcIP string
	WindowS int64
	Total int64
	SYNs int64
	DistinctPorts int
	LastSeen int64
}

func (c *Counter) snapshot(nowS int64) Snapshot {
	idx := nowS % windowSecs
	if c.buckets[idx].ts != nowS && c.buckets[idx].ts != 0 {
		old := c.buckets[idx]
		c.totalPkts -= old.pkts
		c.totalSYN -= old.syns
		if c.totalPkts < 0 {
			c.totalPkts = 0
		}
		if c.totalSYN < 0 {
			c.totalSYN = 0
		}
		c.buckets[idx] = bucket{}
	}
	return Snapshot{
		SrcIP: c.srcIP,
		WindowS: windowSecs,
		Total: c.totalPkts,
		SYNs: c.totalSYN,
		DistinctPorts: len(c.ports),
		LastSeen: c.lastSeen,
	}
}

type CounterStore struct {
	shards []*counterShard
}

type counterShard struct {
	mu sync.Mutex
	m  map[string]*Counter
}

const numShards = 64

func NewCounterStore() *CounterStore {
	cs := &CounterStore{shards: make([]*counterShard, numShards)}
	for i := range cs.shards {
		cs.shards[i] = &counterShard{m: make(map[string]*Counter)}
	}
	return cs
}

func (cs *CounterStore) shardFor(ip string) *counterShard {
	h := fnv.New32a()
	h.Write([]byte(ip))
	return cs.shards[h.Sum32()%numShards]
}

func (cs *CounterStore) Add(srcIP string, dstPort uint16, isSYN bool, nowS int64) {
	s := cs.shardFor(srcIP)
	s.mu.Lock()
	c, ok := s.m[srcIP]
	if !ok {
		c = newCounter(srcIP)
		s.m[srcIP] = c
	}
	c.addPacket(nowS, dstPort, isSYN)
	s.mu.Unlock()
}

func (cs *CounterStore) ForEach(nowS int64, idleEvictS int64, fn func(snap Snapshot)) {
	for _, s := range cs.shards {
		s.mu.Lock()
		snapshots := make([]Snapshot, 0, len(s.m))
		for ip, c := range s.m {
			if nowS-c.lastSeen > idleEvictS {
				delete(s.m, ip)
				continue
		}
			c.prunePorts(nowS)
			snapshots = append(snapshots, c.snapshot(nowS))
		}
		s.mu.Unlock()
		for _, snap := range snapshots {
			fn(snap)
		}
	}
}

func (cs *CounterStore) Count() int {
	n := 0
	for _, s := range cs.shards {
		s.mu.Lock()
		n += len(s.m)
		s.mu.Unlock()
	}
	return n
}
