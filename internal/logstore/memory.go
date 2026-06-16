package logstore

import "sync"

type Memory struct {
	mu    sync.Mutex
	max   int
	items []Entry
}

func NewMemory(max int) *Memory {
	if max <= 0 {
		max = 1000
	}
	return &Memory{max: max}
}
func (m *Memory) Add(e Entry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items = append(m.items, e)
	if len(m.items) > m.max {
		m.items = m.items[len(m.items)-m.max:]
	}
}
func (m *Memory) Recent() []Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Entry, 0, len(m.items))
	for i := len(m.items) - 1; i >= 0; i-- {
		out = append(out, m.items[i])
	}
	return out
}
