package server

import "sync"

type broker struct {
	mu          sync.Mutex
	subscribers map[chan string]struct{}
}

func newBroker() *broker {
	return &broker{subscribers: make(map[chan string]struct{})}
}

func (b *broker) subscribe() (<-chan string, func()) {
	channel := make(chan string, 8)
	b.mu.Lock()
	b.subscribers[channel] = struct{}{}
	b.mu.Unlock()
	return channel, func() {
		b.mu.Lock()
		if _, ok := b.subscribers[channel]; ok {
			delete(b.subscribers, channel)
			close(channel)
		}
		b.mu.Unlock()
	}
}

func (b *broker) publish(message string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for channel := range b.subscribers {
		select {
		case channel <- message:
		default:
		}
	}
}
